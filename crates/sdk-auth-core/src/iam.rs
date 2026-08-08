//! IAM control-plane orchestration and credential-bound authorization.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sdk_auth_authorization::{
    ApiKey, AuthorizationGrant, CredentialKind, MAX_SCOPES_PER_API_KEY, PermissionDefinition,
    PermissionKey, PrincipalId, Role, RoleKey, ServiceAccount, is_allowed, normalize_permissions,
};
use sdk_auth_crypto::{ParsedApiKey, TokenDigest, TokenGenerator, generate_api_key, parse_api_key};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::{
    ApiKeyId, AuthEvent, AuthEventKind, OpaqueToken, PermissionId, RealmId, RoleId, SecretString,
    ServiceAccountId, UserId,
};

use crate::{AuthService, Clock, MfaManagementProof, service::event};

const OWNER_ROLE: &str = "realm_owner";
const PERMISSION_CATALOG_MANAGE: &str = "iam.permissions:manage";
const ROLE_MANAGE: &str = "iam.roles:manage";
const ASSIGNMENT_MANAGE: &str = "iam.assignments:manage";
const SERVICE_ACCOUNT_MANAGE: &str = "iam.service_accounts:manage";
const API_KEY_MANAGE: &str = "iam.api_keys:manage";
const API_KEY_SELF: &str = "iam.api_keys:self";
const AUDIT_READ: &str = "iam.audit:read";

/// Security-sensitive authorization configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationConfig {
    /// Default lifetime for a newly issued API key.
    pub api_key_ttl: Duration,
    /// Maximum accepted API-key lifetime.
    pub max_api_key_ttl: Duration,
    /// Maximum overlap accepted during rotation.
    pub max_rotation_grace: Duration,
}

impl Default for AuthorizationConfig {
    fn default() -> Self {
        Self {
            api_key_ttl: Duration::days(90),
            max_api_key_ttl: Duration::days(365),
            max_rotation_grace: Duration::hours(24),
        }
    }
}

impl AuthorizationConfig {
    /// Rejects unsafe or nonsensical lifetime configuration.
    pub fn validate(self) -> Result<(), AuthError> {
        if self.api_key_ttl <= Duration::zero()
            || self.max_api_key_ttl < self.api_key_ttl
            || self.max_api_key_ttl > Duration::days(365)
            || self.max_rotation_grace < Duration::zero()
            || self.max_rotation_grace > Duration::hours(24)
        {
            return Err(AuthError::new(
                ErrorCode::Misconfigured,
                "authorization configuration is outside supported bounds",
                false,
            ));
        }
        Ok(())
    }
}

/// Fresh human proof required for every IAM control-plane mutation.
#[derive(Debug)]
pub struct IamAdminProof {
    realm_id: RealmId,
    access_token: SecretString,
    proof: MfaManagementProof,
}

impl IamAdminProof {
    /// Creates a step-up proof from a user access token, password and MFA proof.
    #[must_use]
    pub fn new(realm_id: RealmId, access_token: SecretString, proof: MfaManagementProof) -> Self {
        Self {
            realm_id,
            access_token,
            proof,
        }
    }

    /// Realm being administered.
    #[must_use]
    pub const fn realm_id(&self) -> RealmId {
        self.realm_id
    }
}

/// API-key record passed to trusted persistence adapters.
#[derive(Debug, Clone)]
pub struct StoredApiKey {
    /// Public metadata.
    pub key: ApiKey,
    /// Digest of the complete bearer credential.
    pub digest: TokenDigest,
}

/// Authenticated API-key state returned by storage.
#[derive(Debug, Clone)]
pub struct ApiKeyAuthentication {
    /// Active key metadata.
    pub key: ApiKey,
    /// Active role permissions for the owning principal.
    pub permissions: Vec<PermissionKey>,
}

/// One-time API-key issuance response.
#[derive(Debug)]
pub struct ApiKeyGrant {
    /// Persisted public metadata.
    pub key: ApiKey,
    /// Bearer credential returned exactly once.
    pub credential: OpaqueToken,
}

/// Credential supplied to an authorization decision.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthorizationCredential {
    /// Opaque user-session access token.
    UserAccessToken(SecretString),
    /// Restricted API key.
    ApiKey(SecretString),
}

/// Request that always couples authentication to one permission decision.
#[derive(Debug)]
pub struct AuthorizeRequest {
    realm_id: RealmId,
    credential: AuthorizationCredential,
    permission: PermissionKey,
}

impl AuthorizeRequest {
    /// Creates a credential-bound authorization request.
    #[must_use]
    pub fn new(
        realm_id: RealmId,
        credential: AuthorizationCredential,
        permission: PermissionKey,
    ) -> Self {
        Self {
            realm_id,
            credential,
            permission,
        }
    }
}

/// Atomic one-time realm bootstrap command.
#[derive(Debug)]
pub struct BootstrapIam {
    /// Realm initialized by this command.
    pub realm_id: RealmId,
    /// Verified human that becomes the first owner.
    pub owner_user_id: UserId,
    /// Built-in immutable IAM permission definitions.
    pub permissions: Vec<PermissionDefinition>,
    /// Reserved owner role.
    pub owner_role: Role,
    /// Secret-free outbox event.
    pub event: AuthEvent,
}

/// Atomic role creation command.
#[derive(Debug)]
pub struct CreateRole {
    /// Verified human actor.
    pub actor_user_id: UserId,
    /// Required administrative permission.
    pub required_permission: PermissionKey,
    /// New role.
    pub role: Role,
    /// Secret-free outbox event.
    pub event: AuthEvent,
}

/// Atomic permission registration command.
#[derive(Debug)]
pub struct CreatePermission {
    /// Verified human actor.
    pub actor_user_id: UserId,
    /// Required administrative permission.
    pub required_permission: PermissionKey,
    /// New catalog entry.
    pub permission: PermissionDefinition,
    /// Secret-free outbox event.
    pub event: AuthEvent,
}

/// Atomic service-account creation command.
#[derive(Debug)]
pub struct CreateServiceAccount {
    /// Verified human actor.
    pub actor_user_id: UserId,
    /// Required administrative permission.
    pub required_permission: PermissionKey,
    /// New non-human principal.
    pub service_account: ServiceAccount,
    /// Secret-free outbox event.
    pub event: AuthEvent,
}

/// Atomic API-key creation command.
#[derive(Debug)]
pub struct CreateApiKey {
    /// Verified human actor.
    pub actor_user_id: UserId,
    /// Permission required of the actor.
    pub required_permission: PermissionKey,
    /// Persisted key state.
    pub stored: StoredApiKey,
    /// Secret-free outbox event.
    pub event: AuthEvent,
}

/// Atomic API-key rotation command.
#[derive(Debug)]
pub struct RotateApiKey {
    /// Verified human actor.
    pub actor_user_id: UserId,
    /// Permission required of the actor.
    pub required_permission: PermissionKey,
    /// Key being replaced.
    pub previous_id: ApiKeyId,
    /// End of the optional predecessor overlap.
    pub previous_grace_expires_at: DateTime<Utc>,
    /// Replacement key state.
    pub replacement: StoredApiKey,
    /// Secret-free outbox event.
    pub event: AuthEvent,
}

/// Persistence contract for IAM and authorization.
///
/// Mutation methods must recheck `required_permission` for `actor_user_id`
/// inside the same critical section or database transaction as the mutation.
#[async_trait]
pub trait IamStore: Send + Sync {
    /// Returns whether the realm has completed bootstrap.
    async fn iam_initialized(&self, realm_id: RealmId) -> Result<bool, AuthError>;
    /// Initializes a realm exactly once.
    async fn bootstrap_iam(&self, command: BootstrapIam) -> Result<(), AuthError>;
    /// Returns current active permissions for one principal.
    async fn principal_permissions(
        &self,
        realm_id: RealmId,
        principal: PrincipalId,
    ) -> Result<Vec<PermissionKey>, AuthError>;
    /// Registers a catalog permission.
    async fn create_permission(&self, command: CreatePermission) -> Result<(), AuthError>;
    /// Enables or disables a catalog permission.
    #[allow(clippy::too_many_arguments)]
    async fn set_permission_enabled(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        permission_id: PermissionId,
        enabled: bool,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError>;
    /// Lists permission definitions in deterministic order.
    async fn list_permissions(
        &self,
        realm_id: RealmId,
    ) -> Result<Vec<PermissionDefinition>, AuthError>;
    /// Creates a role.
    async fn create_role(&self, command: CreateRole) -> Result<(), AuthError>;
    /// Enables or disables a non-reserved role.
    #[allow(clippy::too_many_arguments)]
    async fn set_role_enabled(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        role_id: RoleId,
        enabled: bool,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError>;
    /// Lists roles in deterministic order.
    async fn list_roles(&self, realm_id: RealmId) -> Result<Vec<Role>, AuthError>;
    /// Grants or revokes a catalog permission on a role.
    #[allow(clippy::too_many_arguments)]
    async fn set_role_permission(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        role_id: RoleId,
        permission_id: PermissionId,
        granted: bool,
        event: AuthEvent,
    ) -> Result<bool, AuthError>;
    /// Grants or revokes a role on a principal while preserving the last owner.
    #[allow(clippy::too_many_arguments)]
    async fn set_principal_role(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        principal: PrincipalId,
        role_id: RoleId,
        granted: bool,
        event: AuthEvent,
    ) -> Result<bool, AuthError>;
    /// Creates a non-human principal.
    async fn create_service_account(&self, command: CreateServiceAccount) -> Result<(), AuthError>;
    /// Enables or disables a service account.
    #[allow(clippy::too_many_arguments)]
    async fn set_service_account_enabled(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        service_account_id: ServiceAccountId,
        enabled: bool,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError>;
    /// Lists service accounts in deterministic order.
    async fn list_service_accounts(
        &self,
        realm_id: RealmId,
    ) -> Result<Vec<ServiceAccount>, AuthError>;
    /// Creates an API key after atomically checking actor authority and scope subset.
    async fn create_api_key(&self, command: CreateApiKey) -> Result<(), AuthError>;
    /// Returns API-key metadata by public ID.
    async fn find_api_key(
        &self,
        realm_id: RealmId,
        id: ApiKeyId,
    ) -> Result<Option<ApiKey>, AuthError>;
    /// Lists API keys for one principal without credential material.
    async fn list_api_keys(
        &self,
        realm_id: RealmId,
        principal: PrincipalId,
    ) -> Result<Vec<ApiKey>, AuthError>;
    /// Rotates a key atomically and caps predecessor validity at the grace time.
    async fn rotate_api_key(&self, command: RotateApiKey) -> Result<(), AuthError>;
    /// Revokes an API key idempotently.
    #[allow(clippy::too_many_arguments)]
    async fn revoke_api_key(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        api_key_id: ApiKeyId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError>;
    /// Authenticates an active key and returns its current role permissions.
    async fn authenticate_api_key(
        &self,
        realm_id: RealmId,
        parsed: ParsedApiKey,
        now: DateTime<Utc>,
    ) -> Result<Option<ApiKeyAuthentication>, AuthError>;
}

/// IAM control-plane service. All mutations require fresh human step-up proof.
#[derive(Clone)]
pub struct IamService {
    store: Arc<dyn IamStore>,
    authentication: Arc<AuthService>,
    token_generator: Arc<dyn TokenGenerator>,
    clock: Arc<dyn Clock>,
    config: AuthorizationConfig,
}

impl IamService {
    pub(crate) fn new(
        store: Arc<dyn IamStore>,
        authentication: Arc<AuthService>,
        token_generator: Arc<dyn TokenGenerator>,
        clock: Arc<dyn Clock>,
        config: AuthorizationConfig,
    ) -> Result<Self, AuthError> {
        config.validate()?;
        Ok(Self {
            store,
            authentication,
            token_generator,
            clock,
            config,
        })
    }

    /// Performs one-time realm initialization and creates the first human owner.
    #[tracing::instrument(name = "sdk_auth.iam.bootstrap", skip_all)]
    pub async fn bootstrap_realm(&self, admin: IamAdminProof) -> Result<(), AuthError> {
        let actor = self.step_up(&admin).await?;
        let now = self.clock.now();
        let permissions = built_in_permissions(admin.realm_id, now)?;
        let owner_role = Role::from_parts(
            admin.realm_id,
            RoleId::new(),
            RoleKey::parse(OWNER_ROLE)?,
            "Realm owner",
            "Reserved IAM control-plane owner",
            true,
            true,
            now,
            now,
        )?;
        let mut audit_event = event(
            admin.realm_id,
            actor,
            AuthEventKind::IamRealmBootstrapped,
            now,
        );
        audit_event.payload = format!("{{\"owner_user_id\":\"{actor}\"}}");
        self.store
            .bootstrap_iam(BootstrapIam {
                realm_id: admin.realm_id,
                owner_user_id: actor,
                permissions,
                owner_role,
                event: audit_event,
            })
            .await
    }

    /// Registers one immutable catalog key.
    pub async fn register_permission(
        &self,
        admin: IamAdminProof,
        key: PermissionKey,
        description: impl Into<String>,
    ) -> Result<PermissionDefinition, AuthError> {
        let actor = self
            .authorized_actor(&admin, PERMISSION_CATALOG_MANAGE)
            .await?;
        let now = self.clock.now();
        let permission = PermissionDefinition::from_parts(
            admin.realm_id,
            PermissionId::new(),
            key,
            description,
            true,
            now,
            now,
        )?;
        let event = iam_event(
            admin.realm_id,
            actor,
            AuthEventKind::IamPermissionChanged,
            "created",
            permission.id(),
            now,
        );
        self.store
            .create_permission(CreatePermission {
                actor_user_id: actor,
                required_permission: permission_key(PERMISSION_CATALOG_MANAGE)?,
                permission: permission.clone(),
                event,
            })
            .await?;
        Ok(permission)
    }

    /// Enables or disables a permission. Disabled permissions deny immediately.
    pub async fn set_permission_enabled(
        &self,
        admin: IamAdminProof,
        permission_id: PermissionId,
        enabled: bool,
    ) -> Result<bool, AuthError> {
        let actor = self
            .authorized_actor(&admin, PERMISSION_CATALOG_MANAGE)
            .await?;
        let now = self.clock.now();
        self.store
            .set_permission_enabled(
                admin.realm_id,
                actor,
                permission_key(PERMISSION_CATALOG_MANAGE)?,
                permission_id,
                enabled,
                now,
                iam_event(
                    admin.realm_id,
                    actor,
                    AuthEventKind::IamPermissionChanged,
                    if enabled { "enabled" } else { "disabled" },
                    permission_id,
                    now,
                ),
            )
            .await
    }

    /// Lists the realm permission catalog after fresh administrative step-up.
    pub async fn list_permissions(
        &self,
        admin: IamAdminProof,
    ) -> Result<Vec<PermissionDefinition>, AuthError> {
        self.authorized_actor(&admin, AUDIT_READ).await?;
        self.store.list_permissions(admin.realm_id).await
    }

    /// Creates a non-hierarchical role.
    pub async fn create_role(
        &self,
        admin: IamAdminProof,
        key: RoleKey,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<Role, AuthError> {
        let actor = self.authorized_actor(&admin, ROLE_MANAGE).await?;
        let now = self.clock.now();
        let role = Role::from_parts(
            admin.realm_id,
            RoleId::new(),
            key,
            name,
            description,
            false,
            true,
            now,
            now,
        )?;
        let event = iam_event(
            admin.realm_id,
            actor,
            AuthEventKind::IamRoleChanged,
            "created",
            role.id(),
            now,
        );
        self.store
            .create_role(CreateRole {
                actor_user_id: actor,
                required_permission: permission_key(ROLE_MANAGE)?,
                role: role.clone(),
                event,
            })
            .await?;
        Ok(role)
    }

    /// Enables or disables a non-reserved role.
    pub async fn set_role_enabled(
        &self,
        admin: IamAdminProof,
        role_id: RoleId,
        enabled: bool,
    ) -> Result<bool, AuthError> {
        let actor = self.authorized_actor(&admin, ROLE_MANAGE).await?;
        let now = self.clock.now();
        self.store
            .set_role_enabled(
                admin.realm_id,
                actor,
                permission_key(ROLE_MANAGE)?,
                role_id,
                enabled,
                now,
                iam_event(
                    admin.realm_id,
                    actor,
                    AuthEventKind::IamRoleChanged,
                    if enabled { "enabled" } else { "disabled" },
                    role_id,
                    now,
                ),
            )
            .await
    }

    /// Lists roles in the realm after fresh administrative step-up.
    pub async fn list_roles(&self, admin: IamAdminProof) -> Result<Vec<Role>, AuthError> {
        self.authorized_actor(&admin, AUDIT_READ).await?;
        self.store.list_roles(admin.realm_id).await
    }

    /// Grants or revokes one catalog permission on a role.
    pub async fn set_role_permission(
        &self,
        admin: IamAdminProof,
        role_id: RoleId,
        permission_id: PermissionId,
        granted: bool,
    ) -> Result<bool, AuthError> {
        let actor = self.authorized_actor(&admin, ROLE_MANAGE).await?;
        let now = self.clock.now();
        self.store
            .set_role_permission(
                admin.realm_id,
                actor,
                permission_key(ROLE_MANAGE)?,
                role_id,
                permission_id,
                granted,
                iam_event(
                    admin.realm_id,
                    actor,
                    AuthEventKind::IamRoleChanged,
                    if granted {
                        "permission_granted"
                    } else {
                        "permission_revoked"
                    },
                    role_id,
                    now,
                ),
            )
            .await
    }

    /// Grants or revokes one role on a human or service principal.
    pub async fn set_principal_role(
        &self,
        admin: IamAdminProof,
        principal: PrincipalId,
        role_id: RoleId,
        granted: bool,
    ) -> Result<bool, AuthError> {
        let actor = self.authorized_actor(&admin, ASSIGNMENT_MANAGE).await?;
        let now = self.clock.now();
        self.store
            .set_principal_role(
                admin.realm_id,
                actor,
                permission_key(ASSIGNMENT_MANAGE)?,
                principal,
                role_id,
                granted,
                iam_event(
                    admin.realm_id,
                    actor,
                    AuthEventKind::IamAssignmentChanged,
                    if granted { "granted" } else { "revoked" },
                    role_id,
                    now,
                ),
            )
            .await
    }

    /// Creates a non-human principal.
    pub async fn create_service_account(
        &self,
        admin: IamAdminProof,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<ServiceAccount, AuthError> {
        let actor = self
            .authorized_actor(&admin, SERVICE_ACCOUNT_MANAGE)
            .await?;
        let now = self.clock.now();
        let account = ServiceAccount::from_parts(
            admin.realm_id,
            ServiceAccountId::new(),
            name,
            description,
            true,
            now,
            now,
        )?;
        self.store
            .create_service_account(CreateServiceAccount {
                actor_user_id: actor,
                required_permission: permission_key(SERVICE_ACCOUNT_MANAGE)?,
                service_account: account.clone(),
                event: iam_event(
                    admin.realm_id,
                    actor,
                    AuthEventKind::IamServiceAccountChanged,
                    "created",
                    account.id(),
                    now,
                ),
            })
            .await?;
        Ok(account)
    }

    /// Enables or disables a service account and its keys.
    pub async fn set_service_account_enabled(
        &self,
        admin: IamAdminProof,
        service_account_id: ServiceAccountId,
        enabled: bool,
    ) -> Result<bool, AuthError> {
        let actor = self
            .authorized_actor(&admin, SERVICE_ACCOUNT_MANAGE)
            .await?;
        let now = self.clock.now();
        self.store
            .set_service_account_enabled(
                admin.realm_id,
                actor,
                permission_key(SERVICE_ACCOUNT_MANAGE)?,
                service_account_id,
                enabled,
                now,
                iam_event(
                    admin.realm_id,
                    actor,
                    AuthEventKind::IamServiceAccountChanged,
                    if enabled { "enabled" } else { "disabled" },
                    service_account_id,
                    now,
                ),
            )
            .await
    }

    /// Lists service accounts after fresh administrative step-up.
    pub async fn list_service_accounts(
        &self,
        admin: IamAdminProof,
    ) -> Result<Vec<ServiceAccount>, AuthError> {
        self.authorized_actor(&admin, AUDIT_READ).await?;
        self.store.list_service_accounts(admin.realm_id).await
    }

    /// Creates a restricted API key after enforcing current-role scope subset.
    pub async fn create_api_key(
        &self,
        admin: IamAdminProof,
        principal: PrincipalId,
        name: impl Into<String>,
        scopes: Vec<PermissionKey>,
        ttl: Option<Duration>,
    ) -> Result<ApiKeyGrant, AuthError> {
        let actor = self.step_up(&admin).await?;
        let required = required_key_permission(actor, principal)?;
        self.require_actor_permission(admin.realm_id, actor, required)
            .await?;
        let scopes = normalize_permissions(scopes, MAX_SCOPES_PER_API_KEY)?;
        if scopes.is_empty() {
            return Err(AuthError::invalid_input());
        }
        let active = self
            .store
            .principal_permissions(admin.realm_id, principal)
            .await?;
        if !scopes
            .iter()
            .all(|scope| active.iter().any(|permission| permission == scope))
        {
            return Err(permission_denied());
        }
        let now = self.clock.now();
        let ttl = self.valid_ttl(ttl)?;
        let generated = generate_api_key(self.token_generator.as_ref())?;
        let key = ApiKey::from_parts(
            admin.realm_id,
            generated.id,
            principal,
            name,
            scopes,
            now,
            now + ttl,
            None,
            None,
        )?;
        self.store
            .create_api_key(CreateApiKey {
                actor_user_id: actor,
                required_permission: permission_key(required)?,
                stored: StoredApiKey {
                    key: key.clone(),
                    digest: generated.digest,
                },
                event: iam_event(
                    admin.realm_id,
                    actor,
                    AuthEventKind::IamApiKeyChanged,
                    "created",
                    key.id(),
                    now,
                ),
            })
            .await?;
        Ok(ApiKeyGrant {
            key,
            credential: generated.credential,
        })
    }

    /// Rotates a key and optionally overlaps its predecessor for at most 24 hours.
    pub async fn rotate_api_key(
        &self,
        admin: IamAdminProof,
        api_key_id: ApiKeyId,
        grace: Duration,
        ttl: Option<Duration>,
    ) -> Result<ApiKeyGrant, AuthError> {
        if grace < Duration::zero() || grace > self.config.max_rotation_grace {
            return Err(AuthError::invalid_input());
        }
        let actor = self.step_up(&admin).await?;
        let previous = self
            .store
            .find_api_key(admin.realm_id, api_key_id)
            .await?
            .ok_or_else(AuthError::invalid_credentials)?;
        let required = required_key_permission(actor, previous.principal())?;
        self.require_actor_permission(admin.realm_id, actor, required)
            .await?;
        let now = self.clock.now();
        if previous.revoked_at().is_some() || previous.expires_at() <= now {
            return Err(AuthError::invalid_credentials());
        }
        let generated = generate_api_key(self.token_generator.as_ref())?;
        let replacement = ApiKey::from_parts(
            admin.realm_id,
            generated.id,
            previous.principal(),
            previous.name(),
            previous.scopes().to_vec(),
            now,
            now + self.valid_ttl(ttl)?,
            None,
            None,
        )?;
        self.store
            .rotate_api_key(RotateApiKey {
                actor_user_id: actor,
                required_permission: permission_key(required)?,
                previous_id: api_key_id,
                previous_grace_expires_at: now + grace,
                replacement: StoredApiKey {
                    key: replacement.clone(),
                    digest: generated.digest,
                },
                event: iam_event(
                    admin.realm_id,
                    actor,
                    AuthEventKind::IamApiKeyChanged,
                    "rotated",
                    api_key_id,
                    now,
                ),
            })
            .await?;
        Ok(ApiKeyGrant {
            key: replacement,
            credential: generated.credential,
        })
    }

    /// Revokes a key idempotently.
    pub async fn revoke_api_key(
        &self,
        admin: IamAdminProof,
        api_key_id: ApiKeyId,
    ) -> Result<bool, AuthError> {
        let actor = self.step_up(&admin).await?;
        let key = self
            .store
            .find_api_key(admin.realm_id, api_key_id)
            .await?
            .ok_or_else(AuthError::invalid_credentials)?;
        let required = required_key_permission(actor, key.principal())?;
        self.require_actor_permission(admin.realm_id, actor, required)
            .await?;
        let now = self.clock.now();
        self.store
            .revoke_api_key(
                admin.realm_id,
                actor,
                permission_key(required)?,
                api_key_id,
                now,
                iam_event(
                    admin.realm_id,
                    actor,
                    AuthEventKind::IamApiKeyChanged,
                    "revoked",
                    api_key_id,
                    now,
                ),
            )
            .await
    }

    /// Lists non-secret key metadata after fresh administrative step-up.
    pub async fn list_api_keys(
        &self,
        admin: IamAdminProof,
        principal: PrincipalId,
    ) -> Result<Vec<ApiKey>, AuthError> {
        self.authorized_actor(&admin, AUDIT_READ).await?;
        self.store.list_api_keys(admin.realm_id, principal).await
    }

    async fn step_up(&self, admin: &IamAdminProof) -> Result<UserId, AuthError> {
        self.authentication
            .verify_iam_step_up(admin.realm_id, &admin.access_token, &admin.proof)
            .await
    }

    async fn authorized_actor(
        &self,
        admin: &IamAdminProof,
        required: &str,
    ) -> Result<UserId, AuthError> {
        let actor = self.step_up(admin).await?;
        self.require_actor_permission(admin.realm_id, actor, required)
            .await?;
        Ok(actor)
    }

    pub(crate) async fn authorize_audit_reader(
        &self,
        admin: &IamAdminProof,
    ) -> Result<UserId, AuthError> {
        self.authorized_actor(admin, AUDIT_READ).await
    }

    async fn require_actor_permission(
        &self,
        realm_id: RealmId,
        actor: UserId,
        required: &str,
    ) -> Result<(), AuthError> {
        self.require_initialized(realm_id).await?;
        let requested = permission_key(required)?;
        let granted = self
            .store
            .principal_permissions(realm_id, PrincipalId::User(actor))
            .await?;
        if is_allowed(&granted, None, &requested) {
            Ok(())
        } else {
            Err(permission_denied())
        }
    }

    async fn require_initialized(&self, realm_id: RealmId) -> Result<(), AuthError> {
        if self.store.iam_initialized(realm_id).await? {
            Ok(())
        } else {
            Err(realm_not_initialized())
        }
    }

    fn valid_ttl(&self, requested: Option<Duration>) -> Result<Duration, AuthError> {
        let value = requested.unwrap_or(self.config.api_key_ttl);
        if value <= Duration::zero() || value > self.config.max_api_key_ttl {
            return Err(AuthError::invalid_input());
        }
        Ok(value)
    }
}

/// Data-plane authorization service. It never accepts a forgeable principal ID.
pub struct AuthorizationService {
    store: Arc<dyn IamStore>,
    authentication: Arc<AuthService>,
    clock: Arc<dyn Clock>,
}

impl AuthorizationService {
    pub(crate) fn new(
        store: Arc<dyn IamStore>,
        authentication: Arc<AuthService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            authentication,
            clock,
        }
    }

    /// Authenticates a credential and checks one exact permission.
    #[tracing::instrument(name = "sdk_auth.authorize", skip_all, fields(realm_id = %request.realm_id, permission = %request.permission))]
    pub async fn authorize(
        &self,
        request: AuthorizeRequest,
    ) -> Result<AuthorizationGrant, AuthError> {
        if !self.store.iam_initialized(request.realm_id).await? {
            return Err(realm_not_initialized());
        }
        let result = match request.credential {
            AuthorizationCredential::UserAccessToken(token) => {
                let validated = self
                    .authentication
                    .validate_access(request.realm_id, &token)
                    .await?;
                let principal = PrincipalId::User(validated.user.id);
                let permissions = self
                    .store
                    .principal_permissions(request.realm_id, principal)
                    .await?;
                is_allowed(&permissions, None, &request.permission).then(|| {
                    AuthorizationGrant::new(
                        request.realm_id,
                        principal,
                        request.permission.clone(),
                        CredentialKind::UserAccessToken,
                        None,
                    )
                })
            }
            AuthorizationCredential::ApiKey(credential) => {
                let parsed = parse_api_key(&credential).map_err(|_| invalid_api_key())?;
                let authenticated = self
                    .store
                    .authenticate_api_key(request.realm_id, parsed, self.clock.now())
                    .await?;
                authenticated.and_then(|value| {
                    is_allowed(
                        &value.permissions,
                        Some(value.key.scopes()),
                        &request.permission,
                    )
                    .then(|| {
                        AuthorizationGrant::new(
                            request.realm_id,
                            value.key.principal(),
                            request.permission.clone(),
                            CredentialKind::ApiKey,
                            Some(value.key.id()),
                        )
                    })
                })
            }
        };
        match result {
            Some(grant) => {
                tracing::trace!(principal = ?grant.principal(), "authorization allowed");
                Ok(grant)
            }
            None => {
                tracing::warn!(reason = "insufficient_permission", "authorization denied");
                Err(permission_denied())
            }
        }
    }
}

fn built_in_permissions(
    realm_id: RealmId,
    now: DateTime<Utc>,
) -> Result<Vec<PermissionDefinition>, AuthError> {
    [
        (PERMISSION_CATALOG_MANAGE, "Manage the permission catalog"),
        (ROLE_MANAGE, "Manage roles and their permissions"),
        (ASSIGNMENT_MANAGE, "Manage principal role assignments"),
        (SERVICE_ACCOUNT_MANAGE, "Manage service accounts"),
        (API_KEY_MANAGE, "Manage service-account API keys"),
        (API_KEY_SELF, "Manage personal API keys"),
        (AUDIT_READ, "Read IAM audit events"),
    ]
    .into_iter()
    .map(|(key, description)| {
        PermissionDefinition::from_parts(
            realm_id,
            PermissionId::new(),
            permission_key(key)?,
            description,
            true,
            now,
            now,
        )
    })
    .collect()
}

fn required_key_permission(
    actor: UserId,
    principal: PrincipalId,
) -> Result<&'static str, AuthError> {
    match principal {
        PrincipalId::User(user_id) if user_id == actor => Ok(API_KEY_SELF),
        PrincipalId::User(_) => Err(permission_denied()),
        PrincipalId::ServiceAccount(_) => Ok(API_KEY_MANAGE),
        _ => Err(permission_denied()),
    }
}

fn permission_key(value: &str) -> Result<PermissionKey, AuthError> {
    PermissionKey::parse(value)
}

fn permission_denied() -> AuthError {
    AuthError::new(ErrorCode::PermissionDenied, "permission denied", false)
}

fn realm_not_initialized() -> AuthError {
    AuthError::new(
        ErrorCode::RealmNotInitialized,
        "realm IAM is not initialized",
        false,
    )
}

fn invalid_api_key() -> AuthError {
    AuthError::new(ErrorCode::TokenInvalid, "credential is invalid", false)
}

fn iam_event(
    realm_id: RealmId,
    actor: UserId,
    kind: AuthEventKind,
    action: &str,
    subject: impl std::fmt::Display,
    now: DateTime<Utc>,
) -> AuthEvent {
    let mut value = event(realm_id, actor, kind, now);
    value.payload = format!("{{\"action\":\"{action}\",\"subject_id\":\"{subject}\"}}");
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_permission_constants_are_safe() -> Result<(), AuthError> {
        AuthorizationConfig::default().validate()?;
        for value in [
            PERMISSION_CATALOG_MANAGE,
            ROLE_MANAGE,
            ASSIGNMENT_MANAGE,
            SERVICE_ACCOUNT_MANAGE,
            API_KEY_MANAGE,
            API_KEY_SELF,
            AUDIT_READ,
        ] {
            let _ = permission_key(value)?;
        }
        assert!(
            AuthorizationConfig {
                max_rotation_grace: Duration::hours(25),
                ..AuthorizationConfig::default()
            }
            .validate()
            .is_err()
        );
        assert_eq!(sdk_auth_authorization::MAX_PERMISSIONS_PER_ROLE, 256);
        assert_eq!(sdk_auth_authorization::MAX_ROLES_PER_PRINCIPAL, 32);
        Ok(())
    }
}
