//! WebAuthn/passkey ports, state machines, and capability facade.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_crypto::{TokenDigest, TokenGenerator, digest_token, digest_token_text};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::{
    AuditRecord, AuthEventKind, AuthenticationMethod, DeviceContext, OpaqueToken, Passkey,
    PasskeyId, RealmId, SecretString, Session, SessionId, UserId,
};

use crate::{
    AuthConfig, AuthService, Authentication, Clock, CreateSession, SecondFactorProof,
    ports::validate_device,
};

/// Maximum credential identifier size accepted by WebAuthn Level 3.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1_023;

/// Versioned WebAuthn provider metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnProviderMetadata {
    /// Stable provider identifier persisted with provider-owned values.
    pub provider_id: String,
    /// Serialization version for pending ceremony state.
    pub state_format: u16,
    /// Serialization version for long-lived credentials.
    pub credential_format: u16,
}

/// Provider-owned credential representation persisted by an adapter.
#[derive(Clone)]
pub struct VersionedPasskeyCredential {
    /// Credential identifier used to select the persisted credential.
    pub credential_id: Vec<u8>,
    /// Stable provider identifier.
    pub provider_id: String,
    /// Provider credential serialization version.
    pub format_version: u16,
    /// Opaque provider credential bytes.
    pub blob: Vec<u8>,
}

impl fmt::Debug for VersionedPasskeyCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VersionedPasskeyCredential")
            .field("credential_id", &"[REDACTED]")
            .field("provider_id", &self.provider_id)
            .field("format_version", &self.format_version)
            .field("blob", &"[REDACTED]")
            .finish()
    }
}

/// Provider response for the beginning of a WebAuthn ceremony.
#[derive(Clone)]
pub struct WebAuthnCeremony {
    /// JSON transport representation converted to browser binary fields by the host.
    pub public_options_json: String,
    /// Stable provider identifier for the persisted state.
    pub provider_id: String,
    /// Provider state serialization version.
    pub state_format: u16,
    /// Opaque state that must remain server-side.
    pub state: Vec<u8>,
}

impl fmt::Debug for WebAuthnCeremony {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAuthnCeremony")
            .field("public_options_json", &"[REDACTED]")
            .field("provider_id", &self.provider_id)
            .field("state_format", &self.state_format)
            .field("state", &"[REDACTED]")
            .finish()
    }
}

/// Provider-verified passkey created by a registration ceremony.
#[derive(Clone)]
pub struct WebAuthnRegistrationResult {
    /// Binary WebAuthn credential identifier.
    pub credential_id: Vec<u8>,
    /// Stable provider identifier.
    pub provider_id: String,
    /// Provider credential serialization version.
    pub credential_format: u16,
    /// Opaque serialized provider credential.
    pub credential_blob: Vec<u8>,
}

impl fmt::Debug for WebAuthnRegistrationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAuthnRegistrationResult")
            .field("credential_id", &"[REDACTED]")
            .field("provider_id", &self.provider_id)
            .field("credential_format", &self.credential_format)
            .field("credential_blob", &"[REDACTED]")
            .finish()
    }
}

/// Provider-verified WebAuthn authentication result.
#[derive(Clone)]
pub struct WebAuthnAuthenticationResult {
    /// Credential used by the authenticator.
    pub credential_id: Vec<u8>,
    /// Stable provider identifier.
    pub provider_id: String,
    /// Provider credential serialization version.
    pub credential_format: u16,
    /// Updated opaque credential state.
    pub credential_blob: Vec<u8>,
    /// Authenticator signature counter.
    pub signature_counter: u32,
    /// Whether local user verification succeeded.
    pub user_verified: bool,
    /// Whether the credential is eligible for backup or synchronization.
    pub backup_eligible: bool,
    /// Whether the credential is currently backed up.
    pub backed_up: bool,
}

impl fmt::Debug for WebAuthnAuthenticationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAuthnAuthenticationResult")
            .field("credential_id", &"[REDACTED]")
            .field("provider_id", &self.provider_id)
            .field("credential_format", &self.credential_format)
            .field("credential_blob", &"[REDACTED]")
            .field("signature_counter", &self.signature_counter)
            .field("user_verified", &self.user_verified)
            .field("backup_eligible", &self.backup_eligible)
            .field("backed_up", &self.backed_up)
            .finish()
    }
}

/// Framework-independent WebAuthn relying-party port.
///
/// Implementations own protocol parsing and cryptographic verification. No
/// provider-specific type crosses this boundary.
pub trait WebAuthnEngine: Send + Sync {
    /// Returns serialization metadata used for compatibility checks.
    fn metadata(&self) -> WebAuthnProviderMetadata;

    /// Starts UV-required passkey registration for one configured realm.
    fn start_registration(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        user_name: &str,
        display_name: &str,
        existing: &[VersionedPasskeyCredential],
    ) -> Result<WebAuthnCeremony, AuthError>;

    /// Verifies a registration response against server-side state.
    fn finish_registration(
        &self,
        realm_id: RealmId,
        response_json: &str,
        state: &[u8],
        state_format: u16,
    ) -> Result<WebAuthnRegistrationResult, AuthError>;

    /// Starts UV-required authentication with an explicit credential list.
    fn start_authentication(
        &self,
        realm_id: RealmId,
        credentials: &[VersionedPasskeyCredential],
    ) -> Result<WebAuthnCeremony, AuthError>;

    /// Verifies an authentication response and updates provider credential state.
    fn finish_authentication(
        &self,
        realm_id: RealmId,
        response_json: &str,
        state: &[u8],
        state_format: u16,
        credentials: &[VersionedPasskeyCredential],
    ) -> Result<WebAuthnAuthenticationResult, AuthError>;
}

/// Kind of server-side WebAuthn ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyCeremonyKind {
    /// Authenticated passkey enrollment.
    Registration,
    /// Passwordless passkey login.
    Authentication,
}

/// Server-side pending WebAuthn state. The raw state never leaves the host.
#[derive(Clone)]
pub struct PendingPasskeyCeremony {
    /// Digest of the random ceremony handle returned to the trusted host.
    pub digest: TokenDigest,
    /// Realm that owns the ceremony.
    pub realm_id: RealmId,
    /// User bound to the ceremony.
    pub user_id: UserId,
    /// Session that authorized registration, when applicable.
    pub session_id: Option<SessionId>,
    /// Ceremony purpose.
    pub kind: PasskeyCeremonyKind,
    /// Label to assign at registration completion.
    pub label: Option<String>,
    /// Normalized rate-limit subject for authentication.
    pub login_subject: Option<String>,
    /// Device metadata for the future session.
    pub device: DeviceContext,
    /// Requested session lifetime class.
    pub remember_me: bool,
    /// Provider that owns the state.
    pub provider_id: String,
    /// Provider state format.
    pub state_format: u16,
    /// Opaque provider state bytes.
    pub state: Vec<u8>,
    /// Failed finish attempts.
    pub attempts: u32,
    /// Maximum failed finish attempts.
    pub max_attempts: u32,
    /// Ceremony expiration.
    pub expires_at: DateTime<Utc>,
    /// Ceremony creation time.
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for PendingPasskeyCeremony {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingPasskeyCeremony")
            .field("realm_id", &self.realm_id)
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("kind", &self.kind)
            .field("provider_id", &self.provider_id)
            .field("state_format", &self.state_format)
            .field("state", &"[REDACTED]")
            .field("attempts", &self.attempts)
            .field("max_attempts", &self.max_attempts)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Passkey record including provider-owned verification material.
#[derive(Clone)]
pub struct StoredPasskey {
    /// Public passkey metadata.
    pub passkey: Passkey,
    /// Binary protocol credential identifier.
    pub credential_id: Vec<u8>,
    /// Provider that owns the credential blob.
    pub provider_id: String,
    /// Provider credential format.
    pub credential_format: u16,
    /// Opaque provider credential bytes.
    pub credential_blob: Vec<u8>,
    /// Greatest accepted non-zero signature counter.
    pub signature_counter: u32,
}

impl fmt::Debug for StoredPasskey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredPasskey")
            .field("passkey", &self.passkey)
            .field("credential_id", &"[REDACTED]")
            .field("provider_id", &self.provider_id)
            .field("credential_format", &self.credential_format)
            .field("credential_blob", &"[REDACTED]")
            .field("signature_counter", &self.signature_counter)
            .finish()
    }
}

impl StoredPasskey {
    fn versioned(&self) -> VersionedPasskeyCredential {
        VersionedPasskeyCredential {
            credential_id: self.credential_id.clone(),
            provider_id: self.provider_id.clone(),
            format_version: self.credential_format,
            blob: self.credential_blob.clone(),
        }
    }
}

/// Result of loading a ceremony.
#[derive(Debug, Clone)]
pub enum PasskeyCeremonyLookup {
    /// Ceremony is active.
    Active(Box<PendingPasskeyCeremony>),
    /// Ceremony is unknown, consumed, or has the wrong purpose.
    Invalid,
    /// Ceremony was already consumed.
    Reused,
    /// Ceremony expired.
    Expired,
    /// Ceremony reached its failure limit.
    RateLimited,
}

/// Atomic registration completion command.
#[derive(Debug, Clone)]
pub struct CompletePasskeyRegistration {
    /// Presented ceremony handle digest.
    pub ceremony_digest: TokenDigest,
    /// Newly verified credential.
    pub credential: StoredPasskey,
    /// Audit record committed with the credential.
    pub audit: AuditRecord,
    /// Completion time.
    pub now: DateTime<Utc>,
}

/// Registration completion outcome.
#[derive(Debug, Clone)]
pub enum PasskeyRegistrationOutcome {
    /// Credential was inserted and the ceremony consumed.
    Completed(Box<Passkey>),
    /// Ceremony or credential relationship is invalid.
    Invalid,
    /// Ceremony expired.
    Expired,
    /// Ceremony reached its failure limit.
    RateLimited,
    /// Ceremony was already consumed.
    Reused,
    /// Credential identifier already belongs to an account.
    Conflict,
}

/// Atomic authentication completion command.
#[derive(Debug, Clone)]
pub struct CompletePasskeyAuthentication {
    /// Presented ceremony handle digest.
    pub ceremony_digest: TokenDigest,
    /// Passkey selected by the verified assertion.
    pub passkey_id: PasskeyId,
    /// Provider that owns the updated blob.
    pub provider_id: String,
    /// Provider credential serialization version.
    pub credential_format: u16,
    /// Updated provider credential bytes.
    pub credential_blob: Vec<u8>,
    /// Counter returned by the assertion.
    pub signature_counter: u32,
    /// Current backup eligibility.
    pub backup_eligible: bool,
    /// Current backup state.
    pub backed_up: bool,
    /// Session to insert only after every credential check succeeds.
    pub session: CreateSession,
    /// Audit record used if a clone signal is detected.
    pub clone_audit: AuditRecord,
    /// Completion time.
    pub now: DateTime<Utc>,
}

/// Authentication completion outcome.
#[derive(Debug, Clone)]
pub enum PasskeyAuthenticationOutcome {
    /// Credential state and session were committed atomically.
    Completed(Box<Session>),
    /// Ceremony or credential relationship is invalid.
    Invalid,
    /// Ceremony expired.
    Expired,
    /// Ceremony reached its failure limit.
    RateLimited,
    /// Ceremony was already consumed.
    Reused,
    /// A positive counter failed to increase; the passkey was revoked.
    CloneSuspected,
}

/// Persistence contract for passkeys and server-side ceremonies.
#[async_trait]
pub trait PasskeyStore: Send + Sync {
    /// Replaces the pending registration for the same user and session.
    async fn replace_passkey_registration(
        &self,
        ceremony: PendingPasskeyCeremony,
    ) -> Result<(), AuthError>;

    /// Persists a new authentication ceremony.
    async fn create_passkey_authentication(
        &self,
        ceremony: PendingPasskeyCeremony,
    ) -> Result<(), AuthError>;

    /// Loads an active ceremony of the expected kind.
    async fn load_passkey_ceremony(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        kind: PasskeyCeremonyKind,
        now: DateTime<Utc>,
    ) -> Result<PasskeyCeremonyLookup, AuthError>;

    /// Records a failed ceremony response.
    async fn record_passkey_failure(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<crate::AttemptDecision, AuthError>;

    /// Returns active provider credentials owned by a user.
    async fn list_stored_passkeys(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<StoredPasskey>, AuthError>;

    /// Atomically consumes registration state and inserts a globally unique credential.
    async fn complete_passkey_registration(
        &self,
        command: CompletePasskeyRegistration,
    ) -> Result<PasskeyRegistrationOutcome, AuthError>;

    /// Atomically checks credential state, consumes a ceremony, and creates a session.
    async fn complete_passkey_authentication(
        &self,
        command: CompletePasskeyAuthentication,
    ) -> Result<PasskeyAuthenticationOutcome, AuthError>;

    /// Lists public passkey metadata owned by a user.
    async fn list_passkeys(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Passkey>, AuthError>;

    /// Changes one owned passkey label and appends an audit record.
    async fn rename_passkey(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        passkey_id: PasskeyId,
        label: String,
        updated_at: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError>;

    /// Revokes one owned passkey and appends an audit record.
    async fn revoke_passkey(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        passkey_id: PasskeyId,
        revoked_at: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError>;
}

/// Fresh proof accepted for passkey registration and revocation.
#[derive(Debug)]
pub enum AuthenticatorManagementProof {
    /// A recently established UV-required passkey session.
    CurrentPasskeySession,
    /// Current password and, when enrolled, the current second factor.
    Password {
        /// Current account password.
        password: SecretString,
        /// Required when the account has an active TOTP factor.
        second_factor: Option<SecondFactorProof>,
    },
}

/// Starts authenticated passkey registration.
#[derive(Debug)]
pub struct BeginPasskeyRegistrationRequest {
    /// Realm that owns the account.
    pub realm_id: RealmId,
    /// Active access token.
    pub access_token: SecretString,
    /// User-visible passkey label.
    pub label: String,
    /// Fresh management proof.
    pub proof: AuthenticatorManagementProof,
}

/// Registration challenge returned to a trusted host.
#[derive(Debug)]
pub struct PasskeyRegistrationChallenge {
    /// Opaque random handle for server-side ceremony state.
    pub ceremony_token: OpaqueToken,
    /// WebAuthn creation options JSON for a standards-compliant browser converter.
    pub creation_options_json: String,
    /// Ceremony expiration.
    pub expires_at: DateTime<Utc>,
}

/// Completes authenticated passkey registration.
#[derive(Debug)]
pub struct FinishPasskeyRegistrationRequest {
    /// Realm that owns the account.
    pub realm_id: RealmId,
    /// Same active session used to begin registration.
    pub access_token: SecretString,
    /// Opaque ceremony handle.
    pub ceremony_token: SecretString,
    /// Browser `PublicKeyCredential` JSON.
    pub response_json: String,
}

/// Starts username-first passkey authentication.
#[derive(Debug)]
pub struct BeginPasskeyLoginRequest {
    /// Realm in which the identity is resolved.
    pub realm_id: RealmId,
    /// Untrusted email input.
    pub email: String,
    /// Whether the longer configured session lifetime is requested.
    pub remember_me: bool,
    /// Bounded host-supplied device metadata.
    pub device: DeviceContext,
}

/// Authentication challenge returned to a trusted host.
#[derive(Debug)]
pub struct PasskeyLoginChallenge {
    /// Opaque random handle for server-side ceremony state.
    pub ceremony_token: OpaqueToken,
    /// WebAuthn request options JSON for a standards-compliant browser converter.
    pub request_options_json: String,
    /// Ceremony expiration.
    pub expires_at: DateTime<Utc>,
}

/// Completes passkey authentication.
#[derive(Debug)]
pub struct FinishPasskeyLoginRequest {
    /// Realm that owns the ceremony.
    pub realm_id: RealmId,
    /// Opaque ceremony handle.
    pub ceremony_token: SecretString,
    /// Browser `PublicKeyCredential` JSON.
    pub response_json: String,
}

/// Authenticated passkey label update.
#[derive(Debug)]
pub struct RenamePasskeyRequest {
    /// Realm that owns the passkey.
    pub realm_id: RealmId,
    /// Active access token.
    pub access_token: SecretString,
    /// Passkey to rename.
    pub passkey_id: PasskeyId,
    /// Replacement user-visible label.
    pub label: String,
}

/// Authenticated passkey revocation.
#[derive(Debug)]
pub struct RevokePasskeyRequest {
    /// Realm that owns the passkey.
    pub realm_id: RealmId,
    /// Active access token.
    pub access_token: SecretString,
    /// Passkey to revoke.
    pub passkey_id: PasskeyId,
    /// Fresh management proof.
    pub proof: AuthenticatorManagementProof,
}

/// Passkey capability facade.
pub struct PasskeyService {
    store: Arc<dyn PasskeyStore>,
    engine: Arc<dyn WebAuthnEngine>,
    auth: Arc<AuthService>,
    token_generator: Arc<dyn TokenGenerator>,
    clock: Arc<dyn Clock>,
    config: AuthConfig,
}

impl PasskeyService {
    pub(crate) fn new(
        store: Arc<dyn PasskeyStore>,
        engine: Arc<dyn WebAuthnEngine>,
        auth: Arc<AuthService>,
        token_generator: Arc<dyn TokenGenerator>,
        clock: Arc<dyn Clock>,
        config: AuthConfig,
    ) -> Result<Self, AuthError> {
        let metadata = engine.metadata();
        validate_provider_metadata(&metadata)?;
        Ok(Self {
            store,
            engine,
            auth,
            token_generator,
            clock,
            config,
        })
    }

    /// Starts passkey registration after fresh authenticator-management proof.
    #[tracing::instrument(name = "sdk_auth.passkey.begin_registration", skip_all)]
    pub async fn begin_registration(
        &self,
        request: BeginPasskeyRegistrationRequest,
    ) -> Result<PasskeyRegistrationChallenge, AuthError> {
        let label = validate_label(request.label, self.config.max_passkey_label_chars)?;
        let validated = self
            .auth
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        self.auth
            .verify_authenticator_management(&validated, &request.proof, &self.config)
            .await?;
        let existing = self
            .store
            .list_stored_passkeys(request.realm_id, validated.user.id)
            .await?;
        if existing.len() >= self.config.max_passkeys_per_user {
            return Err(AuthError::new(
                ErrorCode::Conflict,
                "passkey limit reached",
                false,
            ));
        }
        let provider_credentials = existing
            .iter()
            .map(StoredPasskey::versioned)
            .collect::<Vec<_>>();
        let ceremony = self.engine.start_registration(
            request.realm_id,
            validated.user.id,
            validated.user.email.normalized(),
            validated.user.email.as_str(),
            &provider_credentials,
        )?;
        self.validate_ceremony(&ceremony)?;
        let now = self.clock.now();
        let expires_at = now + self.config.passkey_ceremony_ttl;
        let token = self.token_generator.generate()?;
        self.store
            .replace_passkey_registration(PendingPasskeyCeremony {
                digest: digest_token(&token),
                realm_id: request.realm_id,
                user_id: validated.user.id,
                session_id: Some(validated.session.id),
                kind: PasskeyCeremonyKind::Registration,
                label: Some(label),
                login_subject: None,
                device: DeviceContext::default(),
                remember_me: false,
                provider_id: ceremony.provider_id,
                state_format: ceremony.state_format,
                state: ceremony.state,
                attempts: 0,
                max_attempts: self.config.max_passkey_attempts,
                expires_at,
                created_at: now,
            })
            .await?;
        Ok(PasskeyRegistrationChallenge {
            ceremony_token: token,
            creation_options_json: ceremony.public_options_json,
            expires_at,
        })
    }

    /// Verifies a browser registration response and persists a globally unique passkey.
    #[tracing::instrument(name = "sdk_auth.passkey.finish_registration", skip_all)]
    pub async fn finish_registration(
        &self,
        request: FinishPasskeyRegistrationRequest,
    ) -> Result<Passkey, AuthError> {
        validate_response_json(&request.response_json, self.config.max_webauthn_json_bytes)?;
        let validated = self
            .auth
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        let digest = digest_token_text(&request.ceremony_token);
        let now = self.clock.now();
        let ceremony = self
            .active_ceremony(
                request.realm_id,
                digest,
                PasskeyCeremonyKind::Registration,
                now,
            )
            .await?;
        self.ensure_pending_compatible(&ceremony)?;
        if ceremony.user_id != validated.user.id
            || ceremony.session_id != Some(validated.session.id)
        {
            return Err(AuthError::invalid_credentials());
        }
        let result = match self.engine.finish_registration(
            request.realm_id,
            &request.response_json,
            &ceremony.state,
            ceremony.state_format,
        ) {
            Ok(result) => result,
            Err(error) if error.code() == ErrorCode::Misconfigured => return Err(error),
            Err(_) => {
                self.record_failure(request.realm_id, digest, now).await?;
                return Err(AuthError::invalid_credentials());
            }
        };
        self.validate_registration_result(&ceremony, &result)?;
        let passkey = Passkey {
            realm_id: request.realm_id,
            id: PasskeyId::new(),
            user_id: validated.user.id,
            label: ceremony.label.ok_or_else(AuthError::invalid_credentials)?,
            backup_eligible: false,
            backed_up: false,
            created_at: now,
            last_used_at: None,
            revoked_at: None,
        };
        let outcome = self
            .store
            .complete_passkey_registration(CompletePasskeyRegistration {
                ceremony_digest: digest,
                credential: StoredPasskey {
                    passkey,
                    credential_id: result.credential_id,
                    provider_id: result.provider_id,
                    credential_format: result.credential_format,
                    credential_blob: result.credential_blob,
                    signature_counter: 0,
                },
                audit: AuditRecord::succeeded_user_action(
                    request.realm_id,
                    validated.user.id,
                    AuthEventKind::PasskeyRegistered,
                    now,
                ),
                now,
            })
            .await?;
        registration_outcome(outcome)
    }

    /// Starts username-first, UV-required passkey authentication.
    #[tracing::instrument(name = "sdk_auth.passkey.begin_login", skip_all)]
    pub async fn begin_login(
        &self,
        request: BeginPasskeyLoginRequest,
    ) -> Result<PasskeyLoginChallenge, AuthError> {
        let email = sdk_auth_types::EmailAddress::parse(request.email)?;
        let device = validate_device(
            request.device,
            self.config.max_device_name_chars,
            self.config.max_device_metadata_bytes,
        )?;
        let now = self.clock.now();
        self.auth
            .record_authentication_attempt(
                request.realm_id,
                email.normalized(),
                device.network_hash.as_deref(),
                now,
            )
            .await?;
        let stored_user = self
            .auth
            .find_user_by_email(request.realm_id, email.normalized())
            .await?
            .ok_or_else(AuthError::invalid_credentials)?;
        if self.config.require_verified_email && !stored_user.user.email_verified {
            return Err(AuthError::invalid_credentials());
        }
        let credentials = self
            .store
            .list_stored_passkeys(request.realm_id, stored_user.user.id)
            .await?;
        if credentials.is_empty() {
            return Err(AuthError::invalid_credentials());
        }
        let provider_credentials = credentials
            .iter()
            .map(StoredPasskey::versioned)
            .collect::<Vec<_>>();
        let ceremony = self
            .engine
            .start_authentication(request.realm_id, &provider_credentials)?;
        self.validate_ceremony(&ceremony)?;
        let expires_at = now + self.config.passkey_ceremony_ttl;
        let token = self.token_generator.generate()?;
        self.store
            .create_passkey_authentication(PendingPasskeyCeremony {
                digest: digest_token(&token),
                realm_id: request.realm_id,
                user_id: stored_user.user.id,
                session_id: None,
                kind: PasskeyCeremonyKind::Authentication,
                label: None,
                login_subject: Some(email.normalized().to_owned()),
                device,
                remember_me: request.remember_me,
                provider_id: ceremony.provider_id,
                state_format: ceremony.state_format,
                state: ceremony.state,
                attempts: 0,
                max_attempts: self.config.max_passkey_attempts,
                expires_at,
                created_at: now,
            })
            .await?;
        Ok(PasskeyLoginChallenge {
            ceremony_token: token,
            request_options_json: ceremony.public_options_json,
            expires_at,
        })
    }

    /// Verifies a browser assertion and creates an opaque SDK session atomically.
    #[tracing::instrument(name = "sdk_auth.passkey.finish_login", skip_all)]
    pub async fn finish_login(
        &self,
        request: FinishPasskeyLoginRequest,
    ) -> Result<Authentication, AuthError> {
        validate_response_json(&request.response_json, self.config.max_webauthn_json_bytes)?;
        let digest = digest_token_text(&request.ceremony_token);
        let now = self.clock.now();
        let ceremony = self
            .active_ceremony(
                request.realm_id,
                digest,
                PasskeyCeremonyKind::Authentication,
                now,
            )
            .await?;
        self.ensure_pending_compatible(&ceremony)?;
        let credentials = self
            .store
            .list_stored_passkeys(request.realm_id, ceremony.user_id)
            .await?;
        if credentials.is_empty() {
            return Err(AuthError::invalid_credentials());
        }
        let provider_credentials = credentials
            .iter()
            .map(StoredPasskey::versioned)
            .collect::<Vec<_>>();
        let result = match self.engine.finish_authentication(
            request.realm_id,
            &request.response_json,
            &ceremony.state,
            ceremony.state_format,
            &provider_credentials,
        ) {
            Ok(result) if result.user_verified => result,
            Err(error) if error.code() == ErrorCode::Misconfigured => return Err(error),
            _ => {
                self.record_failure(request.realm_id, digest, now).await?;
                return Err(AuthError::invalid_credentials());
            }
        };
        let Some(stored_passkey) = credentials.iter().find(|credential| {
            credential.credential_id == result.credential_id
                && credential.provider_id == result.provider_id
                && credential.credential_format == result.credential_format
        }) else {
            self.record_failure(request.realm_id, digest, now).await?;
            return Err(AuthError::invalid_credentials());
        };
        validate_credential_material(
            &result.credential_id,
            &result.credential_blob,
            self.config.max_webauthn_state_bytes,
        )?;
        let stored_user = self
            .auth
            .find_user_by_id(request.realm_id, ceremony.user_id)
            .await?
            .ok_or_else(AuthError::invalid_credentials)?;
        let prepared = self.auth.prepare_external_session(
            &stored_user.user,
            ceremony.device,
            ceremony.remember_me,
            AuthenticationMethod::Passkey,
            Some(now),
            now,
        )?;
        let tokens = prepared.tokens;
        let outcome = self
            .store
            .complete_passkey_authentication(CompletePasskeyAuthentication {
                ceremony_digest: digest,
                passkey_id: stored_passkey.passkey.id,
                provider_id: result.provider_id,
                credential_format: result.credential_format,
                credential_blob: result.credential_blob,
                signature_counter: result.signature_counter,
                backup_eligible: result.backup_eligible,
                backed_up: result.backed_up,
                session: prepared.command,
                clone_audit: AuditRecord {
                    id: sdk_auth_types::AuditId::new(),
                    realm_id: request.realm_id,
                    actor: sdk_auth_types::AuditActor::System,
                    subject_user_id: Some(ceremony.user_id),
                    kind: AuthEventKind::PasskeyCloneSuspected,
                    outcome: sdk_auth_types::AuditOutcome::Denied,
                    metadata_json: "{}".to_owned(),
                    occurred_at: now,
                    outbox_event_id: None,
                },
                now,
            })
            .await?;
        match outcome {
            PasskeyAuthenticationOutcome::Completed(session) => {
                if let Some(subject) = ceremony.login_subject {
                    self.auth
                        .clear_authentication_attempts(request.realm_id, &subject)
                        .await?;
                }
                Ok(Authentication {
                    user: stored_user.user,
                    session: *session,
                    tokens,
                    trusted_device_grant: None,
                })
            }
            PasskeyAuthenticationOutcome::Invalid => Err(AuthError::invalid_credentials()),
            PasskeyAuthenticationOutcome::Expired => Err(expired()),
            PasskeyAuthenticationOutcome::RateLimited => Err(rate_limited()),
            PasskeyAuthenticationOutcome::Reused => Err(reused()),
            PasskeyAuthenticationOutcome::CloneSuspected => Err(AuthError::new(
                ErrorCode::AuthenticatorCompromised,
                "authenticator was disabled after a security anomaly",
                false,
            )),
        }
    }

    /// Lists active and revoked passkeys owned by the authenticated user.
    pub async fn list(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
    ) -> Result<Vec<Passkey>, AuthError> {
        let validated = self.auth.validate_access(realm_id, access_token).await?;
        self.store.list_passkeys(realm_id, validated.user.id).await
    }

    /// Renames an owned passkey. The label never influences authorization.
    pub async fn rename(&self, request: RenamePasskeyRequest) -> Result<bool, AuthError> {
        let label = validate_label(request.label, self.config.max_passkey_label_chars)?;
        let validated = self
            .auth
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        let now = self.clock.now();
        self.store
            .rename_passkey(
                request.realm_id,
                validated.user.id,
                request.passkey_id,
                label,
                now,
                AuditRecord::succeeded_user_action(
                    request.realm_id,
                    validated.user.id,
                    AuthEventKind::PasskeyRenamed,
                    now,
                ),
            )
            .await
    }

    /// Revokes an owned passkey after fresh management proof.
    pub async fn revoke(&self, request: RevokePasskeyRequest) -> Result<bool, AuthError> {
        let validated = self
            .auth
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        self.auth
            .verify_authenticator_management(&validated, &request.proof, &self.config)
            .await?;
        let now = self.clock.now();
        self.store
            .revoke_passkey(
                request.realm_id,
                validated.user.id,
                request.passkey_id,
                now,
                AuditRecord::succeeded_user_action(
                    request.realm_id,
                    validated.user.id,
                    AuthEventKind::PasskeyRevoked,
                    now,
                ),
            )
            .await
    }

    async fn active_ceremony(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        kind: PasskeyCeremonyKind,
        now: DateTime<Utc>,
    ) -> Result<PendingPasskeyCeremony, AuthError> {
        match self
            .store
            .load_passkey_ceremony(realm_id, digest, kind, now)
            .await?
        {
            PasskeyCeremonyLookup::Active(value) => Ok(*value),
            PasskeyCeremonyLookup::Invalid => Err(AuthError::invalid_credentials()),
            PasskeyCeremonyLookup::Reused => Err(reused()),
            PasskeyCeremonyLookup::Expired => Err(expired()),
            PasskeyCeremonyLookup::RateLimited => Err(rate_limited()),
        }
    }

    async fn record_failure(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        if matches!(
            self.store
                .record_passkey_failure(realm_id, digest, now)
                .await?,
            crate::AttemptDecision::BlockedUntil(_)
        ) {
            return Err(rate_limited());
        }
        Ok(())
    }

    fn validate_ceremony(&self, ceremony: &WebAuthnCeremony) -> Result<(), AuthError> {
        let metadata = self.engine.metadata();
        if ceremony.provider_id != metadata.provider_id
            || ceremony.state_format != metadata.state_format
            || ceremony.public_options_json.is_empty()
            || ceremony.public_options_json.len() > self.config.max_webauthn_json_bytes
            || ceremony.state.is_empty()
            || ceremony.state.len() > self.config.max_webauthn_state_bytes
        {
            return Err(AuthError::new(
                ErrorCode::Internal,
                "WebAuthn provider returned invalid state",
                false,
            ));
        }
        Ok(())
    }

    fn ensure_pending_compatible(
        &self,
        ceremony: &PendingPasskeyCeremony,
    ) -> Result<(), AuthError> {
        let metadata = self.engine.metadata();
        if ceremony.provider_id != metadata.provider_id
            || ceremony.state_format != metadata.state_format
        {
            return Err(AuthError::new(
                ErrorCode::Misconfigured,
                "persisted WebAuthn state is incompatible with this provider",
                false,
            ));
        }
        Ok(())
    }

    fn validate_registration_result(
        &self,
        ceremony: &PendingPasskeyCeremony,
        result: &WebAuthnRegistrationResult,
    ) -> Result<(), AuthError> {
        let metadata = self.engine.metadata();
        if result.provider_id != ceremony.provider_id
            || result.provider_id != metadata.provider_id
            || result.credential_format != metadata.credential_format
        {
            return Err(AuthError::new(
                ErrorCode::Internal,
                "WebAuthn provider returned an incompatible credential",
                false,
            ));
        }
        validate_credential_material(
            &result.credential_id,
            &result.credential_blob,
            self.config.max_webauthn_state_bytes,
        )
    }
}

fn validate_provider_metadata(metadata: &WebAuthnProviderMetadata) -> Result<(), AuthError> {
    if metadata.provider_id.is_empty()
        || metadata.provider_id.len() > 64
        || metadata.state_format == 0
        || metadata.credential_format == 0
    {
        return Err(AuthError::new(
            ErrorCode::Misconfigured,
            "WebAuthn provider metadata is invalid",
            false,
        ));
    }
    Ok(())
}

fn validate_label(value: String, max_chars: usize) -> Result<String, AuthError> {
    let value = value.trim().to_owned();
    if value.is_empty() || value.chars().count() > max_chars {
        return Err(AuthError::invalid_input());
    }
    Ok(value)
}

fn validate_response_json(value: &str, max_bytes: usize) -> Result<(), AuthError> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(AuthError::invalid_input());
    }
    Ok(())
}

fn validate_credential_material(
    credential_id: &[u8],
    blob: &[u8],
    max_blob_bytes: usize,
) -> Result<(), AuthError> {
    if credential_id.is_empty()
        || credential_id.len() > MAX_CREDENTIAL_ID_BYTES
        || blob.is_empty()
        || blob.len() > max_blob_bytes
    {
        return Err(AuthError::new(
            ErrorCode::Internal,
            "WebAuthn provider returned invalid credential material",
            false,
        ));
    }
    Ok(())
}

fn registration_outcome(outcome: PasskeyRegistrationOutcome) -> Result<Passkey, AuthError> {
    match outcome {
        PasskeyRegistrationOutcome::Completed(passkey) => Ok(*passkey),
        PasskeyRegistrationOutcome::Invalid => Err(AuthError::invalid_credentials()),
        PasskeyRegistrationOutcome::Expired => Err(expired()),
        PasskeyRegistrationOutcome::RateLimited => Err(rate_limited()),
        PasskeyRegistrationOutcome::Reused => Err(reused()),
        PasskeyRegistrationOutcome::Conflict => Err(AuthError::new(
            ErrorCode::Conflict,
            "passkey is already registered",
            false,
        )),
    }
}

fn expired() -> AuthError {
    AuthError::new(ErrorCode::TokenExpired, "WebAuthn ceremony expired", false)
}

fn reused() -> AuthError {
    AuthError::new(
        ErrorCode::TokenReused,
        "WebAuthn ceremony was already used",
        false,
    )
}

fn rate_limited() -> AuthError {
    AuthError::new(
        ErrorCode::RateLimited,
        "too many authentication attempts",
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passkey(now: DateTime<Utc>) -> Passkey {
        Passkey {
            realm_id: RealmId::new(),
            id: PasskeyId::new(),
            user_id: UserId::new(),
            label: "security key".to_owned(),
            backup_eligible: true,
            backed_up: false,
            created_at: now,
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn sensitive_webauthn_debug_values_are_redacted() {
        let credential = VersionedPasskeyCredential {
            credential_id: b"secret-credential-id".to_vec(),
            provider_id: "provider".to_owned(),
            format_version: 1,
            blob: b"secret-credential".to_vec(),
        };
        let ceremony = WebAuthnCeremony {
            public_options_json: "secret-options".to_owned(),
            provider_id: "provider".to_owned(),
            state_format: 1,
            state: b"secret-state".to_vec(),
        };
        let registration = WebAuthnRegistrationResult {
            credential_id: b"secret-registration-id".to_vec(),
            provider_id: "provider".to_owned(),
            credential_format: 1,
            credential_blob: b"secret-registration".to_vec(),
        };
        let authentication = WebAuthnAuthenticationResult {
            credential_id: b"secret-authentication-id".to_vec(),
            provider_id: "provider".to_owned(),
            credential_format: 1,
            credential_blob: b"secret-authentication".to_vec(),
            signature_counter: 7,
            user_verified: true,
            backup_eligible: true,
            backed_up: true,
        };
        let now = Utc::now();
        let pending = PendingPasskeyCeremony {
            digest: digest_token_text(&SecretString::new("secret-handle")),
            realm_id: RealmId::new(),
            user_id: UserId::new(),
            session_id: Some(SessionId::new()),
            kind: PasskeyCeremonyKind::Registration,
            label: Some("label".to_owned()),
            login_subject: None,
            device: DeviceContext::default(),
            remember_me: false,
            provider_id: "provider".to_owned(),
            state_format: 1,
            state: b"secret-pending-state".to_vec(),
            attempts: 0,
            max_attempts: 5,
            expires_at: now,
            created_at: now,
        };
        let stored = StoredPasskey {
            passkey: passkey(now),
            credential_id: b"secret-stored-id".to_vec(),
            provider_id: "provider".to_owned(),
            credential_format: 1,
            credential_blob: b"secret-stored-credential".to_vec(),
            signature_counter: 9,
        };

        let rendered = format!(
            "{credential:?}{ceremony:?}{registration:?}{authentication:?}{pending:?}{stored:?}"
        );
        assert!(rendered.contains("[REDACTED]"));
        for secret in [
            "secret-credential-id",
            "secret-options",
            "secret-registration-id",
            "secret-authentication-id",
            "secret-pending-state",
            "secret-stored-id",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn local_webauthn_invariants_reject_every_invalid_boundary() {
        let valid_metadata = WebAuthnProviderMetadata {
            provider_id: "provider".to_owned(),
            state_format: 1,
            credential_format: 1,
        };
        assert!(validate_provider_metadata(&valid_metadata).is_ok());
        for metadata in [
            WebAuthnProviderMetadata {
                provider_id: String::new(),
                ..valid_metadata.clone()
            },
            WebAuthnProviderMetadata {
                provider_id: "x".repeat(65),
                ..valid_metadata.clone()
            },
            WebAuthnProviderMetadata {
                state_format: 0,
                ..valid_metadata.clone()
            },
            WebAuthnProviderMetadata {
                credential_format: 0,
                ..valid_metadata
            },
        ] {
            assert_eq!(
                validate_provider_metadata(&metadata)
                    .err()
                    .map(|error| error.code()),
                Some(ErrorCode::Misconfigured)
            );
        }

        assert_eq!(validate_label(" key ".to_owned(), 8), Ok("key".to_owned()));
        assert_eq!(
            validate_label(" ".to_owned(), 8)
                .err()
                .map(|error| error.code()),
            Some(ErrorCode::InvalidInput)
        );
        assert_eq!(
            validate_label("too long".to_owned(), 3)
                .err()
                .map(|error| error.code()),
            Some(ErrorCode::InvalidInput)
        );
        assert!(validate_response_json("{}", 2).is_ok());
        assert!(validate_response_json("", 2).is_err());
        assert!(validate_response_json("{}", 1).is_err());

        assert!(validate_credential_material(&[1], &[2], 1).is_ok());
        for (credential_id, blob, max_blob_bytes) in [
            (Vec::new(), vec![2], 1),
            (vec![1; MAX_CREDENTIAL_ID_BYTES + 1], vec![2], 1),
            (vec![1], Vec::new(), 1),
            (vec![1], vec![2, 3], 1),
        ] {
            assert_eq!(
                validate_credential_material(&credential_id, &blob, max_blob_bytes)
                    .err()
                    .map(|error| error.code()),
                Some(ErrorCode::Internal)
            );
        }
    }

    #[test]
    fn registration_outcomes_have_stable_public_errors() -> Result<(), AuthError> {
        let completed = registration_outcome(PasskeyRegistrationOutcome::Completed(Box::new(
            passkey(Utc::now()),
        )))?;
        assert_eq!(completed.label, "security key");

        for (outcome, code) in [
            (
                PasskeyRegistrationOutcome::Invalid,
                ErrorCode::InvalidCredentials,
            ),
            (PasskeyRegistrationOutcome::Expired, ErrorCode::TokenExpired),
            (
                PasskeyRegistrationOutcome::RateLimited,
                ErrorCode::RateLimited,
            ),
            (PasskeyRegistrationOutcome::Reused, ErrorCode::TokenReused),
            (PasskeyRegistrationOutcome::Conflict, ErrorCode::Conflict),
        ] {
            assert_eq!(
                registration_outcome(outcome)
                    .err()
                    .map(|error| error.code()),
                Some(code)
            );
        }
        Ok(())
    }
}
