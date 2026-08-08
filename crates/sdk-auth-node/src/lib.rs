//! Server-side Node.js binding for SDK-Auth.
//!
//! N-API glue is a translation boundary only; authentication rules remain in
//! `sdk-auth-core`.

use std::sync::Arc;

use chrono::Duration;
use napi::{Error, Result, Status, bindgen_prelude::Uint8Array};
use napi_derive::napi;
use sdk_auth_authorization::{
    ApiKey, CredentialKind, PermissionDefinition, PermissionKey, PrincipalId, Role, RoleKey,
    ServiceAccount,
};
use sdk_auth_core::{
    AuthConfig, AuthService, AuthenticatorManagementProof, AuthorizationCredential,
    AuthorizeRequest, BeginPasskeyLoginRequest, BeginPasskeyRegistrationRequest,
    BeginTotpEnrollmentRequest, BeginTotpReplacementRequest, CompleteLoginRequest,
    ConfirmTotpEnrollmentRequest, FinishPasskeyLoginRequest, FinishPasskeyRegistrationRequest,
    IamAdminProof, LoginOutcome, LoginRequest, ManageMfaRequest, MfaManagementProof, PasskeyStore,
    RateLimitStore, RefreshRequest, RegisterRequest, RenamePasskeyRequest, ResetPasswordRequest,
    RevokePasskeyRequest, RevokeTrustedDeviceRequest, SdkAuth, SdkStore, SecondFactorMethod,
    SecondFactorProof,
};
use sdk_auth_crypto::{Argon2PasswordEngine, OsTokenGenerator, VaultKey, XChaCha20Vault};
use sdk_auth_error::AuthError;
use sdk_auth_postgres::{PostgresAuthStore, PostgresConfig, PostgresMigrator};
use sdk_auth_redis::{RedisRateLimitConfig, RedisRateLimitStore};
use sdk_auth_sqlite::{SqliteAuthStore, SqliteMigrator};
use sdk_auth_types::{
    ApiKeyId, DeviceContext, MfaEnrollmentId, Passkey, PasskeyId, PermissionId, RealmId, RoleId,
    SecretBytes, SecretString, ServiceAccountId, TrustedDevice, TrustedDeviceId, UserId,
};
use sdk_auth_webauthn::{WebAuthnRealmConfig, WebAuthnRegistry};
use url::Url;

/// One versioned XChaCha20-Poly1305 vault key supplied by the host.
#[napi(object)]
pub struct NodeVaultKey {
    /// Stable key identifier persisted with ciphertext.
    pub key_id: String,
    /// Exactly 32 bytes of key material.
    pub material: Uint8Array,
}

/// Constructor options for the server-side authentication service.
#[napi(object)]
pub struct NodeAuthOptions {
    /// Path to a database already migrated with [`migrate_sqlite`].
    pub sqlite_path: String,
    /// Key used for newly sealed MFA secrets.
    pub active_key_id: String,
    /// Active and retained decryption keys.
    pub vault_keys: Vec<NodeVaultKey>,
    /// Optional exact-origin WebAuthn relying parties, one per SDK realm.
    pub webauthn_realms: Option<Vec<NodeWebAuthnRealmOptions>>,
}

/// Asynchronous PostgreSQL composition options for a server-side Node host.
#[napi(object)]
pub struct NodePostgresAuthOptions {
    /// PostgreSQL URL. Production endpoints require verified TLS.
    pub database_url: String,
    /// Permits plaintext PostgreSQL only when the URL targets loopback.
    pub allow_insecure_localhost: Option<bool>,
    /// Key used for newly sealed MFA secrets.
    pub active_key_id: String,
    /// Active and retained decryption keys.
    pub vault_keys: Vec<NodeVaultKey>,
    /// Optional exact-origin WebAuthn relying parties, one per SDK realm.
    pub webauthn_realms: Option<Vec<NodeWebAuthnRealmOptions>>,
    /// Optional dedicated Redis rate limiter. PostgreSQL is used when absent.
    pub redis_rate_limit: Option<NodeRedisRateLimitOptions>,
}

/// Dedicated distributed throttling options for the Node composition root.
#[napi(object)]
pub struct NodeRedisRateLimitOptions {
    /// Redis URL. Production endpoints require TLS through `rediss://`.
    pub redis_url: String,
    /// Exactly 32 secret bytes used to hide email/network bucket subjects.
    pub privacy_key: Uint8Array,
    /// Optional deployment namespace. Defaults to `sdk-auth`.
    pub namespace: Option<String>,
    /// Permits plaintext Redis only when the URL targets loopback.
    pub allow_insecure_localhost: Option<bool>,
}

/// Exact-origin WebAuthn relying-party configuration for one SDK realm.
#[napi(object)]
pub struct NodeWebAuthnRealmOptions {
    /// SDK realm mapped to this relying party.
    pub realm_id: String,
    /// Immutable relying-party identifier.
    pub rp_id: String,
    /// Human-readable relying-party name.
    pub rp_name: String,
    /// Exact HTTPS or Android signing-certificate origins accepted for ceremonies.
    pub origins: Vec<String>,
}

/// Fresh proof for passkey registration or revocation.
#[napi(object)]
pub struct NodeAuthenticatorManagementProof {
    /// `current_passkey_session` or `password`.
    pub kind: String,
    /// Current password when `kind` is `password`.
    pub password: Option<String>,
    /// Optional `totp` or `recovery_code` for an MFA-enabled account.
    pub second_factor_kind: Option<String>,
    /// Current second-factor value.
    pub second_factor: Option<String>,
}

/// Fresh human proof required for one IAM mutation.
#[napi(object)]
pub struct NodeIamAdminProof {
    /// Realm being administered.
    pub realm_id: String,
    /// Active opaque user access token.
    pub access_token: String,
    /// Current password.
    pub password: String,
    /// `totp` or `recovery_code`.
    pub proof_kind: String,
    /// Current second-factor proof.
    pub second_factor: String,
}

/// Result of an explicit SQLite migration.
#[napi(object)]
pub struct NodeMigrationReport {
    /// Schema version before migration.
    pub from: u32,
    /// Schema version after migration.
    pub to: u32,
    /// Ordered versions applied by the invocation.
    pub applied: Vec<u32>,
}

/// Device metadata supplied by a trusted Node.js host.
#[napi(object)]
pub struct NodeDeviceContext {
    /// User-visible device label.
    pub name: Option<String>,
    /// Privacy-preserving network fingerprint created by the host.
    pub network_hash: Option<String>,
    /// Bounded user-agent summary.
    pub user_agent: Option<String>,
}

/// Successful registration returned to the trusted Node.js host.
#[napi(object)]
pub struct NodeRegistration {
    /// Created user identifier.
    pub user_id: String,
    /// Validated email.
    pub email: String,
    /// Verification secret that must never be logged.
    pub verification_token: String,
    /// Verification expiration in RFC 3339 format.
    pub verification_expires_at: String,
}

/// Successful authentication or refresh result.
#[napi(object)]
pub struct NodeAuthentication {
    /// Authenticated user identifier.
    pub user_id: String,
    /// Active session identifier.
    pub session_id: String,
    /// Short-lived access bearer token.
    pub access_token: String,
    /// Single-use refresh bearer token.
    pub refresh_token: String,
    /// Access expiration in RFC 3339 format.
    pub access_expires_at: String,
    /// Session expiration in RFC 3339 format.
    pub session_expires_at: String,
    /// New or rotated trusted-device identifier.
    pub trusted_device_id: Option<String>,
    /// New or rotated trusted-device bearer token.
    pub trusted_device_token: Option<String>,
    /// Absolute trusted-device expiration.
    pub trusted_device_expires_at: Option<String>,
}

/// WebAuthn challenge with server-side state referenced by an opaque handle.
#[napi(object)]
pub struct NodePasskeyChallenge {
    /// Opaque single-use ceremony handle.
    pub ceremony_token: String,
    /// JSON options converted to browser binary fields before `create` or `get`.
    pub public_options_json: String,
    /// Ceremony expiration in RFC 3339 format.
    pub expires_at: String,
}

/// Public passkey metadata without credential verification material.
#[napi(object)]
pub struct NodePasskey {
    /// Stable SDK passkey identifier.
    pub id: String,
    /// User-visible passkey label.
    pub label: String,
    /// Whether the authenticator is backup eligible.
    pub backup_eligible: bool,
    /// Current backup state.
    pub backed_up: bool,
    /// Creation time in RFC 3339 format.
    pub created_at: String,
    /// Most recent successful use.
    pub last_used_at: Option<String>,
    /// Revocation time.
    pub revoked_at: Option<String>,
}

/// Discriminated result of the password phase.
#[napi(object)]
pub struct NodeLoginOutcome {
    /// `authenticated` or `second_factor_required`.
    pub kind: String,
    /// Present only when authentication completed.
    pub authentication: Option<NodeAuthentication>,
    /// Opaque pending-login token.
    pub challenge_token: Option<String>,
    /// Supported proof method names.
    pub methods: Vec<String>,
    /// Pending-login expiration.
    pub challenge_expires_at: Option<String>,
}

/// One-time challenge returned to a trusted delivery layer.
#[napi(object)]
pub struct NodeChallenge {
    /// One-time bearer secret.
    pub token: String,
    /// Expiration in RFC 3339 format.
    pub expires_at: String,
}

/// Secret TOTP enrollment material returned once.
#[napi(object)]
pub struct NodeTotpEnrollment {
    /// Pending enrollment identifier.
    pub enrollment_id: String,
    /// Base32 seed for manual entry.
    pub base32_secret: String,
    /// Secret-bearing `otpauth` URI.
    pub provisioning_uri: String,
    /// Enrollment expiration.
    pub expires_at: String,
}

/// Result of activating or replacing TOTP.
#[napi(object)]
pub struct NodeTotpActivation {
    /// Single-display recovery codes.
    pub recovery_codes: Vec<String>,
    /// Optional trusted-device identifier.
    pub trusted_device_id: Option<String>,
    /// Optional trusted-device bearer token.
    pub trusted_device_token: Option<String>,
    /// Optional absolute trusted-device expiration.
    pub trusted_device_expires_at: Option<String>,
}

/// Public trusted-device metadata.
#[napi(object)]
pub struct NodeTrustedDevice {
    /// Stable grant identifier.
    pub id: String,
    /// User-visible device label.
    pub name: Option<String>,
    /// Grant creation time.
    pub created_at: String,
    /// Last successful token rotation.
    pub last_used_at: String,
    /// Absolute expiration.
    pub expires_at: String,
    /// Revocation time, if revoked.
    pub revoked_at: Option<String>,
}

/// Registered permission metadata.
#[napi(object)]
pub struct NodePermission {
    /// Stable permission identifier.
    pub id: String,
    /// Canonical `resource:action` key.
    pub key: String,
    /// Human-readable description.
    pub description: String,
    /// Whether grants can currently authorize access.
    pub enabled: bool,
}

/// Non-hierarchical role metadata.
#[napi(object)]
pub struct NodeRole {
    /// Stable role identifier.
    pub id: String,
    /// Canonical role key.
    pub key: String,
    /// Human-readable name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether SDK invariants protect the role.
    pub reserved: bool,
    /// Whether assignments through this role are active.
    pub enabled: bool,
}

/// Public service-account metadata.
#[napi(object)]
pub struct NodeServiceAccount {
    /// Stable service-account identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether its credentials can authorize access.
    pub enabled: bool,
}

/// Public API-key metadata without bearer material.
#[napi(object)]
pub struct NodeApiKey {
    /// Public key identifier.
    pub id: String,
    /// Principal kind: `user` or `service_account`.
    pub principal_kind: String,
    /// Principal identifier.
    pub principal_id: String,
    /// Human-readable key name.
    pub name: String,
    /// Exact permission ceiling.
    pub scopes: Vec<String>,
    /// Absolute expiration.
    pub expires_at: String,
    /// Rotation overlap cutoff for a predecessor.
    pub grace_expires_at: Option<String>,
    /// Revocation time.
    pub revoked_at: Option<String>,
}

/// One-time API-key issuance response.
#[napi(object)]
pub struct NodeApiKeyGrant {
    /// Public metadata.
    pub key: NodeApiKey,
    /// Bearer credential returned exactly once.
    pub credential: String,
}

/// Successful authorization result.
#[napi(object)]
pub struct NodeAuthorizationGrant {
    /// Authorized principal kind.
    pub principal_kind: String,
    /// Authorized principal identifier.
    pub principal_id: String,
    /// Exact permission checked by the Core.
    pub permission: String,
    /// Credential kind: `user_access_token` or `api_key`.
    pub credential_kind: String,
    /// API-key identifier when applicable.
    pub api_key_id: Option<String>,
}

/// Applies all pending SQLite migrations. Call before constructing the service.
#[napi]
pub fn migrate_sqlite(sqlite_path: String) -> Result<NodeMigrationReport> {
    let report = SqliteMigrator::migrate(sqlite_path).map_err(node_error)?;
    Ok(NodeMigrationReport {
        from: report.from,
        to: report.to,
        applied: report.applied,
    })
}

/// Applies explicit PostgreSQL migrations without starting an auth service.
#[napi]
pub async fn migrate_postgres(
    database_url: String,
    allow_insecure_localhost: Option<bool>,
) -> Result<NodeMigrationReport> {
    let mut config = PostgresConfig::new(SecretString::new(database_url));
    config.allow_insecure_localhost = allow_insecure_localhost.unwrap_or(false);
    let report = PostgresMigrator::migrate(&config)
        .await
        .map_err(node_error)?;
    Ok(NodeMigrationReport {
        from: report.from,
        to: report.to,
        applied: report.applied,
    })
}

/// Node.js facade backed by SQLite.
#[napi]
pub struct NodeAuthService {
    inner: Arc<SdkAuth>,
}

impl NodeAuthService {
    fn auth(&self) -> &AuthService {
        self.inner.compatibility_auth_service()
    }

    fn passkeys(&self) -> Result<&sdk_auth_core::PasskeyService> {
        self.inner.passkeys().ok_or_else(|| {
            Error::new(
                Status::GenericFailure,
                "MISCONFIGURED:WebAuthn is not configured for this service",
            )
        })
    }
}

#[napi]
impl NodeAuthService {
    /// Opens a migrated SQLite database using a host-provided versioned vault.
    #[napi(constructor)]
    pub fn new(options: NodeAuthOptions) -> Result<Self> {
        let store = Arc::new(SqliteAuthStore::open(options.sqlite_path).map_err(node_error)?);
        build_node_service(
            store,
            options.active_key_id,
            options.vault_keys,
            options.webauthn_realms,
            None,
        )
    }

    /// Connects asynchronously to an explicitly migrated PostgreSQL database.
    #[napi(factory)]
    pub async fn connect_postgres(options: NodePostgresAuthOptions) -> Result<Self> {
        let mut postgres_config = PostgresConfig::new(SecretString::new(options.database_url));
        postgres_config.allow_insecure_localhost =
            options.allow_insecure_localhost.unwrap_or(false);
        let store = Arc::new(
            PostgresAuthStore::connect(postgres_config)
                .await
                .map_err(node_error)?,
        );
        let rate_limit_store = if let Some(redis) = options.redis_rate_limit {
            let mut config = RedisRateLimitConfig::new(
                SecretString::new(redis.redis_url),
                SecretBytes::new(redis.privacy_key.to_vec()),
            );
            if let Some(namespace) = redis.namespace {
                config.namespace = namespace;
            }
            config.allow_insecure_localhost = redis.allow_insecure_localhost.unwrap_or(false);
            Some(Arc::new(
                RedisRateLimitStore::connect(config)
                    .await
                    .map_err(node_error)?,
            ) as Arc<dyn RateLimitStore>)
        } else {
            None
        };
        build_node_service(
            store,
            options.active_key_id,
            options.vault_keys,
            options.webauthn_realms,
            rate_limit_store,
        )
    }

    /// Registers an account and returns a delivery-only verification token.
    #[napi]
    pub async fn register(
        &self,
        realm_id: String,
        email: String,
        password: String,
    ) -> Result<NodeRegistration> {
        let result = self
            .auth()
            .register(RegisterRequest {
                realm_id: parse_realm(&realm_id)?,
                email,
                password: SecretString::new(password),
            })
            .await
            .map_err(node_error)?;
        Ok(NodeRegistration {
            user_id: result.user.id.to_string(),
            email: result.user.email.as_str().to_owned(),
            verification_token: result.verification.token.expose_secret().to_owned(),
            verification_expires_at: result.verification.expires_at.to_rfc3339(),
        })
    }

    /// Consumes an email verification token.
    #[napi]
    pub async fn verify_email(&self, realm_id: String, token: String) -> Result<()> {
        self.auth()
            .verify_email(parse_realm(&realm_id)?, &SecretString::new(token))
            .await
            .map_err(node_error)
    }

    /// Verifies password and either authenticates or requests a second factor.
    #[napi(
        ts_return_type = "Promise<{ kind: 'authenticated'; authentication: NodeAuthentication; challengeToken?: never; methods: []; challengeExpiresAt?: never } | { kind: 'second_factor_required'; authentication?: never; challengeToken: string; methods: Array<'totp' | 'recovery_code'>; challengeExpiresAt: string }>"
    )]
    pub async fn login(
        &self,
        realm_id: String,
        email: String,
        password: String,
        remember_me: bool,
        device: Option<NodeDeviceContext>,
        trusted_device_token: Option<String>,
    ) -> Result<NodeLoginOutcome> {
        let result = self
            .auth()
            .login(LoginRequest {
                realm_id: parse_realm(&realm_id)?,
                email,
                password: SecretString::new(password),
                remember_me,
                device: device.map_or_else(DeviceContext::default, node_device),
                trusted_device_token: trusted_device_token.map(SecretString::new),
            })
            .await
            .map_err(node_error)?;
        login_result(result)
    }

    /// Completes a pending login with TOTP or a recovery code.
    #[napi]
    pub async fn complete_login(
        &self,
        realm_id: String,
        challenge_token: String,
        proof_kind: String,
        proof: String,
        trust_device: bool,
    ) -> Result<NodeAuthentication> {
        self.auth()
            .complete_login(CompleteLoginRequest {
                realm_id: parse_realm(&realm_id)?,
                challenge_token: SecretString::new(challenge_token),
                proof: parse_proof(&proof_kind, proof)?,
                trust_device,
            })
            .await
            .map(authentication_result)
            .map_err(node_error)
    }

    /// Starts passkey registration after fresh authenticator-management proof.
    #[napi]
    pub async fn begin_passkey_registration(
        &self,
        realm_id: String,
        access_token: String,
        label: String,
        management: NodeAuthenticatorManagementProof,
    ) -> Result<NodePasskeyChallenge> {
        let result = self
            .passkeys()?
            .begin_registration(BeginPasskeyRegistrationRequest {
                realm_id: parse_realm(&realm_id)?,
                access_token: SecretString::new(access_token),
                label,
                proof: parse_authenticator_management(management)?,
            })
            .await
            .map_err(node_error)?;
        Ok(NodePasskeyChallenge {
            ceremony_token: result.ceremony_token.expose_secret().to_owned(),
            public_options_json: result.creation_options_json,
            expires_at: result.expires_at.to_rfc3339(),
        })
    }

    /// Completes passkey registration with browser response JSON.
    #[napi]
    pub async fn finish_passkey_registration(
        &self,
        realm_id: String,
        access_token: String,
        ceremony_token: String,
        response_json: String,
    ) -> Result<NodePasskey> {
        self.passkeys()?
            .finish_registration(FinishPasskeyRegistrationRequest {
                realm_id: parse_realm(&realm_id)?,
                access_token: SecretString::new(access_token),
                ceremony_token: SecretString::new(ceremony_token),
                response_json,
            })
            .await
            .map(passkey_result)
            .map_err(node_error)
    }

    /// Starts username-first, UV-required passkey authentication.
    #[napi]
    pub async fn begin_passkey_login(
        &self,
        realm_id: String,
        email: String,
        remember_me: bool,
        device: Option<NodeDeviceContext>,
    ) -> Result<NodePasskeyChallenge> {
        let result = self
            .passkeys()?
            .begin_login(BeginPasskeyLoginRequest {
                realm_id: parse_realm(&realm_id)?,
                email,
                remember_me,
                device: device.map_or_else(DeviceContext::default, node_device),
            })
            .await
            .map_err(node_error)?;
        Ok(NodePasskeyChallenge {
            ceremony_token: result.ceremony_token.expose_secret().to_owned(),
            public_options_json: result.request_options_json,
            expires_at: result.expires_at.to_rfc3339(),
        })
    }

    /// Completes passkey authentication and returns opaque SDK tokens.
    #[napi]
    pub async fn finish_passkey_login(
        &self,
        realm_id: String,
        ceremony_token: String,
        response_json: String,
    ) -> Result<NodeAuthentication> {
        self.passkeys()?
            .finish_login(FinishPasskeyLoginRequest {
                realm_id: parse_realm(&realm_id)?,
                ceremony_token: SecretString::new(ceremony_token),
                response_json,
            })
            .await
            .map(authentication_result)
            .map_err(node_error)
    }

    /// Lists passkeys owned by the authenticated account.
    #[napi]
    pub async fn list_passkeys(
        &self,
        realm_id: String,
        access_token: String,
    ) -> Result<Vec<NodePasskey>> {
        let access_token = SecretString::new(access_token);
        self.passkeys()?
            .list(parse_realm(&realm_id)?, &access_token)
            .await
            .map(|values| values.into_iter().map(passkey_result).collect())
            .map_err(node_error)
    }

    /// Changes the user-visible label of an active passkey.
    #[napi]
    pub async fn rename_passkey(
        &self,
        realm_id: String,
        access_token: String,
        passkey_id: String,
        label: String,
    ) -> Result<bool> {
        self.passkeys()?
            .rename(RenamePasskeyRequest {
                realm_id: parse_realm(&realm_id)?,
                access_token: SecretString::new(access_token),
                passkey_id: PasskeyId::parse(&passkey_id).map_err(node_error)?,
                label,
            })
            .await
            .map_err(node_error)
    }

    /// Revokes one passkey after fresh authenticator-management proof.
    #[napi]
    pub async fn revoke_passkey(
        &self,
        realm_id: String,
        access_token: String,
        passkey_id: String,
        management: NodeAuthenticatorManagementProof,
    ) -> Result<bool> {
        self.passkeys()?
            .revoke(RevokePasskeyRequest {
                realm_id: parse_realm(&realm_id)?,
                access_token: SecretString::new(access_token),
                passkey_id: PasskeyId::parse(&passkey_id).map_err(node_error)?,
                proof: parse_authenticator_management(management)?,
            })
            .await
            .map_err(node_error)
    }

    /// Starts TOTP enrollment after password reauthentication.
    #[napi]
    pub async fn begin_totp_enrollment(
        &self,
        realm_id: String,
        access_token: String,
        password: String,
        issuer: String,
    ) -> Result<NodeTotpEnrollment> {
        self.auth()
            .begin_totp_enrollment(BeginTotpEnrollmentRequest {
                realm_id: parse_realm(&realm_id)?,
                access_token: SecretString::new(access_token),
                password: SecretString::new(password),
                issuer,
            })
            .await
            .map(enrollment_result)
            .map_err(node_error)
    }

    /// Starts replacement after password and current-factor verification.
    #[napi]
    pub async fn begin_totp_replacement(
        &self,
        realm_id: String,
        access_token: String,
        password: String,
        proof_kind: String,
        second_factor: String,
        issuer: String,
    ) -> Result<NodeTotpEnrollment> {
        self.auth()
            .begin_totp_replacement(BeginTotpReplacementRequest {
                realm_id: parse_realm(&realm_id)?,
                access_token: SecretString::new(access_token),
                proof: MfaManagementProof {
                    password: SecretString::new(password),
                    second_factor: parse_proof(&proof_kind, second_factor)?,
                },
                issuer,
            })
            .await
            .map(enrollment_result)
            .map_err(node_error)
    }

    /// Confirms and activates a pending TOTP factor.
    #[napi]
    pub async fn confirm_totp_enrollment(
        &self,
        realm_id: String,
        access_token: String,
        enrollment_id: String,
        code: String,
        trust_current_device: bool,
    ) -> Result<NodeTotpActivation> {
        self.auth()
            .confirm_totp_enrollment(ConfirmTotpEnrollmentRequest {
                realm_id: parse_realm(&realm_id)?,
                access_token: SecretString::new(access_token),
                enrollment_id: MfaEnrollmentId::parse(&enrollment_id).map_err(node_error)?,
                code: SecretString::new(code),
                trust_current_device,
            })
            .await
            .map(activation_result)
            .map_err(node_error)
    }

    /// Replaces all unused recovery codes after strong reauthentication.
    #[napi]
    pub async fn regenerate_recovery_codes(
        &self,
        realm_id: String,
        access_token: String,
        password: String,
        proof_kind: String,
        second_factor: String,
    ) -> Result<Vec<String>> {
        self.auth()
            .regenerate_recovery_codes(manage_request(
                realm_id,
                access_token,
                password,
                proof_kind,
                second_factor,
            )?)
            .await
            .map(|codes| {
                codes
                    .into_iter()
                    .map(|code| code.expose_secret().to_owned())
                    .collect()
            })
            .map_err(node_error)
    }

    /// Disables MFA and revokes all sessions and trusted-device grants.
    #[napi]
    pub async fn disable_mfa(
        &self,
        realm_id: String,
        access_token: String,
        password: String,
        proof_kind: String,
        second_factor: String,
    ) -> Result<()> {
        self.auth()
            .disable_mfa(manage_request(
                realm_id,
                access_token,
                password,
                proof_kind,
                second_factor,
            )?)
            .await
            .map_err(node_error)
    }

    /// Lists trusted-device grants for the authenticated account.
    #[napi]
    pub async fn list_trusted_devices(
        &self,
        realm_id: String,
        access_token: String,
    ) -> Result<Vec<NodeTrustedDevice>> {
        self.auth()
            .list_trusted_devices(parse_realm(&realm_id)?, &SecretString::new(access_token))
            .await
            .map(|devices| devices.into_iter().map(trusted_device_result).collect())
            .map_err(node_error)
    }

    /// Revokes one trusted-device grant owned by the authenticated account.
    #[napi]
    pub async fn revoke_trusted_device(
        &self,
        realm_id: String,
        access_token: String,
        trusted_device_id: String,
    ) -> Result<bool> {
        self.auth()
            .revoke_trusted_device(RevokeTrustedDeviceRequest {
                realm_id: parse_realm(&realm_id)?,
                access_token: SecretString::new(access_token),
                trusted_device_id: TrustedDeviceId::parse(&trusted_device_id)
                    .map_err(node_error)?,
            })
            .await
            .map_err(node_error)
    }

    /// Re-encrypts a bounded batch of TOTP factors with the active vault key.
    #[napi]
    pub async fn rewrap_mfa_secrets(&self, realm_id: String, limit: u32) -> Result<u32> {
        self.auth()
            .rewrap_mfa_secrets(parse_realm(&realm_id)?, limit)
            .await
            .map_err(node_error)
    }

    /// Rotates a refresh token.
    #[napi]
    pub async fn refresh(
        &self,
        realm_id: String,
        refresh_token: String,
    ) -> Result<NodeAuthentication> {
        self.auth()
            .refresh(RefreshRequest {
                realm_id: parse_realm(&realm_id)?,
                refresh_token: SecretString::new(refresh_token),
            })
            .await
            .map(authentication_result)
            .map_err(node_error)
    }

    /// Validates an access token and returns its user identifier.
    #[napi]
    pub async fn validate_access(&self, realm_id: String, access_token: String) -> Result<String> {
        self.auth()
            .validate_access(parse_realm(&realm_id)?, &SecretString::new(access_token))
            .await
            .map(|validated| validated.user.id.to_string())
            .map_err(node_error)
    }

    /// Revokes the session associated with an access token.
    #[napi]
    pub async fn logout(&self, realm_id: String, access_token: String) -> Result<()> {
        self.auth()
            .logout(parse_realm(&realm_id)?, &SecretString::new(access_token))
            .await
            .map_err(node_error)
    }

    /// Creates a reset challenge for a trusted email delivery layer.
    #[napi]
    pub async fn request_password_reset(
        &self,
        realm_id: String,
        email: String,
    ) -> Result<Option<NodeChallenge>> {
        self.auth()
            .request_password_reset(parse_realm(&realm_id)?, email)
            .await
            .map(|challenge| {
                challenge.map(|value| NodeChallenge {
                    token: value.token.expose_secret().to_owned(),
                    expires_at: value.expires_at.to_rfc3339(),
                })
            })
            .map_err(node_error)
    }

    /// Replaces a password and revokes sessions and trusted-device grants.
    #[napi]
    pub async fn reset_password(
        &self,
        realm_id: String,
        reset_token: String,
        new_password: String,
    ) -> Result<()> {
        self.auth()
            .reset_password(ResetPasswordRequest {
                realm_id: parse_realm(&realm_id)?,
                reset_token: SecretString::new(reset_token),
                new_password: SecretString::new(new_password),
            })
            .await
            .map_err(node_error)
    }

    /// Performs one-time IAM bootstrap with fresh password and MFA proof.
    #[napi]
    pub async fn bootstrap_iam(&self, admin: NodeIamAdminProof) -> Result<()> {
        self.inner
            .iam()
            .bootstrap_realm(admin_proof(admin)?)
            .await
            .map_err(node_error)
    }

    /// Registers a canonical permission in the realm catalog.
    #[napi]
    pub async fn register_permission(
        &self,
        admin: NodeIamAdminProof,
        key: String,
        description: String,
    ) -> Result<NodePermission> {
        self.inner
            .iam()
            .register_permission(
                admin_proof(admin)?,
                PermissionKey::parse(key).map_err(node_error)?,
                description,
            )
            .await
            .map(permission_result)
            .map_err(node_error)
    }

    /// Lists the registered permission catalog after administrative step-up.
    #[napi]
    pub async fn list_permissions(&self, admin: NodeIamAdminProof) -> Result<Vec<NodePermission>> {
        self.inner
            .iam()
            .list_permissions(admin_proof(admin)?)
            .await
            .map(|values| values.into_iter().map(permission_result).collect())
            .map_err(node_error)
    }

    /// Enables or disables a catalog permission.
    #[napi]
    pub async fn set_permission_enabled(
        &self,
        admin: NodeIamAdminProof,
        permission_id: String,
        enabled: bool,
    ) -> Result<bool> {
        self.inner
            .iam()
            .set_permission_enabled(
                admin_proof(admin)?,
                PermissionId::parse(&permission_id).map_err(node_error)?,
                enabled,
            )
            .await
            .map_err(node_error)
    }

    /// Creates a non-hierarchical role.
    #[napi]
    pub async fn create_role(
        &self,
        admin: NodeIamAdminProof,
        key: String,
        name: String,
        description: String,
    ) -> Result<NodeRole> {
        self.inner
            .iam()
            .create_role(
                admin_proof(admin)?,
                RoleKey::parse(key).map_err(node_error)?,
                name,
                description,
            )
            .await
            .map(role_result)
            .map_err(node_error)
    }

    /// Lists roles after administrative step-up.
    #[napi]
    pub async fn list_roles(&self, admin: NodeIamAdminProof) -> Result<Vec<NodeRole>> {
        self.inner
            .iam()
            .list_roles(admin_proof(admin)?)
            .await
            .map(|values| values.into_iter().map(role_result).collect())
            .map_err(node_error)
    }

    /// Enables or disables a non-reserved role.
    #[napi]
    pub async fn set_role_enabled(
        &self,
        admin: NodeIamAdminProof,
        role_id: String,
        enabled: bool,
    ) -> Result<bool> {
        self.inner
            .iam()
            .set_role_enabled(
                admin_proof(admin)?,
                RoleId::parse(&role_id).map_err(node_error)?,
                enabled,
            )
            .await
            .map_err(node_error)
    }

    /// Grants or revokes a permission on a role.
    #[napi]
    pub async fn set_role_permission(
        &self,
        admin: NodeIamAdminProof,
        role_id: String,
        permission_id: String,
        granted: bool,
    ) -> Result<bool> {
        self.inner
            .iam()
            .set_role_permission(
                admin_proof(admin)?,
                RoleId::parse(&role_id).map_err(node_error)?,
                PermissionId::parse(&permission_id).map_err(node_error)?,
                granted,
            )
            .await
            .map_err(node_error)
    }

    /// Grants or revokes a role on a user or service account.
    #[napi]
    pub async fn set_principal_role(
        &self,
        admin: NodeIamAdminProof,
        principal_kind: String,
        principal_id: String,
        role_id: String,
        granted: bool,
    ) -> Result<bool> {
        self.inner
            .iam()
            .set_principal_role(
                admin_proof(admin)?,
                parse_principal(&principal_kind, &principal_id)?,
                RoleId::parse(&role_id).map_err(node_error)?,
                granted,
            )
            .await
            .map_err(node_error)
    }

    /// Creates a non-human service principal.
    #[napi]
    pub async fn create_service_account(
        &self,
        admin: NodeIamAdminProof,
        name: String,
        description: String,
    ) -> Result<NodeServiceAccount> {
        self.inner
            .iam()
            .create_service_account(admin_proof(admin)?, name, description)
            .await
            .map(service_account_result)
            .map_err(node_error)
    }

    /// Lists service accounts after administrative step-up.
    #[napi]
    pub async fn list_service_accounts(
        &self,
        admin: NodeIamAdminProof,
    ) -> Result<Vec<NodeServiceAccount>> {
        self.inner
            .iam()
            .list_service_accounts(admin_proof(admin)?)
            .await
            .map(|values| values.into_iter().map(service_account_result).collect())
            .map_err(node_error)
    }

    /// Enables or disables a service account and all of its keys.
    #[napi]
    pub async fn set_service_account_enabled(
        &self,
        admin: NodeIamAdminProof,
        service_account_id: String,
        enabled: bool,
    ) -> Result<bool> {
        self.inner
            .iam()
            .set_service_account_enabled(
                admin_proof(admin)?,
                ServiceAccountId::parse(&service_account_id).map_err(node_error)?,
                enabled,
            )
            .await
            .map_err(node_error)
    }

    /// Creates a restricted API key and returns its bearer credential once.
    #[napi]
    pub async fn create_api_key(
        &self,
        admin: NodeIamAdminProof,
        principal_kind: String,
        principal_id: String,
        name: String,
        scopes: Vec<String>,
        ttl_days: Option<u32>,
    ) -> Result<NodeApiKeyGrant> {
        let scopes = scopes
            .into_iter()
            .map(PermissionKey::parse)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(node_error)?;
        self.inner
            .iam()
            .create_api_key(
                admin_proof(admin)?,
                parse_principal(&principal_kind, &principal_id)?,
                name,
                scopes,
                ttl_days.map(|days| Duration::days(i64::from(days))),
            )
            .await
            .map(api_key_grant_result)
            .map_err(node_error)
    }

    /// Lists API-key metadata without bearer material after administrative step-up.
    #[napi]
    pub async fn list_api_keys(
        &self,
        admin: NodeIamAdminProof,
        principal_kind: String,
        principal_id: String,
    ) -> Result<Vec<NodeApiKey>> {
        self.inner
            .iam()
            .list_api_keys(
                admin_proof(admin)?,
                parse_principal(&principal_kind, &principal_id)?,
            )
            .await
            .map(|values| values.into_iter().map(api_key_result).collect())
            .map_err(node_error)
    }

    /// Rotates an API key with bounded predecessor overlap.
    #[napi]
    pub async fn rotate_api_key(
        &self,
        admin: NodeIamAdminProof,
        api_key_id: String,
        grace_seconds: u32,
        ttl_days: Option<u32>,
    ) -> Result<NodeApiKeyGrant> {
        self.inner
            .iam()
            .rotate_api_key(
                admin_proof(admin)?,
                ApiKeyId::parse(&api_key_id).map_err(node_error)?,
                Duration::seconds(i64::from(grace_seconds)),
                ttl_days.map(|days| Duration::days(i64::from(days))),
            )
            .await
            .map(api_key_grant_result)
            .map_err(node_error)
    }

    /// Revokes an API key idempotently.
    #[napi]
    pub async fn revoke_api_key(
        &self,
        admin: NodeIamAdminProof,
        api_key_id: String,
    ) -> Result<bool> {
        self.inner
            .iam()
            .revoke_api_key(
                admin_proof(admin)?,
                ApiKeyId::parse(&api_key_id).map_err(node_error)?,
            )
            .await
            .map_err(node_error)
    }

    /// Authenticates a user token or API key and checks one exact permission.
    #[napi]
    pub async fn authorize(
        &self,
        realm_id: String,
        credential_kind: String,
        credential: String,
        permission: String,
    ) -> Result<NodeAuthorizationGrant> {
        let credential = match credential_kind.as_str() {
            "user_access_token" => {
                AuthorizationCredential::UserAccessToken(SecretString::new(credential))
            }
            "api_key" => AuthorizationCredential::ApiKey(SecretString::new(credential)),
            _ => return Err(invalid_input()),
        };
        self.inner
            .authorization()
            .authorize(AuthorizeRequest::new(
                parse_realm(&realm_id)?,
                credential,
                PermissionKey::parse(permission).map_err(node_error)?,
            ))
            .await
            .map(|grant| {
                let (principal_kind, principal_id) = principal_result(grant.principal());
                NodeAuthorizationGrant {
                    principal_kind,
                    principal_id,
                    permission: grant.permission().as_str().to_owned(),
                    credential_kind: match grant.credential_kind() {
                        CredentialKind::UserAccessToken => "user_access_token".to_owned(),
                        CredentialKind::ApiKey => "api_key".to_owned(),
                        _ => "unsupported".to_owned(),
                    },
                    api_key_id: grant.api_key_id().map(|id| id.to_string()),
                }
            })
            .map_err(node_error)
    }
}

fn build_node_service<T>(
    store: Arc<T>,
    active_key_id: String,
    vault_keys: Vec<NodeVaultKey>,
    webauthn_realms: Option<Vec<NodeWebAuthnRealmOptions>>,
    rate_limit_store: Option<Arc<dyn RateLimitStore>>,
) -> Result<NodeAuthService>
where
    T: SdkStore + PasskeyStore + 'static,
{
    let password_engine = Argon2PasswordEngine::recommended().map_err(node_error)?;
    let mut keys = Vec::with_capacity(vault_keys.len());
    for key in vault_keys {
        keys.push(
            VaultKey::new(key.key_id, SecretBytes::new(key.material.to_vec()))
                .map_err(node_error)?,
        );
    }
    let vault = XChaCha20Vault::new(active_key_id, keys).map_err(node_error)?;
    let mut builder = SdkAuth::builder()
        .store(Arc::clone(&store))
        .password_engine(Arc::new(password_engine))
        .token_generator(Arc::new(OsTokenGenerator))
        .secret_vault(Arc::new(vault))
        .auth_config(AuthConfig::default());
    if let Some(rate_limit_store) = rate_limit_store {
        builder = builder.rate_limit_store(rate_limit_store);
    }
    if let Some(realms) = webauthn_realms {
        let mut configs = Vec::with_capacity(realms.len());
        for realm in realms {
            let origins = realm
                .origins
                .into_iter()
                .map(|origin| Url::parse(&origin).map_err(|_| invalid_input()))
                .collect::<Result<Vec<_>>>()?;
            configs.push(WebAuthnRealmConfig {
                realm_id: parse_realm(&realm.realm_id)?,
                rp_id: realm.rp_id,
                rp_name: realm.rp_name,
                origins,
            });
        }
        let engine = WebAuthnRegistry::new(configs).map_err(node_error)?;
        builder = builder
            .passkey_store(store)
            .webauthn_engine(Arc::new(engine));
    }
    let service = builder.build().map_err(node_error)?;
    Ok(NodeAuthService {
        inner: Arc::new(service),
    })
}

fn node_device(value: NodeDeviceContext) -> DeviceContext {
    DeviceContext {
        name: value.name,
        network_hash: value.network_hash,
        user_agent: value.user_agent,
    }
}

fn login_result(result: LoginOutcome) -> Result<NodeLoginOutcome> {
    #[allow(unreachable_patterns)]
    match result {
        LoginOutcome::Authenticated(authentication) => Ok(NodeLoginOutcome {
            kind: "authenticated".to_owned(),
            authentication: Some(authentication_result(*authentication)),
            challenge_token: None,
            methods: Vec::new(),
            challenge_expires_at: None,
        }),
        LoginOutcome::SecondFactorRequired(challenge) => {
            let methods = challenge
                .methods
                .into_iter()
                .map(method_name)
                .collect::<Result<Vec<_>>>()?;
            Ok(NodeLoginOutcome {
                kind: "second_factor_required".to_owned(),
                authentication: None,
                challenge_token: Some(challenge.token.expose_secret().to_owned()),
                methods,
                challenge_expires_at: Some(challenge.expires_at.to_rfc3339()),
            })
        }
        _ => Err(Error::new(
            Status::GenericFailure,
            "INTERNAL:unsupported login outcome",
        )),
    }
}

fn method_name(method: SecondFactorMethod) -> Result<String> {
    #[allow(unreachable_patterns)]
    match method {
        SecondFactorMethod::Totp => Ok("totp".to_owned()),
        SecondFactorMethod::RecoveryCode => Ok("recovery_code".to_owned()),
        _ => Err(Error::new(
            Status::GenericFailure,
            "INTERNAL:unsupported second-factor method",
        )),
    }
}

fn parse_proof(kind: &str, value: String) -> Result<SecondFactorProof> {
    match kind {
        "totp" => Ok(SecondFactorProof::Totp(SecretString::new(value))),
        "recovery_code" => Ok(SecondFactorProof::RecoveryCode(SecretString::new(value))),
        _ => Err(Error::new(
            Status::InvalidArg,
            "INVALID_INPUT:proofKind must be totp or recovery_code",
        )),
    }
}

fn parse_authenticator_management(
    value: NodeAuthenticatorManagementProof,
) -> Result<AuthenticatorManagementProof> {
    match value.kind.as_str() {
        "current_passkey_session" => {
            if value.password.is_some()
                || value.second_factor_kind.is_some()
                || value.second_factor.is_some()
            {
                return Err(invalid_input());
            }
            Ok(AuthenticatorManagementProof::CurrentPasskeySession)
        }
        "password" => {
            let password = value.password.ok_or_else(invalid_input)?;
            let second_factor = match (value.second_factor_kind, value.second_factor) {
                (None, None) => None,
                (Some(kind), Some(value)) => Some(parse_proof(&kind, value)?),
                _ => return Err(invalid_input()),
            };
            Ok(AuthenticatorManagementProof::Password {
                password: SecretString::new(password),
                second_factor,
            })
        }
        _ => Err(invalid_input()),
    }
}

fn manage_request(
    realm_id: String,
    access_token: String,
    password: String,
    proof_kind: String,
    second_factor: String,
) -> Result<ManageMfaRequest> {
    Ok(ManageMfaRequest {
        realm_id: parse_realm(&realm_id)?,
        access_token: SecretString::new(access_token),
        proof: MfaManagementProof {
            password: SecretString::new(password),
            second_factor: parse_proof(&proof_kind, second_factor)?,
        },
    })
}

fn admin_proof(value: NodeIamAdminProof) -> Result<IamAdminProof> {
    Ok(IamAdminProof::new(
        parse_realm(&value.realm_id)?,
        SecretString::new(value.access_token),
        MfaManagementProof {
            password: SecretString::new(value.password),
            second_factor: parse_proof(&value.proof_kind, value.second_factor)?,
        },
    ))
}

fn parse_principal(kind: &str, id: &str) -> Result<PrincipalId> {
    match kind {
        "user" => UserId::parse(id).map(PrincipalId::User).map_err(node_error),
        "service_account" => ServiceAccountId::parse(id)
            .map(PrincipalId::ServiceAccount)
            .map_err(node_error),
        _ => Err(invalid_input()),
    }
}

fn principal_result(principal: PrincipalId) -> (String, String) {
    match principal {
        PrincipalId::User(id) => ("user".to_owned(), id.to_string()),
        PrincipalId::ServiceAccount(id) => ("service_account".to_owned(), id.to_string()),
        _ => ("unsupported".to_owned(), String::new()),
    }
}

fn permission_result(value: PermissionDefinition) -> NodePermission {
    NodePermission {
        id: value.id().to_string(),
        key: value.key().as_str().to_owned(),
        description: value.description().to_owned(),
        enabled: value.enabled(),
    }
}

fn role_result(value: Role) -> NodeRole {
    NodeRole {
        id: value.id().to_string(),
        key: value.key().as_str().to_owned(),
        name: value.name().to_owned(),
        description: value.description().to_owned(),
        reserved: value.reserved(),
        enabled: value.enabled(),
    }
}

fn service_account_result(value: ServiceAccount) -> NodeServiceAccount {
    NodeServiceAccount {
        id: value.id().to_string(),
        name: value.name().to_owned(),
        description: value.description().to_owned(),
        enabled: value.enabled(),
    }
}

fn api_key_result(value: ApiKey) -> NodeApiKey {
    let (principal_kind, principal_id) = principal_result(value.principal());
    NodeApiKey {
        id: value.id().to_string(),
        principal_kind,
        principal_id,
        name: value.name().to_owned(),
        scopes: value
            .scopes()
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
        expires_at: value.expires_at().to_rfc3339(),
        grace_expires_at: value.grace_expires_at().map(|time| time.to_rfc3339()),
        revoked_at: value.revoked_at().map(|time| time.to_rfc3339()),
    }
}

fn api_key_grant_result(value: sdk_auth_core::ApiKeyGrant) -> NodeApiKeyGrant {
    NodeApiKeyGrant {
        key: api_key_result(value.key),
        credential: value.credential.expose_secret().to_owned(),
    }
}

fn invalid_input() -> Error {
    Error::new(Status::InvalidArg, "INVALID_INPUT:invalid input")
}

fn authentication_result(result: sdk_auth_core::Authentication) -> NodeAuthentication {
    let (trusted_device_id, trusted_device_token, trusted_device_expires_at) = result
        .trusted_device_grant
        .map_or((None, None, None), |grant| {
            (
                Some(grant.device.id.to_string()),
                Some(grant.token.expose_secret().to_owned()),
                Some(grant.device.expires_at.to_rfc3339()),
            )
        });
    NodeAuthentication {
        user_id: result.user.id.to_string(),
        session_id: result.session.id.to_string(),
        access_token: result.tokens.access_token.expose_secret().to_owned(),
        refresh_token: result.tokens.refresh_token.expose_secret().to_owned(),
        access_expires_at: result.tokens.access_expires_at.to_rfc3339(),
        session_expires_at: result.tokens.session_expires_at.to_rfc3339(),
        trusted_device_id,
        trusted_device_token,
        trusted_device_expires_at,
    }
}

fn enrollment_result(result: sdk_auth_core::TotpEnrollment) -> NodeTotpEnrollment {
    NodeTotpEnrollment {
        enrollment_id: result.id.to_string(),
        base32_secret: result.base32_secret.expose_secret().to_owned(),
        provisioning_uri: result.provisioning_uri.expose_secret().to_owned(),
        expires_at: result.expires_at.to_rfc3339(),
    }
}

fn activation_result(result: sdk_auth_core::TotpActivation) -> NodeTotpActivation {
    let (trusted_device_id, trusted_device_token, trusted_device_expires_at) = result
        .trusted_device_grant
        .map_or((None, None, None), |grant| {
            (
                Some(grant.device.id.to_string()),
                Some(grant.token.expose_secret().to_owned()),
                Some(grant.device.expires_at.to_rfc3339()),
            )
        });
    NodeTotpActivation {
        recovery_codes: result
            .recovery_codes
            .into_iter()
            .map(|code| code.expose_secret().to_owned())
            .collect(),
        trusted_device_id,
        trusted_device_token,
        trusted_device_expires_at,
    }
}

fn trusted_device_result(device: TrustedDevice) -> NodeTrustedDevice {
    NodeTrustedDevice {
        id: device.id.to_string(),
        name: device.device.name,
        created_at: device.created_at.to_rfc3339(),
        last_used_at: device.last_used_at.to_rfc3339(),
        expires_at: device.expires_at.to_rfc3339(),
        revoked_at: device.revoked_at.map(|value| value.to_rfc3339()),
    }
}

fn passkey_result(passkey: Passkey) -> NodePasskey {
    NodePasskey {
        id: passkey.id.to_string(),
        label: passkey.label,
        backup_eligible: passkey.backup_eligible,
        backed_up: passkey.backed_up,
        created_at: passkey.created_at.to_rfc3339(),
        last_used_at: passkey.last_used_at.map(|value| value.to_rfc3339()),
        revoked_at: passkey.revoked_at.map(|value| value.to_rfc3339()),
    }
}

fn parse_realm(value: &str) -> Result<RealmId> {
    RealmId::parse(value).map_err(node_error)
}

fn node_error(error: AuthError) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("{}:{}", error.code().as_str(), error.message()),
    )
}
