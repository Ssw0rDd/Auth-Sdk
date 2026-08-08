//! Top-level composition root for authentication, MFA, IAM and authorization.

use std::sync::Arc;

use sdk_auth_crypto::{
    CryptoProvider, CryptoProviderMetadata, PasswordEngine, SecretVault, TokenGenerator,
};
use sdk_auth_error::{AuthError, ErrorCode};

use crate::{
    AuditService, AuditStore, AuthConfig, AuthService, AuthStore, AuthenticationService,
    AuthenticatorService, AuthorizationConfig, AuthorizationService, Clock, IamService, IamStore,
    IdentityService, LeasedEventStore, OutboxService, PasskeyService, PasskeyStore, RateLimitStore,
    RecoveryService, SessionService, SystemClock, UnitOfWorkCapabilities, UnitOfWorkStore,
    WebAuthnEngine,
};

/// Composite adapter implemented by production and test storage crates.
pub trait SdkStore: AuthStore + IamStore + AuditStore + LeasedEventStore + UnitOfWorkStore {}

impl<T> SdkStore for T where
    T: AuthStore + IamStore + AuditStore + LeasedEventStore + UnitOfWorkStore
{
}

/// Composed SDK façade with explicit control-plane and data-plane services.
pub struct SdkAuth {
    legacy_authentication: Arc<AuthService>,
    identity: IdentityService,
    authentication: AuthenticationService,
    authenticators: AuthenticatorService,
    sessions: SessionService,
    recovery: RecoveryService,
    audit: AuditService,
    outbox: OutboxService,
    crypto_metadata: CryptoProviderMetadata,
    iam: IamService,
    authorization: AuthorizationService,
    passkeys: Option<PasskeyService>,
}

impl SdkAuth {
    /// Starts a validated composition builder.
    #[must_use]
    pub fn builder() -> SdkAuthBuilder {
        SdkAuthBuilder::default()
    }

    /// Login, refresh and access-validation service.
    #[must_use]
    pub const fn authentication(&self) -> &AuthenticationService {
        &self.authentication
    }

    /// MFA service. Kept as a distinct façade entry while legacy methods remain on `AuthService`.
    #[must_use]
    pub const fn mfa(&self) -> &AuthenticatorService {
        &self.authenticators
    }

    /// Identity registration and email-ownership service.
    #[must_use]
    pub const fn identity(&self) -> &IdentityService {
        &self.identity
    }

    /// MFA and trusted-device lifecycle service.
    #[must_use]
    pub const fn authenticators(&self) -> &AuthenticatorService {
        &self.authenticators
    }

    /// Session listing and revocation service.
    #[must_use]
    pub const fn sessions(&self) -> &SessionService {
        &self.sessions
    }

    /// Account-recovery service.
    #[must_use]
    pub const fn recovery(&self) -> &RecoveryService {
        &self.recovery
    }

    /// Durable audit and outbox service.
    #[must_use]
    pub const fn audit(&self) -> &AuditService {
        &self.audit
    }

    /// Trusted-host integration-event delivery service.
    #[must_use]
    pub const fn outbox(&self) -> &OutboxService {
        &self.outbox
    }

    /// Temporary compatibility surface for pre-0.4 bindings.
    ///
    /// New integrations must use capability-oriented facades. This method is
    /// scheduled for removal before the 1.0 API freeze.
    #[doc(hidden)]
    #[must_use]
    pub fn compatibility_auth_service(&self) -> &AuthService {
        &self.legacy_authentication
    }

    /// Cryptographic provider metadata captured at composition time.
    #[must_use]
    pub const fn crypto_provider_metadata(&self) -> CryptoProviderMetadata {
        self.crypto_metadata
    }

    /// IAM control-plane service.
    #[must_use]
    pub const fn iam(&self) -> &IamService {
        &self.iam
    }

    /// Credential-bound authorization data plane.
    #[must_use]
    pub const fn authorization(&self) -> &AuthorizationService {
        &self.authorization
    }

    /// WebAuthn/passkey capability when a provider and store were composed.
    #[must_use]
    pub const fn passkeys(&self) -> Option<&PasskeyService> {
        self.passkeys.as_ref()
    }
}

/// Builder for [`SdkAuth`].
#[derive(Default)]
pub struct SdkAuthBuilder {
    auth_store: Option<Arc<dyn AuthStore>>,
    iam_store: Option<Arc<dyn IamStore>>,
    audit_store: Option<Arc<dyn AuditStore>>,
    rate_limit_store: Option<Arc<dyn RateLimitStore>>,
    leased_event_store: Option<Arc<dyn LeasedEventStore>>,
    unit_of_work_capabilities: Option<UnitOfWorkCapabilities>,
    crypto_provider: Option<Arc<dyn CryptoProvider>>,
    password_engine: Option<Arc<dyn PasswordEngine>>,
    token_generator: Option<Arc<dyn TokenGenerator>>,
    secret_vault: Option<Arc<dyn SecretVault>>,
    clock: Option<Arc<dyn Clock>>,
    auth_config: Option<AuthConfig>,
    authorization_config: Option<AuthorizationConfig>,
    passkey_store: Option<Arc<dyn PasskeyStore>>,
    webauthn_engine: Option<Arc<dyn WebAuthnEngine>>,
}

impl SdkAuthBuilder {
    /// Supplies one adapter implementing both authentication and IAM ports.
    #[must_use]
    pub fn store<T>(mut self, store: Arc<T>) -> Self
    where
        T: SdkStore + 'static,
    {
        self.unit_of_work_capabilities = Some(store.unit_of_work_capabilities());
        self.auth_store = Some(store.clone());
        self.iam_store = Some(store.clone());
        self.audit_store = Some(store.clone());
        if self.rate_limit_store.is_none() {
            self.rate_limit_store = Some(store.clone());
        }
        self.leased_event_store = Some(store);
        self
    }

    /// Overrides authentication throttling with a dedicated adapter.
    #[must_use]
    pub fn rate_limit_store(mut self, store: Arc<dyn RateLimitStore>) -> Self {
        self.rate_limit_store = Some(store);
        self
    }

    /// Supplies one versioned provider for every cryptographic capability.
    ///
    /// A provider cannot be combined with the legacy per-capability builder
    /// methods because ambiguous precedence would make security configuration
    /// difficult to audit.
    #[must_use]
    pub fn crypto_provider(mut self, value: Arc<dyn CryptoProvider>) -> Self {
        self.crypto_provider = Some(value);
        self
    }

    /// Supplies the password hashing engine.
    #[must_use]
    pub fn password_engine(mut self, value: Arc<dyn PasswordEngine>) -> Self {
        self.password_engine = Some(value);
        self
    }

    /// Supplies the cryptographically secure token generator.
    #[must_use]
    pub fn token_generator(mut self, value: Arc<dyn TokenGenerator>) -> Self {
        self.token_generator = Some(value);
        self
    }

    /// Supplies the versioned authenticated secret vault.
    #[must_use]
    pub fn secret_vault(mut self, value: Arc<dyn SecretVault>) -> Self {
        self.secret_vault = Some(value);
        self
    }

    /// Supplies a deterministic clock, primarily for tests.
    #[must_use]
    pub fn clock(mut self, value: Arc<dyn Clock>) -> Self {
        self.clock = Some(value);
        self
    }

    /// Supplies authentication policy.
    #[must_use]
    pub fn auth_config(mut self, value: AuthConfig) -> Self {
        self.auth_config = Some(value);
        self
    }

    /// Supplies IAM and API-key policy.
    #[must_use]
    pub fn authorization_config(mut self, value: AuthorizationConfig) -> Self {
        self.authorization_config = Some(value);
        self
    }

    /// Supplies the server-side passkey persistence adapter.
    #[must_use]
    pub fn passkey_store(mut self, value: Arc<dyn PasskeyStore>) -> Self {
        self.passkey_store = Some(value);
        self
    }

    /// Supplies the WebAuthn relying-party implementation.
    #[must_use]
    pub fn webauthn_engine(mut self, value: Arc<dyn WebAuthnEngine>) -> Self {
        self.webauthn_engine = Some(value);
        self
    }

    /// Validates all dependencies and constructs the composed SDK.
    pub fn build(self) -> Result<SdkAuth, AuthError> {
        let auth_store = self.auth_store.ok_or_else(misconfigured)?;
        let iam_store = self.iam_store.ok_or_else(misconfigured)?;
        let audit_store = self.audit_store.ok_or_else(misconfigured)?;
        let rate_limit_store = self.rate_limit_store.ok_or_else(misconfigured)?;
        let leased_event_store = self.leased_event_store.ok_or_else(misconfigured)?;
        if self.unit_of_work_capabilities != Some(UnitOfWorkCapabilities::REQUIRED) {
            return Err(AuthError::new(
                ErrorCode::Misconfigured,
                "storage adapter lacks required atomic journal guarantees",
                false,
            ));
        }
        let (password_engine, token_generator, secret_vault, crypto_metadata) =
            if let Some(provider) = self.crypto_provider {
                if self.password_engine.is_some()
                    || self.token_generator.is_some()
                    || self.secret_vault.is_some()
                {
                    return Err(AuthError::new(
                        ErrorCode::Misconfigured,
                        "crypto provider conflicts with individual crypto capabilities",
                        false,
                    ));
                }
                (
                    provider.password_engine(),
                    provider.token_generator(),
                    provider.secret_vault(),
                    provider.metadata(),
                )
            } else {
                (
                    self.password_engine.ok_or_else(misconfigured)?,
                    self.token_generator.ok_or_else(misconfigured)?,
                    self.secret_vault.ok_or_else(misconfigured)?,
                    CryptoProviderMetadata {
                        provider_id: "legacy-capabilities-v1",
                        sealed_secret_format: 1,
                        fips_validated: false,
                    },
                )
            };
        if crypto_metadata.sealed_secret_format != 1 {
            return Err(AuthError::new(
                ErrorCode::Misconfigured,
                "crypto provider emits an unsupported sealed-secret format",
                false,
            ));
        }
        let clock = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let auth_config = self.auth_config.unwrap_or_default();
        let legacy_authentication = Arc::new(
            AuthService::builder()
                .store(auth_store)
                .rate_limit_store(rate_limit_store)
                .password_engine(password_engine)
                .token_generator(Arc::clone(&token_generator))
                .secret_vault(secret_vault)
                .clock(Arc::clone(&clock))
                .config(auth_config.clone())
                .build()?,
        );
        let passkeys = match (self.passkey_store, self.webauthn_engine) {
            (Some(store), Some(engine)) => Some(PasskeyService::new(
                store,
                engine,
                Arc::clone(&legacy_authentication),
                Arc::clone(&token_generator),
                Arc::clone(&clock),
                auth_config,
            )?),
            (None, None) => None,
            _ => {
                return Err(AuthError::new(
                    ErrorCode::Misconfigured,
                    "passkey store and WebAuthn provider must be configured together",
                    false,
                ));
            }
        };
        let iam = IamService::new(
            Arc::clone(&iam_store),
            Arc::clone(&legacy_authentication),
            token_generator,
            Arc::clone(&clock),
            self.authorization_config.unwrap_or_default(),
        )?;
        let outbox = OutboxService::new(leased_event_store, Arc::clone(&clock));
        let authorization =
            AuthorizationService::new(iam_store, Arc::clone(&legacy_authentication), clock);
        Ok(SdkAuth {
            identity: IdentityService::new(Arc::clone(&legacy_authentication)),
            authentication: AuthenticationService::new(Arc::clone(&legacy_authentication)),
            authenticators: AuthenticatorService::new(Arc::clone(&legacy_authentication)),
            sessions: SessionService::new(Arc::clone(&legacy_authentication)),
            recovery: RecoveryService::new(Arc::clone(&legacy_authentication)),
            audit: AuditService::new(audit_store, iam.clone()),
            outbox,
            crypto_metadata,
            legacy_authentication,
            iam,
            authorization,
            passkeys,
        })
    }
}

fn misconfigured() -> AuthError {
    AuthError::new(
        ErrorCode::Misconfigured,
        "required SDK dependency is missing",
        false,
    )
}
