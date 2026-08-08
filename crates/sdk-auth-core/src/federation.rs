//! Provider-independent federated identity resolution and safe account linking.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sdk_auth_crypto::{TokenDigest, TokenGenerator, digest_token};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::{
    AuditRecord, AuthEvent, AuthEventKind, AuthenticationMethod, DeviceContext, EmailAddress,
    FederatedIdentityId, OpaqueToken, RealmId, SecretString, User, UserId,
};
use url::Url;

use crate::{
    AuthService, Authentication, AuthenticatorManagementProof, Clock, CreateSession, SystemClock,
    service::event,
};

/// Limits for short-lived account-link challenges.
#[derive(Debug, Clone, Copy)]
pub struct FederationConfig {
    /// Lifetime of a challenge that requires proof of an existing account.
    pub link_challenge_ttl: Duration,
    /// Whether a verified external email may create a user on first login.
    pub allow_registration: bool,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            link_challenge_ttl: Duration::minutes(10),
            allow_registration: true,
        }
    }
}

impl FederationConfig {
    fn validate(self) -> Result<Self, AuthError> {
        if self.link_challenge_ttl < Duration::minutes(1)
            || self.link_challenge_ttl > Duration::hours(1)
        {
            return Err(AuthError::new(
                ErrorCode::Misconfigured,
                "federation link challenge lifetime is invalid",
                false,
            ));
        }
        Ok(self)
    }
}

/// Claims whose signature, issuer, audience and nonce were checked by a trusted provider adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFederatedClaims {
    /// Stable SDK configuration key such as `google`, `github`, or `microsoft`.
    pub provider_id: String,
    /// Exact authority that issued the durable subject.
    pub issuer: String,
    /// Durable provider subject. Email and username must never be placed here.
    pub subject: String,
    /// Email attribute returned by the provider, when available.
    pub email: Option<String>,
    /// Whether the provider asserted ownership of the email attribute.
    pub email_verified: bool,
}

/// Provider-independent request after a provider adapter has verified its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginFederatedLoginRequest {
    /// Realm in which the provider is configured.
    pub realm_id: RealmId,
    /// Bounded device metadata for the resulting session.
    pub device: DeviceContext,
    /// Whether the resulting session uses the configured extended lifetime.
    pub remember_me: bool,
    /// Verified, untrusted-until-bounded provider claims.
    pub claims: VerifiedFederatedClaims,
}

/// Bounded identity material safe to compare and persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedIdentityKey {
    /// Exact provider authority.
    pub issuer: String,
    /// Durable subject within that authority.
    pub subject: String,
}

/// Persisted association between one external subject and one SDK user.
#[derive(Clone, PartialEq, Eq)]
pub struct FederatedIdentity {
    /// SDK identifier independent of provider identifiers.
    pub id: FederatedIdentityId,
    /// Realm that owns the association.
    pub realm_id: RealmId,
    /// Stable SDK user authenticated by the external identity.
    pub user_id: UserId,
    /// SDK provider configuration key.
    pub provider_id: String,
    /// Exact external authority.
    pub issuer: String,
    /// Durable external subject. This is never an email or username.
    pub subject: String,
    /// Provider-verified email observed when the link was created.
    pub verified_email: EmailAddress,
    /// Link creation time.
    pub created_at: DateTime<Utc>,
    /// Most recent provider authentication, when recorded.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Revocation time after unlinking, when applicable.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for FederatedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FederatedIdentity")
            .field("id", &self.id)
            .field("realm_id", &self.realm_id)
            .field("user_id", &self.user_id)
            .field("provider_id", &self.provider_id)
            .field("issuer", &self.issuer)
            .field("subject", &"[REDACTED]")
            .field("verified_email", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

/// Server-side state requiring proof of control of the target user.
#[derive(Debug, Clone)]
pub struct PendingFederatedLink {
    /// Realm owning the transition.
    pub realm_id: RealmId,
    /// Digest of the raw link bearer returned only to the trusted host.
    pub digest: TokenDigest,
    /// Existing user selected by a verified-email match.
    pub user_id: UserId,
    /// Identifier reserved for the eventual association.
    pub identity_id: FederatedIdentityId,
    /// SDK provider configuration key.
    pub provider_id: String,
    /// Durable external identity proposed for the link.
    pub identity: FederatedIdentityKey,
    /// Provider-verified email used only to locate the candidate user.
    pub verified_email: EmailAddress,
    /// Absolute challenge expiration.
    pub expires_at: DateTime<Utc>,
    /// Challenge creation time.
    pub created_at: DateTime<Utc>,
}

/// Atomic store result while resolving an unfamiliar provider subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederatedResolution {
    /// The durable issuer/subject pair is already linked to this user.
    KnownIdentity(UserId),
    /// A matching user exists and a link challenge was stored for it.
    LinkRequired(UserId),
    /// No safe existing-user match was available.
    RegistrationRequired,
}

/// Persistence seam for provider identities and link challenges.
#[async_trait]
pub trait FederationStore: Send + Sync {
    /// Resolves an active durable subject and records its latest successful use.
    async fn resolve_federated_user(
        &self,
        realm_id: RealmId,
        identity: FederatedIdentityKey,
        now: DateTime<Utc>,
    ) -> Result<Option<UserId>, AuthError>;

    /// Resolves a durable identity and atomically stores a link challenge when needed.
    async fn begin_federated_link(
        &self,
        pending: PendingFederatedLink,
    ) -> Result<FederatedResolution, AuthError>;

    /// Consumes an owned link challenge and creates the identity association atomically.
    async fn complete_federated_link(
        &self,
        command: CompleteFederatedLink,
    ) -> Result<FederatedLinkResolution, AuthError>;

    /// Atomically creates a passwordless user, identity, session, audit and event.
    async fn register_federated_user(
        &self,
        command: RegisterFederatedUser,
    ) -> Result<FederatedRegistrationResolution, AuthError>;
}

/// Atomic first-login command for a verified external identity.
#[derive(Debug, Clone)]
pub struct RegisterFederatedUser {
    /// New verified user without a local credential.
    pub user: User,
    /// Durable external identity bound to the new user.
    pub identity: FederatedIdentity,
    /// Initial provider-authenticated session and token digests.
    pub session: CreateSession,
    /// Registration notification committed to the durable outbox.
    pub event: AuthEvent,
}

/// Result of racing first-login registration against another login path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederatedRegistrationResolution {
    /// User, identity and session were committed together.
    Registered,
    /// Email or external subject appeared concurrently and must be resolved again.
    Retry,
}

/// Atomic command for a proof-authorized external identity link.
#[derive(Debug, Clone)]
pub struct CompleteFederatedLink {
    /// Realm owning both the user and challenge.
    pub realm_id: RealmId,
    /// Digest of the presented link bearer.
    pub digest: TokenDigest,
    /// Authenticated user that proved control.
    pub user_id: UserId,
    /// Current time used for TTL and persisted metadata.
    pub now: DateTime<Utc>,
    /// Security record committed with the identity link.
    pub audit: AuditRecord,
}

/// Store outcome for consuming an account-link challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederatedLinkResolution {
    /// The identity association was created.
    Linked(Box<FederatedIdentity>),
    /// The challenge is unknown or belongs to a different user.
    Invalid,
    /// The challenge expired before proof completed.
    Expired,
    /// The challenge was already consumed.
    Reused,
    /// The external subject was linked concurrently to another user.
    Conflict,
}

/// Raw single-use account-link dispatch retained by the trusted backend.
#[derive(Debug)]
pub struct FederatedLinkDispatch {
    /// Existing user that must prove control before linking.
    pub user_id: UserId,
    /// Bearer consumed only after authenticating as `user_id`.
    pub token: OpaqueToken,
    /// Absolute challenge expiration.
    pub expires_at: DateTime<Utc>,
}

/// Safe result of resolving verified provider claims.
#[derive(Debug)]
#[non_exhaustive]
pub enum FederatedLoginOutcome {
    /// A session was created for an existing or newly registered identity.
    Authenticated(Box<Authentication>),
    /// An existing email matched; explicit proof is required instead of auto-linking.
    LinkRequired(FederatedLinkDispatch),
    /// The caller must continue a new-user registration flow.
    RegistrationRequired,
}

/// Fresh authenticator proof required to link an external identity.
pub type FederatedLinkProof = AuthenticatorManagementProof;

/// Authenticated request to consume an account-link challenge.
#[derive(Debug)]
pub struct CompleteFederatedLinkRequest {
    /// Realm owning the challenge and current session.
    pub realm_id: RealmId,
    /// Active access bearer proving the target user.
    pub access_token: SecretString,
    /// Single-use account-link bearer.
    pub link_token: SecretString,
    /// Fresh passkey or password plus current MFA proof.
    pub proof: FederatedLinkProof,
}

/// Resolves provider subjects without using email as an authentication key.
pub struct FederationService {
    auth: Arc<AuthService>,
    store: Arc<dyn FederationStore>,
    token_generator: Arc<dyn TokenGenerator>,
    clock: Arc<dyn Clock>,
    config: FederationConfig,
}

impl FederationService {
    /// Builds a service with the system clock after validating its policy.
    pub fn new(
        auth: Arc<AuthService>,
        store: Arc<dyn FederationStore>,
        token_generator: Arc<dyn TokenGenerator>,
        config: FederationConfig,
    ) -> Result<Self, AuthError> {
        Self::with_clock(auth, store, token_generator, Arc::new(SystemClock), config)
    }

    /// Builds a service with an injected clock for deterministic hosts and tests.
    pub fn with_clock(
        auth: Arc<AuthService>,
        store: Arc<dyn FederationStore>,
        token_generator: Arc<dyn TokenGenerator>,
        clock: Arc<dyn Clock>,
        config: FederationConfig,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            auth,
            store,
            token_generator,
            clock,
            config: config.validate()?,
        })
    }

    /// Resolves claims verified by a trusted provider adapter.
    ///
    /// A verified email may locate an existing user, but never links or logs in
    /// that user without a separate proof-of-control step.
    #[tracing::instrument(name = "sdk_auth.federation.begin_verified_login", skip_all)]
    pub async fn begin_verified_login(
        &self,
        request: BeginFederatedLoginRequest,
    ) -> Result<FederatedLoginOutcome, AuthError> {
        let claims = validate_claims(request.claims)?;
        let device = self.auth.validate_external_device(request.device)?;
        let now = self.clock.now();
        if let Some(user_id) = self
            .store
            .resolve_federated_user(request.realm_id, claims.identity.clone(), now)
            .await?
        {
            return Ok(FederatedLoginOutcome::Authenticated(Box::new(
                self.auth
                    .authenticate_external_user(
                        request.realm_id,
                        user_id,
                        device,
                        request.remember_me,
                        now,
                    )
                    .await?,
            )));
        }
        let Some(verified_email) = claims.verified_email else {
            return Ok(FederatedLoginOutcome::RegistrationRequired);
        };
        let token = self.token_generator.generate()?;
        let expires_at = now + self.config.link_challenge_ttl;
        let pending = PendingFederatedLink {
            realm_id: request.realm_id,
            digest: digest_token(&token),
            user_id: UserId::new(),
            identity_id: FederatedIdentityId::new(),
            provider_id: claims.provider_id,
            identity: claims.identity,
            verified_email,
            expires_at,
            created_at: now,
        };
        let resolution = self.store.begin_federated_link(pending.clone()).await?;
        match resolution {
            FederatedResolution::KnownIdentity(user_id) => {
                Ok(FederatedLoginOutcome::Authenticated(Box::new(
                    self.auth
                        .authenticate_external_user(
                            request.realm_id,
                            user_id,
                            device,
                            request.remember_me,
                            now,
                        )
                        .await?,
                )))
            }
            FederatedResolution::LinkRequired(user_id) => {
                Ok(FederatedLoginOutcome::LinkRequired(FederatedLinkDispatch {
                    user_id,
                    token,
                    expires_at,
                }))
            }
            FederatedResolution::RegistrationRequired if !self.config.allow_registration => {
                Ok(FederatedLoginOutcome::RegistrationRequired)
            }
            FederatedResolution::RegistrationRequired => {
                self.register_or_retry(pending, token, device, request.remember_me, now)
                    .await
            }
        }
    }

    async fn register_or_retry(
        &self,
        pending: PendingFederatedLink,
        token: OpaqueToken,
        device: DeviceContext,
        remember_me: bool,
        now: DateTime<Utc>,
    ) -> Result<FederatedLoginOutcome, AuthError> {
        let user = User {
            realm_id: pending.realm_id,
            id: UserId::new(),
            email: pending.verified_email.clone(),
            email_verified: true,
            created_at: now,
            updated_at: now,
        };
        let identity = FederatedIdentity {
            id: pending.identity_id,
            realm_id: pending.realm_id,
            user_id: user.id,
            provider_id: pending.provider_id.clone(),
            issuer: pending.identity.issuer.clone(),
            subject: pending.identity.subject.clone(),
            verified_email: pending.verified_email.clone(),
            created_at: now,
            last_used_at: Some(now),
            revoked_at: None,
        };
        let prepared = self.auth.prepare_external_session(
            &user,
            device.clone(),
            remember_me,
            AuthenticationMethod::Federated,
            None,
            now,
        )?;
        let session = prepared.command.session.clone();
        let result = self
            .store
            .register_federated_user(RegisterFederatedUser {
                user: user.clone(),
                identity,
                session: prepared.command,
                event: event(
                    pending.realm_id,
                    user.id,
                    AuthEventKind::FederatedUserRegistered,
                    now,
                ),
            })
            .await?;
        if result == FederatedRegistrationResolution::Registered {
            return Ok(FederatedLoginOutcome::Authenticated(Box::new(
                Authentication {
                    user,
                    session,
                    tokens: prepared.tokens,
                    trusted_device_grant: None,
                },
            )));
        }
        match self.store.begin_federated_link(pending.clone()).await? {
            FederatedResolution::KnownIdentity(user_id) => {
                Ok(FederatedLoginOutcome::Authenticated(Box::new(
                    self.auth
                        .authenticate_external_user(
                            pending.realm_id,
                            user_id,
                            device,
                            remember_me,
                            now,
                        )
                        .await?,
                )))
            }
            FederatedResolution::LinkRequired(user_id) => {
                Ok(FederatedLoginOutcome::LinkRequired(FederatedLinkDispatch {
                    user_id,
                    token,
                    expires_at: pending.expires_at,
                }))
            }
            FederatedResolution::RegistrationRequired => Err(AuthError::new(
                ErrorCode::Conflict,
                "federated registration could not be resolved",
                true,
            )),
        }
    }

    /// Links a pending external identity only after fresh proof by the target user.
    #[tracing::instrument(name = "sdk_auth.federation.complete_link", skip_all)]
    pub async fn complete_link(
        &self,
        request: CompleteFederatedLinkRequest,
    ) -> Result<FederatedIdentity, AuthError> {
        if request.link_token.is_empty() {
            return Err(link_invalid());
        }
        let user_id = self
            .auth
            .verify_federated_link_step_up(request.realm_id, &request.access_token, &request.proof)
            .await?;
        let now = self.clock.now();
        match self
            .store
            .complete_federated_link(CompleteFederatedLink {
                realm_id: request.realm_id,
                digest: sdk_auth_crypto::digest_token_text(&request.link_token),
                user_id,
                now,
                audit: AuditRecord::succeeded_user_action(
                    request.realm_id,
                    user_id,
                    AuthEventKind::FederatedIdentityLinked,
                    now,
                ),
            })
            .await?
        {
            FederatedLinkResolution::Linked(identity) => Ok(*identity),
            FederatedLinkResolution::Invalid => Err(link_invalid()),
            FederatedLinkResolution::Expired => Err(AuthError::new(
                ErrorCode::TokenExpired,
                "federated link challenge expired",
                false,
            )),
            FederatedLinkResolution::Reused => Err(AuthError::new(
                ErrorCode::TokenReused,
                "federated link challenge was already used",
                false,
            )),
            FederatedLinkResolution::Conflict => Err(AuthError::new(
                ErrorCode::Conflict,
                "the external identity is already linked",
                false,
            )),
        }
    }
}

fn link_invalid() -> AuthError {
    AuthError::new(
        ErrorCode::TokenInvalid,
        "federated link challenge is invalid",
        false,
    )
}

struct ValidatedClaims {
    provider_id: String,
    identity: FederatedIdentityKey,
    verified_email: Option<EmailAddress>,
}

fn validate_claims(claims: VerifiedFederatedClaims) -> Result<ValidatedClaims, AuthError> {
    let provider_id = claims.provider_id.trim().to_owned();
    if provider_id.is_empty()
        || provider_id.len() > 64
        || !provider_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AuthError::invalid_input());
    }
    let issuer = Url::parse(claims.issuer.trim()).map_err(|_| AuthError::invalid_input())?;
    if issuer.scheme() != "https"
        || issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
        || issuer.as_str().len() > 2_048
    {
        return Err(AuthError::invalid_input());
    }
    let subject = claims.subject.trim().to_owned();
    if subject.is_empty() || subject.len() > 255 || subject.chars().any(char::is_control) {
        return Err(AuthError::invalid_input());
    }
    let verified_email = if claims.email_verified {
        claims.email.map(EmailAddress::parse).transpose()?
    } else {
        None
    };
    Ok(ValidatedClaims {
        provider_id,
        identity: FederatedIdentityKey {
            issuer: issuer.to_string(),
            subject,
        },
        verified_email,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_claim_boundaries_reject_ambiguous_identity_keys() {
        for claims in [
            VerifiedFederatedClaims {
                provider_id: "bad provider".to_owned(),
                issuer: "https://accounts.example.com".to_owned(),
                subject: "stable".to_owned(),
                email: None,
                email_verified: false,
            },
            VerifiedFederatedClaims {
                provider_id: "google".to_owned(),
                issuer: "http://accounts.example.com".to_owned(),
                subject: "stable".to_owned(),
                email: None,
                email_verified: false,
            },
            VerifiedFederatedClaims {
                provider_id: "google".to_owned(),
                issuer: "https://accounts.example.com?tenant=other".to_owned(),
                subject: "stable".to_owned(),
                email: None,
                email_verified: false,
            },
            VerifiedFederatedClaims {
                provider_id: "google".to_owned(),
                issuer: "https://accounts.example.com".to_owned(),
                subject: "\n".to_owned(),
                email: None,
                email_verified: false,
            },
        ] {
            assert!(validate_claims(claims).is_err());
        }
    }
}
