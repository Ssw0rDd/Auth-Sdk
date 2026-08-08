//! Domain types with invalid states excluded at construction boundaries.

use std::fmt;

use chrono::{DateTime, Utc};
use email_address::EmailAddress as ParsedEmail;
use sdk_auth_error::AuthError;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

macro_rules! id_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a time-ordered UUIDv7 identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an existing UUID after it has crossed a trusted boundary.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            /// Parses a canonical UUID string.
            pub fn parse(value: &str) -> Result<Self, AuthError> {
                Uuid::parse_str(value)
                    .map(Self)
                    .map_err(|_| AuthError::invalid_input())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

id_type!(
    RealmId,
    "Identifier that partitions every authentication resource."
);
id_type!(UserId, "Stable identifier for a user inside a realm.");
id_type!(SessionId, "Stable identifier for a device session.");
id_type!(
    TokenFamilyId,
    "Identifier shared by refresh tokens in one session family."
);
id_type!(EventId, "Stable identifier for an outbox event.");
id_type!(
    OutboxClaimId,
    "Stable identifier for one leased batch of outbox events."
);
id_type!(
    AuditId,
    "Stable identifier for an append-only audit record."
);
id_type!(MfaFactorId, "Stable identifier for an enrolled MFA factor.");
id_type!(
    MfaEnrollmentId,
    "Stable identifier for a pending MFA enrollment."
);
id_type!(
    TrustedDeviceId,
    "Stable identifier for a trusted-device grant."
);
id_type!(PasskeyId, "Stable identifier for a WebAuthn passkey.");
id_type!(
    ServiceAccountId,
    "Stable identifier for a non-human principal inside a realm."
);
id_type!(
    PermissionId,
    "Stable identifier for a permission definition."
);
id_type!(RoleId, "Stable identifier for an authorization role.");
id_type!(
    ApiKeyId,
    "Stable public identifier for a revocable API key."
);

/// Validated email address with deterministic lookup normalization.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EmailAddress {
    original: String,
    normalized: String,
}

impl EmailAddress {
    /// Validates an email and creates its normalized lookup representation.
    pub fn parse(value: impl Into<String>) -> Result<Self, AuthError> {
        let original = value.into().trim().to_owned();
        if original.len() > 254 || !ParsedEmail::is_valid(&original) {
            return Err(AuthError::invalid_input());
        }
        let normalized = original.to_lowercase();
        Ok(Self {
            original,
            normalized,
        })
    }

    /// Returns the address as supplied after surrounding whitespace removal.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Returns the case-normalized value used for lookup and uniqueness.
    #[must_use]
    pub fn normalized(&self) -> &str {
        &self.normalized
    }
}

impl fmt::Debug for EmailAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmailAddress([REDACTED])")
    }
}

impl Serialize for EmailAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EmailAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(|_| D::Error::custom("invalid email address"))
    }
}

/// A zeroizing string whose contents never appear in debug output.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wraps a secret so its allocation is zeroized when dropped.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Exposes the secret to the smallest possible trusted scope.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// Returns whether the secret contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

/// Zeroizing binary secret used for cryptographic keys and seeds.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wraps bytes so the allocation is zeroized when dropped.
    #[must_use]
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Exposes the secret bytes to the smallest possible trusted scope.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the number of secret bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no secret bytes are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Explicitly erases the current contents before drop.
    pub fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

/// Opaque bearer token returned exactly once to the trusted host.
#[derive(Debug)]
pub struct OpaqueToken(SecretString);

impl OpaqueToken {
    /// Creates a token from cryptographically generated text.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::new(value))
    }

    /// Exposes the bearer token to a transport boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

/// Pair issued after successful authentication or refresh.
#[derive(Debug)]
pub struct TokenPair {
    /// Short-lived token used to authenticate requests.
    pub access_token: OpaqueToken,
    /// Single-use token used to rotate a session.
    pub refresh_token: OpaqueToken,
    /// Access token expiration.
    pub access_expires_at: DateTime<Utc>,
    /// Absolute session expiration.
    pub session_expires_at: DateTime<Utc>,
}

/// Minimal, host-supplied device context.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceContext {
    /// User-visible device label, bounded by the core.
    pub name: Option<String>,
    /// Host-generated privacy-preserving network fingerprint.
    pub network_hash: Option<String>,
    /// Bounded user-agent summary; never trusted for authorization.
    pub user_agent: Option<String>,
}

/// Public account state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Realm that owns the user.
    pub realm_id: RealmId,
    /// Stable user identifier.
    pub id: UserId,
    /// Validated primary email.
    pub email: EmailAddress,
    /// Whether the primary email has been verified.
    pub email_verified: bool,
    /// Account creation time.
    pub created_at: DateTime<Utc>,
    /// Last account update time.
    pub updated_at: DateTime<Utc>,
}

/// Method that established the current session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthenticationMethod {
    /// Password-only authentication for accounts without MFA.
    Password,
    /// Password followed by a TOTP proof.
    PasswordTotp,
    /// Password followed by a single-use recovery code.
    PasswordRecoveryCode,
    /// Password followed by possession of a rotating trusted-device token.
    PasswordTrustedDevice,
    /// A WebAuthn passkey ceremony with mandatory local user verification.
    Passkey,
}

/// Authentication Assurance Level conservatively established by a session.
///
/// These values use the NIST AAL vocabulary, but applications remain
/// responsible for selecting a deployment profile whose complete operational
/// controls satisfy the corresponding NIST requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AssuranceLevel {
    /// A single authentication factor was verified.
    Aal1,
    /// Two distinct authentication factors were verified.
    Aal2,
    /// A hardware-protected, phishing-resistant authenticator was verified.
    Aal3,
}

/// Security properties established when a session was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationAssurance {
    /// Conservative assurance level established by the method.
    pub level: AssuranceLevel,
    /// Method that established the session.
    pub method: AuthenticationMethod,
    /// Time of the original authentication ceremony.
    pub authenticated_at: DateTime<Utc>,
    /// Time of the most recent explicit second-factor proof, when present.
    pub second_factor_verified_at: Option<DateTime<Utc>>,
    /// Whether the ceremony cryptographically bound proof to the verifier.
    pub phishing_resistant: bool,
    /// Whether the authenticator verified the user locally.
    pub user_verified: bool,
}

/// Public view of a device session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Realm that owns the session.
    pub realm_id: RealmId,
    /// Session identifier.
    pub id: SessionId,
    /// User authenticated by the session.
    pub user_id: UserId,
    /// Device metadata supplied by the host.
    pub device: DeviceContext,
    /// Method that established this session.
    pub authentication_method: AuthenticationMethod,
    /// Time at which an explicit second factor was last verified.
    pub second_factor_verified_at: Option<DateTime<Utc>>,
    /// Session creation time.
    pub created_at: DateTime<Utc>,
    /// Most recent successful refresh or access validation time.
    pub last_seen_at: DateTime<Utc>,
    /// Absolute session expiration.
    pub expires_at: DateTime<Utc>,
    /// Revocation time when the session is no longer active.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Session {
    /// Returns a conservative, policy-ready assurance description.
    ///
    /// Trusted-device tokens remain AAL1 because the SDK cannot prove that the
    /// host stored the token as an independent authentication factor. Manual
    /// TOTP and recovery-code entry are never marked phishing-resistant.
    #[must_use]
    pub const fn assurance(&self) -> AuthenticationAssurance {
        let level = match self.authentication_method {
            AuthenticationMethod::Password | AuthenticationMethod::PasswordTrustedDevice => {
                AssuranceLevel::Aal1
            }
            AuthenticationMethod::PasswordTotp | AuthenticationMethod::PasswordRecoveryCode => {
                AssuranceLevel::Aal2
            }
            AuthenticationMethod::Passkey => AssuranceLevel::Aal2,
        };
        AuthenticationAssurance {
            level,
            method: self.authentication_method,
            authenticated_at: self.created_at,
            second_factor_verified_at: self.second_factor_verified_at,
            phishing_resistant: matches!(self.authentication_method, AuthenticationMethod::Passkey),
            user_verified: matches!(self.authentication_method, AuthenticationMethod::Passkey),
        }
    }
}

/// Public metadata for a revocable WebAuthn passkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Passkey {
    /// Realm that owns the credential.
    pub realm_id: RealmId,
    /// SDK identifier independent of the protocol credential identifier.
    pub id: PasskeyId,
    /// User that owns the credential.
    pub user_id: UserId,
    /// User-controlled bounded label.
    pub label: String,
    /// Whether the authenticator reported backup eligibility.
    pub backup_eligible: bool,
    /// Current authenticator backup state.
    pub backed_up: bool,
    /// Credential creation time.
    pub created_at: DateTime<Utc>,
    /// Most recent successful authentication, when any.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Revocation time when the credential is no longer accepted.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Public metadata for a revocable trusted-device grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    /// Realm that owns the grant.
    pub realm_id: RealmId,
    /// Stable trusted-device identifier.
    pub id: TrustedDeviceId,
    /// User that owns the grant.
    pub user_id: UserId,
    /// Descriptive metadata; never authorization evidence.
    pub device: DeviceContext,
    /// Creation time of the absolute-lifetime grant.
    pub created_at: DateTime<Utc>,
    /// Most recent successful rotation.
    pub last_used_at: DateTime<Utc>,
    /// Absolute expiration that rotation never extends.
    pub expires_at: DateTime<Utc>,
    /// Revocation time when the grant is inactive.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Stable security-activity classification used by audit and durable events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthEventKind {
    /// Record a successful authentication ceremony.
    LoginSucceeded,
    /// Record revocation of one session.
    SessionRevoked,
    /// Record bulk revocation of active sessions.
    SessionsRevoked,
    /// Record successful verification of a primary email address.
    EmailVerified,
    /// Deliver an email verification link.
    EmailVerificationRequested,
    /// Deliver a password reset link.
    PasswordResetRequested,
    /// Notify monitoring that refresh token reuse was detected.
    RefreshTokenReuseDetected,
    /// Notify monitoring that a password changed.
    PasswordChanged,
    /// Notify that TOTP MFA was enabled.
    MfaEnabled,
    /// Notify that the active TOTP factor was replaced.
    MfaReplaced,
    /// Notify that MFA was disabled.
    MfaDisabled,
    /// Notify that recovery codes were regenerated.
    RecoveryCodesRegenerated,
    /// Notify that one recovery code was consumed.
    RecoveryCodeUsed,
    /// Notify that a trusted-device grant was created.
    TrustedDeviceCreated,
    /// Notify that a trusted-device grant was revoked.
    TrustedDeviceRevoked,
    /// Notify that a rotated trusted-device token was replayed.
    TrustedDeviceReplayDetected,
    /// Record successful registration of a passkey.
    PasskeyRegistered,
    /// Record a user-visible passkey label change.
    PasskeyRenamed,
    /// Record passkey revocation.
    PasskeyRevoked,
    /// Record and reject a non-monotonic WebAuthn signature counter.
    PasskeyCloneSuspected,
    /// Notify that a realm completed its one-time IAM bootstrap.
    IamRealmBootstrapped,
    /// Record a permission catalog mutation.
    IamPermissionChanged,
    /// Record a role or role-permission mutation.
    IamRoleChanged,
    /// Record a principal-role assignment mutation.
    IamAssignmentChanged,
    /// Record a service-account lifecycle mutation.
    IamServiceAccountChanged,
    /// Record an API-key lifecycle mutation without including the credential.
    IamApiKeyChanged,
}

/// Durable event persisted atomically with authentication state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthEvent {
    /// Event identifier used for idempotent delivery.
    pub id: EventId,
    /// Realm associated with the event.
    pub realm_id: RealmId,
    /// User associated with the event.
    pub user_id: UserId,
    /// Event classification.
    pub kind: AuthEventKind,
    /// Opaque JSON payload intended for the trusted dispatcher.
    pub payload: String,
    /// Event creation time.
    pub created_at: DateTime<Utc>,
}

/// Actor responsible for an append-only audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditActor {
    /// An authenticated human actor.
    User(UserId),
    /// The SDK or a trusted host process initiated the transition.
    System,
}

/// Security-relevant outcome captured by the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditOutcome {
    /// The requested state transition completed.
    Succeeded,
    /// A hostile or invalid replay was detected and rejected.
    Denied,
}

/// Structured, append-only security audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Stable record identifier.
    pub id: AuditId,
    /// Security boundary that owns the record.
    pub realm_id: RealmId,
    /// Authenticated actor or trusted system process.
    pub actor: AuditActor,
    /// User affected by the transition, when applicable.
    pub subject_user_id: Option<UserId>,
    /// Stable action classification.
    pub kind: AuthEventKind,
    /// Security-relevant result.
    pub outcome: AuditOutcome,
    /// Secret-free, bounded JSON metadata.
    pub metadata_json: String,
    /// Timestamp committed with the state transition.
    pub occurred_at: DateTime<Utc>,
    /// Matching outbox event, when one was emitted.
    pub outbox_event_id: Option<EventId>,
}

impl AuditRecord {
    /// Creates a successful user-initiated audit record without an outbox event.
    #[must_use]
    pub fn succeeded_user_action(
        realm_id: RealmId,
        user_id: UserId,
        kind: AuthEventKind,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: AuditId::new(),
            realm_id,
            actor: AuditActor::User(user_id),
            subject_user_id: Some(user_id),
            kind,
            outcome: AuditOutcome::Succeeded,
            metadata_json: "{}".to_owned(),
            occurred_at,
            outbox_event_id: None,
        }
    }

    /// Creates a successful system-initiated audit record without an outbox event.
    #[must_use]
    pub fn succeeded_system_action(
        realm_id: RealmId,
        subject_user_id: UserId,
        kind: AuthEventKind,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: AuditId::new(),
            realm_id,
            actor: AuditActor::System,
            subject_user_id: Some(subject_user_id),
            kind,
            outcome: AuditOutcome::Succeeded,
            metadata_json: "{}".to_owned(),
            occurred_at,
            outbox_event_id: None,
        }
    }

    /// Creates an audit record coupled to an existing secret-free outbox event.
    #[must_use]
    pub fn from_outbox_event(event: &AuthEvent) -> Self {
        let system_actor = matches!(
            event.kind,
            AuthEventKind::EmailVerificationRequested
                | AuthEventKind::PasswordResetRequested
                | AuthEventKind::RefreshTokenReuseDetected
        );
        let denied = matches!(
            event.kind,
            AuthEventKind::RefreshTokenReuseDetected | AuthEventKind::TrustedDeviceReplayDetected
        );
        Self {
            id: AuditId::from_uuid(event.id.as_uuid()),
            realm_id: event.realm_id,
            actor: if system_actor {
                AuditActor::System
            } else {
                AuditActor::User(event.user_id)
            },
            subject_user_id: Some(event.user_id),
            kind: event.kind,
            outcome: if denied {
                AuditOutcome::Denied
            } else {
                AuditOutcome::Succeeded
            },
            metadata_json: event.payload.clone(),
            occurred_at: event.created_at,
            outbox_event_id: Some(event.id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(method: AuthenticationMethod) -> Session {
        let now = Utc::now();
        Session {
            realm_id: RealmId::new(),
            id: SessionId::new(),
            user_id: UserId::new(),
            device: DeviceContext::default(),
            authentication_method: method,
            second_factor_verified_at: Some(now),
            created_at: now,
            last_seen_at: now,
            expires_at: now,
            revoked_at: None,
        }
    }

    #[test]
    fn assurance_is_conservative_and_marks_only_passkeys_phishing_resistant() {
        let password = session(AuthenticationMethod::Password).assurance();
        assert_eq!(password.level, AssuranceLevel::Aal1);
        assert!(!password.phishing_resistant);

        let totp = session(AuthenticationMethod::PasswordTotp).assurance();
        assert_eq!(totp.level, AssuranceLevel::Aal2);
        assert!(!totp.phishing_resistant);

        let trusted = session(AuthenticationMethod::PasswordTrustedDevice).assurance();
        assert_eq!(trusted.level, AssuranceLevel::Aal1);

        let passkey = session(AuthenticationMethod::Passkey).assurance();
        assert_eq!(passkey.level, AssuranceLevel::Aal2);
        assert!(passkey.phishing_resistant);
        assert!(passkey.user_verified);
    }

    #[test]
    fn audit_mapping_distinguishes_system_and_denied_replays() {
        let realm_id = RealmId::new();
        let user_id = UserId::new();
        let event = AuthEvent {
            id: EventId::new(),
            realm_id,
            user_id,
            kind: AuthEventKind::RefreshTokenReuseDetected,
            payload: "{}".to_owned(),
            created_at: Utc::now(),
        };
        let audit = AuditRecord::from_outbox_event(&event);
        assert_eq!(audit.actor, AuditActor::System);
        assert_eq!(audit.outcome, AuditOutcome::Denied);
        assert_eq!(audit.subject_user_id, Some(user_id));
        assert_eq!(audit.outbox_event_id, Some(event.id));
        assert_eq!(audit.id.as_uuid(), event.id.as_uuid());

        let user_event = AuthEvent {
            id: EventId::new(),
            kind: AuthEventKind::MfaEnabled,
            ..event
        };
        let user_audit = AuditRecord::from_outbox_event(&user_event);
        assert_eq!(user_audit.actor, AuditActor::User(user_id));
        assert_eq!(user_audit.outcome, AuditOutcome::Succeeded);
    }
}
