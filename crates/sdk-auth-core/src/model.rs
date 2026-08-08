//! Public request and response models.

use chrono::{DateTime, Utc};
use sdk_auth_crypto::TokenDigest;
use sdk_auth_types::{
    DeviceContext, MfaEnrollmentId, OpaqueToken, RealmId, SecretString, Session, TokenPair,
    TrustedDevice, TrustedDeviceId, User,
};
use serde::{Deserialize, Serialize};

/// Registration request accepted only by a trusted server-side host.
#[derive(Debug)]
pub struct RegisterRequest {
    /// Realm in which the identity will be created.
    pub realm_id: RealmId,
    /// Untrusted email input.
    pub email: String,
    /// Plaintext password held in zeroizing memory.
    pub password: SecretString,
}

/// Successful registration and its one-time verification dispatch.
#[derive(Debug)]
pub struct Registration {
    /// Created user.
    pub user: User,
    /// Secret that the trusted host must deliver and never log.
    pub verification: ChallengeDispatch,
}

/// Login request accepted only by a trusted server-side host.
#[derive(Debug)]
pub struct LoginRequest {
    /// Realm in which the identity is resolved.
    pub realm_id: RealmId,
    /// Untrusted email input.
    pub email: String,
    /// Plaintext password held in zeroizing memory.
    pub password: SecretString,
    /// Whether the caller requests the longer configured session lifetime.
    pub remember_me: bool,
    /// Minimal device context supplied by the host.
    pub device: DeviceContext,
    /// Optional rotating token that can satisfy MFA after password verification.
    pub trusted_device_token: Option<SecretString>,
}

/// Result of the password phase of a login.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoginOutcome {
    /// Authentication completed and bearer tokens were issued.
    Authenticated(Box<Authentication>),
    /// A second factor must complete before any session is created.
    SecondFactorRequired(MfaLoginChallenge),
}

/// Available proof methods for a pending second-factor login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SecondFactorMethod {
    /// RFC 6238 TOTP code.
    Totp,
    /// Single-use high-entropy recovery code.
    RecoveryCode,
}

/// Pending post-password login challenge.
#[derive(Debug)]
pub struct MfaLoginChallenge {
    /// Opaque single-use challenge token.
    pub token: OpaqueToken,
    /// Supported proof methods.
    pub methods: Vec<SecondFactorMethod>,
    /// Challenge expiration.
    pub expires_at: DateTime<Utc>,
}

/// Secret second-factor proof supplied by a trusted host.
#[derive(Debug)]
pub enum SecondFactorProof {
    /// Six-digit TOTP code.
    Totp(SecretString),
    /// Printable recovery code.
    RecoveryCode(SecretString),
}

/// Completes a post-password login challenge.
#[derive(Debug)]
pub struct CompleteLoginRequest {
    /// Realm that owns the challenge.
    pub realm_id: RealmId,
    /// Opaque challenge returned by [`LoginOutcome::SecondFactorRequired`].
    pub challenge_token: SecretString,
    /// TOTP or recovery-code proof.
    pub proof: SecondFactorProof,
    /// Whether to create a rotating trusted-device grant.
    pub trust_device: bool,
}

/// Successful authentication response.
#[derive(Debug)]
pub struct Authentication {
    /// Authenticated user.
    pub user: User,
    /// Created or rotated device session.
    pub session: Session,
    /// Bearer tokens returned exactly once.
    pub tokens: TokenPair,
    /// Newly created or rotated trusted-device credential, when applicable.
    pub trusted_device_grant: Option<TrustedDeviceGrant>,
}

/// Trusted-device token returned once with public grant metadata.
#[derive(Debug)]
pub struct TrustedDeviceGrant {
    /// Public grant state.
    pub device: TrustedDevice,
    /// Rotating bearer token; only its digest is persisted.
    pub token: OpaqueToken,
}

/// Begins TOTP enrollment for an account without an active factor.
#[derive(Debug)]
pub struct BeginTotpEnrollmentRequest {
    /// Realm that owns the account.
    pub realm_id: RealmId,
    /// Active session bearer token.
    pub access_token: SecretString,
    /// Current password required for reauthentication.
    pub password: SecretString,
    /// Human-readable issuer placed in the provisioning URI.
    pub issuer: String,
}

/// Secret enrollment material returned exactly once.
#[derive(Debug)]
pub struct TotpEnrollment {
    /// Pending enrollment identifier.
    pub id: MfaEnrollmentId,
    /// Base32 seed for manual authenticator entry.
    pub base32_secret: SecretString,
    /// Secret-bearing `otpauth` provisioning URI.
    pub provisioning_uri: SecretString,
    /// Expiration of the pending enrollment.
    pub expires_at: DateTime<Utc>,
}

/// Confirms a pending TOTP enrollment.
#[derive(Debug)]
pub struct ConfirmTotpEnrollmentRequest {
    /// Realm that owns the account.
    pub realm_id: RealmId,
    /// Active session bearer token.
    pub access_token: SecretString,
    /// Pending enrollment identifier.
    pub enrollment_id: MfaEnrollmentId,
    /// Current code generated from the pending seed.
    pub code: SecretString,
    /// Whether the current device should receive a trusted-device grant.
    pub trust_current_device: bool,
}

/// Result of activating or replacing a TOTP factor.
#[derive(Debug)]
pub struct TotpActivation {
    /// Recovery codes returned once and never persisted in plaintext.
    pub recovery_codes: Vec<SecretString>,
    /// Optional trust grant for the current device.
    pub trusted_device_grant: Option<TrustedDeviceGrant>,
}

/// Reauthentication proof for factor-management operations.
#[derive(Debug)]
pub struct MfaManagementProof {
    /// Current password.
    pub password: SecretString,
    /// Active TOTP or unused recovery code.
    pub second_factor: SecondFactorProof,
}

/// Begins replacement of an active TOTP factor.
#[derive(Debug)]
pub struct BeginTotpReplacementRequest {
    /// Realm that owns the account.
    pub realm_id: RealmId,
    /// Active session bearer token.
    pub access_token: SecretString,
    /// Password and current factor proof.
    pub proof: MfaManagementProof,
    /// Human-readable issuer placed in the new provisioning URI.
    pub issuer: String,
}

/// Authenticated request that changes MFA recovery state.
#[derive(Debug)]
pub struct ManageMfaRequest {
    /// Realm that owns the account.
    pub realm_id: RealmId,
    /// Active session bearer token.
    pub access_token: SecretString,
    /// Password and current factor proof.
    pub proof: MfaManagementProof,
}

/// Request to revoke one owned trusted-device grant.
#[derive(Debug)]
pub struct RevokeTrustedDeviceRequest {
    /// Realm that owns the account.
    pub realm_id: RealmId,
    /// Active session bearer token.
    pub access_token: SecretString,
    /// Grant to revoke.
    pub trusted_device_id: TrustedDeviceId,
}

/// Refresh request carrying a single-use bearer secret.
#[derive(Debug)]
pub struct RefreshRequest {
    /// Realm that owns the session.
    pub realm_id: RealmId,
    /// Refresh token held in zeroizing memory.
    pub refresh_token: SecretString,
}

/// Password reset completion request.
#[derive(Debug)]
pub struct ResetPasswordRequest {
    /// Realm that owns the challenge.
    pub realm_id: RealmId,
    /// Single-use reset token.
    pub reset_token: SecretString,
    /// Replacement password held in zeroizing memory.
    pub new_password: SecretString,
}

/// Kind of one-time authentication challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    /// Challenge that proves control of a primary email.
    EmailVerification,
    /// Challenge that authorizes a password replacement.
    PasswordReset,
}

/// Secret challenge returned only to a trusted delivery adapter.
#[derive(Debug)]
pub struct ChallengeDispatch {
    /// One-time bearer secret.
    pub token: OpaqueToken,
    /// Time after which the challenge is rejected.
    pub expires_at: DateTime<Utc>,
}

/// Result of validating an access token.
#[derive(Debug, Clone)]
pub struct AccessValidation {
    /// Active session associated with the token.
    pub session: Session,
    /// User associated with the session.
    pub user: User,
}

/// Internal access-token record passed to storage adapters.
#[derive(Debug, Clone)]
pub struct AccessTokenRecord {
    /// Token digest; the raw token is never persisted.
    pub digest: TokenDigest,
    /// Expiration time.
    pub expires_at: DateTime<Utc>,
}
