//! Hexagonal ports and atomic persistence commands implemented by adapters.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sdk_auth_crypto::{SealedSecret, TokenDigest};
use sdk_auth_error::AuthError;
use sdk_auth_types::{
    AuditRecord, AuthEvent, DeviceContext, EventId, MfaEnrollmentId, MfaFactorId, OutboxClaimId,
    RealmId, Session, SessionId, TokenFamilyId, TrustedDevice, TrustedDeviceId, User, UserId,
};

use crate::{AccessTokenRecord, ChallengeKind, LoginAttemptPolicy};

/// Clock boundary used to make expiration behavior deterministic in tests.
pub trait Clock: Send + Sync {
    /// Returns current UTC time.
    fn now(&self) -> DateTime<Utc>;
}

/// Production clock backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// User plus its credential representation read by the core.
#[derive(Debug, Clone)]
pub struct StoredUser {
    /// Public user state.
    pub user: User,
    /// Argon2id PHC string.
    pub password_hash: String,
}

/// One-time token persisted only as a digest.
#[derive(Debug, Clone)]
pub struct OneTimeChallenge {
    /// Digest of the raw bearer token.
    pub digest: TokenDigest,
    /// Challenge purpose.
    pub kind: ChallengeKind,
    /// User for whom the challenge was issued.
    pub user_id: UserId,
    /// Expiration time.
    pub expires_at: DateTime<Utc>,
}

/// Atomic user creation command.
#[derive(Debug, Clone)]
pub struct CreateUser {
    /// New user state.
    pub user: User,
    /// Argon2id PHC string.
    pub password_hash: String,
    /// Initial email verification challenge.
    pub challenge: OneTimeChallenge,
    /// Secret-free event persisted with the state transition.
    pub event: AuthEvent,
}

/// Atomic session creation command.
#[derive(Debug, Clone)]
pub struct CreateSession {
    /// Session state.
    pub session: Session,
    /// Refresh family used for replay response.
    pub family_id: TokenFamilyId,
    /// Initial access token record.
    pub access: AccessTokenRecord,
    /// Digest of the initial refresh token.
    pub refresh_digest: TokenDigest,
    /// Successful authentication record committed with the session.
    pub audit: AuditRecord,
}

/// Result of an atomic refresh rotation.
#[derive(Debug, Clone)]
pub enum RefreshRotation {
    /// Rotation succeeded and contains the updated session.
    Rotated(Session),
    /// The token had already been consumed; the family was revoked.
    Reused,
    /// The digest is unknown in the requested realm.
    Invalid,
    /// The session or token expired.
    Expired,
    /// The session was already revoked.
    Revoked,
}

/// Result of atomically consuming a one-time challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneTimeOutcome {
    /// Challenge was consumed for this user.
    Consumed(UserId),
    /// Digest or challenge kind was not found.
    Invalid,
    /// Challenge expired and was not consumed.
    Expired,
    /// Challenge was already consumed.
    Reused,
}

/// Decision returned by an atomic attempt counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptDecision {
    /// Authentication work may continue.
    Allowed,
    /// The caller must wait until the supplied instant.
    BlockedUntil(DateTime<Utc>),
}

/// Active encrypted TOTP factor loaded by the core.
#[derive(Debug, Clone)]
pub struct StoredTotpFactor {
    /// Factor identifier bound into associated data.
    pub id: MfaFactorId,
    /// Owning realm.
    pub realm_id: RealmId,
    /// Owning user.
    pub user_id: UserId,
    /// Authenticated ciphertext containing the raw seed.
    pub sealed_seed: SealedSecret,
    /// Greatest accepted RFC 6238 counter.
    pub last_accepted_counter: Option<u64>,
    /// Factor creation time.
    pub created_at: DateTime<Utc>,
    /// Last factor mutation time.
    pub updated_at: DateTime<Utc>,
}

/// Encrypted pending TOTP enrollment.
#[derive(Debug, Clone)]
pub struct PendingTotpEnrollment {
    /// Enrollment identifier.
    pub id: MfaEnrollmentId,
    /// Owning realm.
    pub realm_id: RealmId,
    /// Owning user.
    pub user_id: UserId,
    /// Seed encrypted with enrollment-specific associated data.
    pub sealed_seed: SealedSecret,
    /// Whether confirmation replaces an active factor.
    pub replacing: bool,
    /// Invalid confirmation attempts.
    pub attempts: u32,
    /// Maximum allowed attempts.
    pub max_attempts: u32,
    /// Enrollment expiration.
    pub expires_at: DateTime<Utc>,
    /// Enrollment creation time.
    pub created_at: DateTime<Utc>,
}

/// Post-password login state persisted without a session.
#[derive(Debug, Clone)]
pub struct StoredMfaLoginChallenge {
    /// Digest of the opaque challenge token.
    pub digest: TokenDigest,
    /// Owning realm.
    pub realm_id: RealmId,
    /// User that passed password verification.
    pub user_id: UserId,
    /// Requested device metadata.
    pub device: DeviceContext,
    /// Requested session lifetime class.
    pub remember_me: bool,
    /// Invalid proof attempts.
    pub attempts: u32,
    /// Maximum allowed attempts.
    pub max_attempts: u32,
    /// Challenge expiration.
    pub expires_at: DateTime<Utc>,
    /// Challenge creation time.
    pub created_at: DateTime<Utc>,
}

/// Result of loading a pending MFA login.
#[derive(Debug, Clone)]
pub enum MfaChallengeLookup {
    /// Challenge and factor are active.
    Active {
        /// Pending login context.
        challenge: Box<StoredMfaLoginChallenge>,
        /// Current encrypted factor.
        factor: Box<StoredTotpFactor>,
    },
    /// Challenge is unknown or no factor remains active.
    Invalid,
    /// Challenge expired.
    Expired,
    /// Challenge exceeded its attempt limit.
    RateLimited,
}

/// Proof already cryptographically checked by the core.
#[derive(Debug, Clone, Copy)]
pub enum VerifiedMfaProof {
    /// Fresh TOTP counter for the specified factor.
    Totp {
        /// Factor whose seed produced the code.
        factor_id: MfaFactorId,
        /// Fresh counter that must be stored atomically.
        counter: u64,
    },
    /// Digest of a normalized recovery code.
    RecoveryCode(TokenDigest),
}

/// New trusted-device grant and first rotating token digest.
#[derive(Debug, Clone)]
pub struct CreateTrustedDevice {
    /// Public grant metadata.
    pub device: TrustedDevice,
    /// Digest of the raw token returned to the host.
    pub token_digest: TokenDigest,
}

/// Atomic trusted-device rotation and session creation command.
#[derive(Debug, Clone)]
pub struct RotateTrustedLogin {
    /// Owning realm.
    pub realm_id: RealmId,
    /// User that already passed password verification.
    pub user_id: UserId,
    /// Digest of the rotating token presented by the host.
    pub presented: TokenDigest,
    /// Digest replacing a successfully consumed token.
    pub replacement: TokenDigest,
    /// Session and bearer-token digests to insert on success.
    pub session: CreateSession,
    /// Current time used for all transition checks.
    pub now: DateTime<Utc>,
    /// Event persisted when a consumed token is replayed.
    pub replay_event: AuthEvent,
}

/// Atomic completion of a pending MFA login.
#[derive(Debug, Clone)]
pub struct CompleteMfaLogin {
    /// Digest of the presented challenge.
    pub challenge_digest: TokenDigest,
    /// Proof previously verified by the core.
    pub proof: VerifiedMfaProof,
    /// Session and bearer-token digests to insert.
    pub session: CreateSession,
    /// Optional new trusted-device grant.
    pub trusted_device: Option<CreateTrustedDevice>,
    /// Secret-free security events.
    pub events: Vec<AuthEvent>,
    /// Current time used for all transition checks.
    pub now: DateTime<Utc>,
}

/// Outcome of an atomic MFA completion.
#[derive(Debug, Clone)]
pub enum MfaCompletionOutcome {
    /// Session and optional trusted device were created.
    Completed {
        /// Persisted session state.
        session: Box<Session>,
        /// Persisted public trusted-device state.
        trusted_device: Option<Box<TrustedDevice>>,
    },
    /// Challenge, factor, counter, or recovery code was invalid.
    Invalid,
    /// Challenge expired.
    Expired,
    /// Challenge exceeded its attempt limit.
    RateLimited,
    /// Proof had already been consumed.
    Reused,
}

/// Atomic TOTP activation or replacement command.
#[derive(Debug, Clone)]
pub struct ActivateTotp {
    /// Pending enrollment being confirmed.
    pub enrollment_id: MfaEnrollmentId,
    /// New active factor.
    pub factor: StoredTotpFactor,
    /// Current session to retain and upgrade.
    pub current_session_id: SessionId,
    /// Digests of newly generated recovery codes.
    pub recovery_digests: Vec<TokenDigest>,
    /// Optional trusted-device grant for the current device.
    pub trusted_device: Option<CreateTrustedDevice>,
    /// Secret-free events persisted atomically.
    pub events: Vec<AuthEvent>,
    /// Current transition time.
    pub now: DateTime<Utc>,
}

/// Outcome of activating a factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaEnrollmentOutcome {
    /// Factor was activated or replaced.
    Activated,
    /// Enrollment was invalid or no longer current.
    Invalid,
    /// Enrollment expired.
    Expired,
    /// Enrollment exceeded its attempt limit.
    RateLimited,
    /// Counter was already consumed.
    Reused,
}

/// Result of rotating a trusted-device token and creating a session.
#[derive(Debug, Clone)]
pub enum TrustedLoginOutcome {
    /// Grant was valid, rotated, and a session was created.
    Authenticated {
        /// New session.
        session: Box<Session>,
        /// Rotated public grant.
        trusted_device: Box<TrustedDevice>,
    },
    /// Token is unknown, expired, revoked, or belongs elsewhere.
    Invalid,
    /// A consumed token was replayed and the grant was revoked.
    Reused,
}

/// Identity persistence operations.
#[async_trait]
pub trait IdentityStore: Send + Sync {
    /// Creates a user, challenge, and event atomically.
    async fn create_user(&self, command: CreateUser) -> Result<(), AuthError>;
    /// Finds a user by normalized email inside one realm.
    async fn find_user_by_email(
        &self,
        realm_id: RealmId,
        normalized_email: &str,
    ) -> Result<Option<StoredUser>, AuthError>;
    /// Finds a user by identifier inside one realm.
    async fn find_user_by_id(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Option<StoredUser>, AuthError>;
    /// Replaces a credential after successful login rehash.
    async fn update_password_hash(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        password_hash: String,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

/// Session and bearer-token persistence operations.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Persists a session, access token, and refresh token atomically.
    async fn create_session(&self, command: CreateSession) -> Result<(), AuthError>;
    /// Validates an access digest and updates last-seen state atomically.
    async fn validate_access(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, AuthError>;
    /// Rotates a refresh token and issues an access token atomically.
    async fn rotate_refresh(
        &self,
        realm_id: RealmId,
        presented: TokenDigest,
        replacement: TokenDigest,
        access: AccessTokenRecord,
        now: DateTime<Utc>,
        reuse_event: AuthEvent,
    ) -> Result<RefreshRotation, AuthError>;
    /// Revokes one session owned by a user.
    async fn revoke_session(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        session_id: SessionId,
        now: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError>;
    /// Revokes every active session owned by a user.
    async fn revoke_all_sessions(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        now: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<u64, AuthError>;
    /// Lists sessions owned by a user.
    async fn list_sessions(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Session>, AuthError>;
}

/// Email verification and password-reset challenge operations.
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Replaces an active challenge and records an event atomically.
    async fn replace_challenge(
        &self,
        realm_id: RealmId,
        challenge: OneTimeChallenge,
        event: AuthEvent,
    ) -> Result<(), AuthError>;
    /// Consumes a challenge and verifies the email atomically.
    async fn consume_email_verification(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<OneTimeOutcome, AuthError>;
    /// Resets a password, revokes sessions and trusted devices, and records an event.
    async fn reset_password(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        new_password_hash: String,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<OneTimeOutcome, AuthError>;
}

/// Authentication attempt throttling operations.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Records a password attempt and returns the current decision atomically.
    async fn record_login_attempt(
        &self,
        realm_id: RealmId,
        subject: &str,
        network_hash: Option<&str>,
        now: DateTime<Utc>,
        policy: LoginAttemptPolicy,
    ) -> Result<AttemptDecision, AuthError>;
    /// Clears account-scoped password attempt state after success.
    async fn clear_login_attempts(&self, realm_id: RealmId, subject: &str)
    -> Result<(), AuthError>;
}

/// Durable secret-free event operations.
#[async_trait]
pub trait EventStore: Send + Sync {
    /// Returns undelivered events in creation order.
    async fn pending_events(&self, limit: u32) -> Result<Vec<AuthEvent>, AuthError>;
    /// Marks one event delivered idempotently.
    async fn acknowledge_event(
        &self,
        event_id: EventId,
        delivered_at: DateTime<Utc>,
    ) -> Result<bool, AuthError>;
}

/// Request for atomically leasing a bounded batch of outbox events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimEventsRequest {
    /// Stable identifier of the trusted dispatcher instance.
    pub consumer_id: String,
    /// Maximum number of events to claim.
    pub limit: u32,
    /// Time after which unacknowledged events become claimable again.
    pub lease_duration: Duration,
}

/// Outbox event protected by a time-bounded delivery lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedEvent {
    /// Secret-free domain event to deliver.
    pub event: AuthEvent,
    /// Claim required to acknowledge this event.
    pub claim_id: OutboxClaimId,
    /// Instant after which another consumer may reclaim the event.
    pub lease_expires_at: DateTime<Utc>,
}

/// Concurrent outbox delivery operations with at-least-once semantics.
#[async_trait]
pub trait LeasedEventStore: EventStore + Send + Sync {
    /// Atomically claims currently available events in creation order.
    async fn claim_events(
        &self,
        request: ClaimEventsRequest,
        claim_id: OutboxClaimId,
        now: DateTime<Utc>,
    ) -> Result<Vec<ClaimedEvent>, AuthError>;

    /// Acknowledges one event only when the supplied claim is active.
    async fn acknowledge_claim(
        &self,
        event_id: EventId,
        claim_id: OutboxClaimId,
        delivered_at: DateTime<Utc>,
    ) -> Result<bool, AuthError>;

    /// Releases every undelivered event owned by one claim.
    async fn release_claim(&self, claim_id: OutboxClaimId) -> Result<u64, AuthError>;
}

/// Append-only security-audit persistence operations.
#[async_trait]
pub trait AuditStore: Send + Sync {
    /// Lists one realm's records in reverse chronological order.
    async fn list_audit_records(
        &self,
        realm_id: RealmId,
        before: Option<DateTime<Utc>>,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, AuthError>;
}

/// Atomicity guarantees required from a composed persistence adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitOfWorkCapabilities {
    /// State, audit and outbox are committed or rolled back together for
    /// every journaled mutation command.
    pub atomic_journal: bool,
    /// A failed journal write rolls back the associated state transition.
    pub rollback_on_journal_failure: bool,
}

impl UnitOfWorkCapabilities {
    /// Capabilities required by the SDK composition root.
    pub const REQUIRED: Self = Self {
        atomic_journal: true,
        rollback_on_journal_failure: true,
    };
}

/// Explicit unit-of-work contract acknowledged by persistence adapters.
///
/// Every journaled mutation must commit domain state and its [`AuditRecord`]
/// and optional [`AuthEvent`] in one atomic section. Implementations must
/// return only after commit or full rollback.
pub trait UnitOfWorkStore: Send + Sync {
    /// Declares the adapter's transaction guarantees for composition checks.
    fn unit_of_work_capabilities(&self) -> UnitOfWorkCapabilities;
}

/// MFA enrollment, proof-consumption, and trusted-device operations.
#[async_trait]
pub trait MfaStore: Send + Sync {
    /// Returns the active factor for a user.
    async fn find_totp_factor(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Option<StoredTotpFactor>, AuthError>;
    /// Replaces the user's pending enrollment.
    async fn replace_totp_enrollment(
        &self,
        enrollment: PendingTotpEnrollment,
    ) -> Result<(), AuthError>;
    /// Returns a pending enrollment owned by the user.
    async fn find_totp_enrollment(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
    ) -> Result<Option<PendingTotpEnrollment>, AuthError>;
    /// Records an invalid enrollment code and returns the new decision.
    async fn record_totp_enrollment_failure(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError>;
    /// Activates or replaces TOTP atomically.
    async fn activate_totp(&self, command: ActivateTotp)
    -> Result<MfaEnrollmentOutcome, AuthError>;
    /// Persists a post-password login challenge.
    async fn create_mfa_login_challenge(
        &self,
        challenge: StoredMfaLoginChallenge,
    ) -> Result<(), AuthError>;
    /// Loads a challenge and current factor without creating a session.
    async fn load_mfa_login_challenge(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<MfaChallengeLookup, AuthError>;
    /// Records an invalid second-factor proof.
    async fn record_mfa_login_failure(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError>;
    /// Consumes a proof and creates the resulting session atomically.
    async fn complete_mfa_login(
        &self,
        command: CompleteMfaLogin,
    ) -> Result<MfaCompletionOutcome, AuthError>;
    /// Rotates a trusted token and creates a session atomically.
    async fn rotate_trusted_and_create_session(
        &self,
        command: RotateTrustedLogin,
    ) -> Result<TrustedLoginOutcome, AuthError>;
    /// Atomically accepts a fresh TOTP counter for factor management.
    async fn accept_management_totp(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        factor_id: MfaFactorId,
        counter: u64,
    ) -> Result<bool, AuthError>;
    /// Atomically consumes a recovery code for factor management.
    async fn consume_management_recovery(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        digest: TokenDigest,
        event: AuthEvent,
    ) -> Result<bool, AuthError>;
    /// Replaces all recovery-code digests atomically.
    async fn replace_recovery_codes(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        digests: Vec<TokenDigest>,
        event: AuthEvent,
    ) -> Result<(), AuthError>;
    /// Disables MFA and revokes all authentication state atomically.
    async fn disable_mfa(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError>;
    /// Lists trusted-device grants owned by a user.
    async fn list_trusted_devices(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<TrustedDevice>, AuthError>;
    /// Revokes one owned trusted-device grant.
    async fn revoke_trusted_device(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        trusted_device_id: TrustedDeviceId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError>;
    /// Returns factors encrypted with a non-active vault key.
    async fn factors_needing_rewrap(
        &self,
        realm_id: RealmId,
        active_key_id: &str,
        limit: u32,
    ) -> Result<Vec<StoredTotpFactor>, AuthError>;
    /// Replaces one factor ciphertext if its expected key still matches.
    async fn update_rewrapped_factor(
        &self,
        factor: StoredTotpFactor,
        expected_key_id: &str,
    ) -> Result<bool, AuthError>;
}

/// Composite object-safe port used by [`crate::AuthService`].
pub trait AuthStore:
    IdentityStore + SessionStore + ChallengeStore + RateLimitStore + EventStore + MfaStore
{
}

impl<T> AuthStore for T where
    T: IdentityStore + SessionStore + ChallengeStore + RateLimitStore + EventStore + MfaStore
{
}

/// Creates a bounded device context suitable for persistence.
pub(crate) fn validate_device(
    mut device: DeviceContext,
    max_name_chars: usize,
    max_metadata_bytes: usize,
) -> Result<DeviceContext, AuthError> {
    if device
        .name
        .as_ref()
        .is_some_and(|value| value.chars().count() > max_name_chars)
        || device
            .network_hash
            .as_ref()
            .is_some_and(|value| value.len() > max_metadata_bytes)
        || device
            .user_agent
            .as_ref()
            .is_some_and(|value| value.len() > max_metadata_bytes)
    {
        return Err(AuthError::invalid_input());
    }
    device.name = device
        .name
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    Ok(device)
}
