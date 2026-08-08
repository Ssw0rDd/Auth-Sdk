//! Deterministic in-memory implementation of the authentication storage port.
//!
//! This adapter is process-local and intentionally non-durable. It implements
//! the same atomic contract as persistent adapters and is suitable for tests.

use std::collections::{HashMap, HashSet, VecDeque};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_authorization::{
    ApiKey, MAX_PERMISSIONS_PER_ROLE, MAX_ROLES_PER_PRINCIPAL, PermissionDefinition, PermissionKey,
    PrincipalId, Role, ServiceAccount,
};
use sdk_auth_core::{
    AccessTokenRecord, ActivateTotp, ApiKeyAuthentication, AttemptDecision, AuditStore,
    BootstrapIam, ChallengeStore, ClaimEventsRequest, ClaimedEvent, CompleteFederatedLink,
    CompleteMfaLogin, CompletePasskeyAuthentication, CompletePasskeyRegistration, CreateApiKey,
    CreatePermission, CreateRole, CreateServiceAccount, CreateSession, CreateTrustedDevice,
    CreateUser, EventStore, FederatedIdentity, FederatedLinkResolution,
    FederatedRegistrationResolution, FederatedResolution, FederationStore, IamStore, IdentityStore,
    LeasedEventStore, LoginAttemptPolicy, MfaChallengeLookup, MfaCompletionOutcome,
    MfaEnrollmentOutcome, MfaStore, OneTimeChallenge, OneTimeOutcome, PasskeyAuthenticationOutcome,
    PasskeyCeremonyKind, PasskeyCeremonyLookup, PasskeyRegistrationOutcome, PasskeyStore,
    PendingFederatedLink, PendingPasskeyCeremony, PendingTotpEnrollment, RateLimitStore,
    RefreshRotation, RegisterFederatedUser, RotateApiKey, RotateTrustedLogin, SessionStore,
    StoredApiKey, StoredMfaLoginChallenge, StoredPasskey, StoredTotpFactor, StoredUser,
    TrustedLoginOutcome, UnitOfWorkCapabilities, UnitOfWorkStore, VerifiedMfaProof,
};
use sdk_auth_crypto::TokenDigest;
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::{
    ApiKeyId, AuditRecord, AuthEvent, AuthenticationMethod, EventId, MfaEnrollmentId, MfaFactorId,
    OutboxClaimId, Passkey, PasskeyId, PermissionId, RealmId, RoleId, ServiceAccountId, Session,
    SessionId, TokenFamilyId, TrustedDevice, TrustedDeviceId, UserId,
};
use tokio::sync::Mutex;

/// Process-local authentication store with serialized atomic transitions.
#[derive(Default)]
pub struct MemoryAuthStore {
    state: Mutex<State>,
}

impl MemoryAuthStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl UnitOfWorkStore for MemoryAuthStore {
    fn unit_of_work_capabilities(&self) -> UnitOfWorkCapabilities {
        UnitOfWorkCapabilities::REQUIRED
    }
}

#[derive(Default)]
struct State {
    users: HashMap<(RealmId, String), StoredUser>,
    user_emails: HashMap<(RealmId, UserId), String>,
    sessions: HashMap<(RealmId, SessionId), SessionRecord>,
    access: HashMap<(RealmId, TokenDigest), AccessLink>,
    refresh: HashMap<(RealmId, TokenDigest), RefreshLink>,
    challenges: HashMap<(RealmId, TokenDigest, sdk_auth_core::ChallengeKind), ChallengeRecord>,
    attempts: HashMap<(RealmId, String, String), AttemptRecord>,
    events: Vec<EventRecord>,
    audit_records: Vec<AuditRecord>,
    totp_factors: HashMap<(RealmId, UserId), StoredTotpFactor>,
    totp_enrollments: HashMap<(RealmId, UserId), PendingTotpEnrollment>,
    mfa_login_challenges: HashMap<(RealmId, TokenDigest), MfaChallengeRecord>,
    recovery_codes: HashMap<(RealmId, UserId, TokenDigest), Option<DateTime<Utc>>>,
    trusted_devices: HashMap<(RealmId, TrustedDeviceId), TrustedDevice>,
    trusted_tokens: HashMap<(RealmId, TokenDigest), TrustedTokenRecord>,
    iam_realms: HashSet<RealmId>,
    permissions: HashMap<(RealmId, PermissionId), PermissionDefinition>,
    permission_keys: HashMap<(RealmId, String), PermissionId>,
    roles: HashMap<(RealmId, RoleId), Role>,
    role_keys: HashMap<(RealmId, String), RoleId>,
    role_permissions: HashSet<(RealmId, RoleId, PermissionId)>,
    principal_roles: HashSet<(RealmId, PrincipalId, RoleId)>,
    service_accounts: HashMap<(RealmId, ServiceAccountId), ServiceAccount>,
    api_keys: HashMap<(RealmId, ApiKeyId), StoredApiKey>,
    passkeys: HashMap<(RealmId, PasskeyId), StoredPasskey>,
    passkey_credential_ids: HashMap<Vec<u8>, (RealmId, PasskeyId)>,
    passkey_ceremonies: HashMap<(RealmId, TokenDigest), PasskeyCeremonyRecord>,
    federated_identities: HashMap<(RealmId, String, String), FederatedIdentity>,
    federated_links: HashMap<(RealmId, TokenDigest), FederatedLinkRecord>,
}

struct SessionRecord {
    session: Session,
    family_id: TokenFamilyId,
}

#[derive(Clone, Copy)]
struct AccessLink {
    session_id: SessionId,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy)]
struct RefreshLink {
    session_id: SessionId,
    family_id: TokenFamilyId,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

struct ChallengeRecord {
    challenge: OneTimeChallenge,
    consumed_at: Option<DateTime<Utc>>,
}

struct AttemptRecord {
    timestamps: VecDeque<DateTime<Utc>>,
    blocked_until: Option<DateTime<Utc>>,
}

struct EventRecord {
    event: AuthEvent,
    delivered_at: Option<DateTime<Utc>>,
    claim_id: Option<OutboxClaimId>,
    _consumer_id: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
}

struct MfaChallengeRecord {
    challenge: StoredMfaLoginChallenge,
    consumed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy)]
struct TrustedTokenRecord {
    trusted_device_id: TrustedDeviceId,
    consumed_at: Option<DateTime<Utc>>,
}

struct PasskeyCeremonyRecord {
    ceremony: PendingPasskeyCeremony,
    consumed_at: Option<DateTime<Utc>>,
}

struct FederatedLinkRecord {
    pending: PendingFederatedLink,
    consumed_at: Option<DateTime<Utc>>,
}

#[async_trait]
impl IdentityStore for MemoryAuthStore {
    async fn create_user(&self, command: CreateUser) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        let key = (
            command.user.realm_id,
            command.user.email.normalized().to_owned(),
        );
        if state.users.contains_key(&key) {
            return Err(AuthError::new(
                ErrorCode::Conflict,
                "an account with this identity already exists",
                false,
            ));
        }
        state.user_emails.insert(
            (command.user.realm_id, command.user.id),
            command.user.email.normalized().to_owned(),
        );
        state.challenges.insert(
            (
                command.user.realm_id,
                command.challenge.digest,
                command.challenge.kind,
            ),
            ChallengeRecord {
                challenge: command.challenge,
                consumed_at: None,
            },
        );
        push_events(&mut state, vec![command.event]);
        state.users.insert(
            key,
            StoredUser {
                user: command.user,
                password_hash: Some(command.password_hash),
            },
        );
        Ok(())
    }

    async fn find_user_by_email(
        &self,
        realm_id: RealmId,
        normalized_email: &str,
    ) -> Result<Option<StoredUser>, AuthError> {
        let state = self.state.lock().await;
        Ok(state
            .users
            .get(&(realm_id, normalized_email.to_owned()))
            .cloned())
    }

    async fn find_user_by_id(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Option<StoredUser>, AuthError> {
        let state = self.state.lock().await;
        let Some(email) = state.user_emails.get(&(realm_id, user_id)) else {
            return Ok(None);
        };
        Ok(state.users.get(&(realm_id, email.clone())).cloned())
    }

    async fn update_password_hash(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        password_hash: String,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        let Some(email) = state.user_emails.get(&(realm_id, user_id)).cloned() else {
            return Err(AuthError::storage_unavailable());
        };
        let Some(stored) = state.users.get_mut(&(realm_id, email)) else {
            return Err(AuthError::storage_unavailable());
        };
        stored.password_hash = Some(password_hash);
        stored.user.updated_at = updated_at;
        Ok(())
    }
}

#[async_trait]
impl FederationStore for MemoryAuthStore {
    async fn begin_federated_link(
        &self,
        mut pending: PendingFederatedLink,
    ) -> Result<FederatedResolution, AuthError> {
        let mut state = self.state.lock().await;
        let identity_key = (
            pending.realm_id,
            pending.identity.issuer.clone(),
            pending.identity.subject.clone(),
        );
        if let Some(identity) = state.federated_identities.get(&identity_key) {
            return Ok(FederatedResolution::KnownIdentity(identity.user_id));
        }
        let user_key = (
            pending.realm_id,
            pending.verified_email.normalized().to_owned(),
        );
        let Some(user_id) = state.users.get(&user_key).map(|stored| stored.user.id) else {
            return Ok(FederatedResolution::RegistrationRequired);
        };
        pending.user_id = user_id;
        state.federated_links.retain(|_, existing| {
            existing.pending.realm_id != pending.realm_id
                || existing.pending.identity != pending.identity
                || existing.pending.user_id != user_id
                || existing.consumed_at.is_some()
        });
        state.federated_links.insert(
            (pending.realm_id, pending.digest),
            FederatedLinkRecord {
                pending,
                consumed_at: None,
            },
        );
        Ok(FederatedResolution::LinkRequired(user_id))
    }

    async fn complete_federated_link(
        &self,
        command: CompleteFederatedLink,
    ) -> Result<FederatedLinkResolution, AuthError> {
        let mut state = self.state.lock().await;
        let record_key = (command.realm_id, command.digest);
        let Some(record) = state.federated_links.get(&record_key) else {
            return Ok(FederatedLinkResolution::Invalid);
        };
        if record.consumed_at.is_some() {
            return Ok(FederatedLinkResolution::Reused);
        }
        if record.pending.expires_at <= command.now {
            return Ok(FederatedLinkResolution::Expired);
        }
        if record.pending.user_id != command.user_id {
            return Ok(FederatedLinkResolution::Invalid);
        }
        let pending = record.pending.clone();
        let identity_key = (
            pending.realm_id,
            pending.identity.issuer.clone(),
            pending.identity.subject.clone(),
        );
        if let Some(existing) = state.federated_identities.get(&identity_key) {
            return if existing.user_id == command.user_id {
                Ok(FederatedLinkResolution::Reused)
            } else {
                Ok(FederatedLinkResolution::Conflict)
            };
        }
        let identity = FederatedIdentity {
            id: pending.identity_id,
            realm_id: pending.realm_id,
            user_id: command.user_id,
            provider_id: pending.provider_id,
            issuer: pending.identity.issuer,
            subject: pending.identity.subject,
            verified_email: pending.verified_email,
            created_at: command.now,
            last_used_at: None,
            revoked_at: None,
        };
        let Some(record) = state.federated_links.get_mut(&record_key) else {
            return Err(AuthError::storage_unavailable());
        };
        record.consumed_at = Some(command.now);
        state
            .federated_identities
            .insert(identity_key, identity.clone());
        state.audit_records.push(command.audit);
        Ok(FederatedLinkResolution::Linked(Box::new(identity)))
    }

    async fn register_federated_user(
        &self,
        command: RegisterFederatedUser,
    ) -> Result<FederatedRegistrationResolution, AuthError> {
        let mut state = self.state.lock().await;
        let user_key = (
            command.user.realm_id,
            command.user.email.normalized().to_owned(),
        );
        let identity_key = (
            command.identity.realm_id,
            command.identity.issuer.clone(),
            command.identity.subject.clone(),
        );
        if state.users.contains_key(&user_key)
            || state.federated_identities.contains_key(&identity_key)
        {
            return Ok(FederatedRegistrationResolution::Retry);
        }
        insert_session(&mut state, command.session)?;
        state.user_emails.insert(
            (command.user.realm_id, command.user.id),
            command.user.email.normalized().to_owned(),
        );
        state.users.insert(
            user_key,
            StoredUser {
                user: command.user,
                password_hash: None,
            },
        );
        state
            .federated_identities
            .insert(identity_key, command.identity);
        push_events(&mut state, vec![command.event]);
        Ok(FederatedRegistrationResolution::Registered)
    }
}

#[async_trait]
impl SessionStore for MemoryAuthStore {
    async fn create_session(&self, command: CreateSession) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        insert_session(&mut state, command)
    }

    async fn validate_access(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, AuthError> {
        let mut state = self.state.lock().await;
        let Some(link) = state.access.get(&(realm_id, digest)).copied() else {
            return Ok(None);
        };
        if link.expires_at <= now {
            return Ok(None);
        }
        let Some(record) = state.sessions.get_mut(&(realm_id, link.session_id)) else {
            return Ok(None);
        };
        if record.session.revoked_at.is_some() || record.session.expires_at <= now {
            return Ok(None);
        }
        record.session.last_seen_at = now;
        Ok(Some(record.session.clone()))
    }

    async fn rotate_refresh(
        &self,
        realm_id: RealmId,
        presented: TokenDigest,
        replacement: TokenDigest,
        access: AccessTokenRecord,
        now: DateTime<Utc>,
        mut reuse_event: AuthEvent,
    ) -> Result<RefreshRotation, AuthError> {
        let mut state = self.state.lock().await;
        let Some(link) = state.refresh.get(&(realm_id, presented)).copied() else {
            return Ok(RefreshRotation::Invalid);
        };
        if link.consumed_at.is_some() {
            let Some(session_record) = state.sessions.get_mut(&(realm_id, link.session_id)) else {
                return Ok(RefreshRotation::Invalid);
            };
            if session_record.family_id != link.family_id {
                return Err(AuthError::storage_unavailable());
            }
            session_record.session.revoked_at = Some(now);
            reuse_event.user_id = session_record.session.user_id;
            push_events(&mut state, vec![reuse_event]);
            return Ok(RefreshRotation::Reused);
        }
        let (session_id, family_id, expires_at, updated) = {
            let Some(session_record) = state.sessions.get_mut(&(realm_id, link.session_id)) else {
                return Ok(RefreshRotation::Invalid);
            };
            if session_record.family_id != link.family_id {
                return Err(AuthError::storage_unavailable());
            }
            if session_record.session.revoked_at.is_some() {
                return Ok(RefreshRotation::Revoked);
            }
            if link.expires_at <= now || session_record.session.expires_at <= now {
                return Ok(RefreshRotation::Expired);
            }
            session_record.session.last_seen_at = now;
            (
                session_record.session.id,
                session_record.family_id,
                session_record.session.expires_at,
                session_record.session.clone(),
            )
        };
        if let Some(current) = state.refresh.get_mut(&(realm_id, presented)) {
            current.consumed_at = Some(now);
        }
        state.refresh.insert(
            (realm_id, replacement),
            RefreshLink {
                session_id,
                family_id,
                expires_at,
                consumed_at: None,
            },
        );
        state.access.insert(
            (realm_id, access.digest),
            AccessLink {
                session_id,
                expires_at: access.expires_at.min(expires_at),
            },
        );
        Ok(RefreshRotation::Rotated(updated))
    }

    async fn revoke_session(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        session_id: SessionId,
        now: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        let Some(record) = state.sessions.get_mut(&(realm_id, session_id)) else {
            return Ok(false);
        };
        if record.session.user_id != user_id {
            return Ok(false);
        }
        if record.session.revoked_at.is_none() {
            record.session.revoked_at = Some(now);
        }
        state.audit_records.push(audit);
        Ok(true)
    }

    async fn revoke_all_sessions(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        now: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<u64, AuthError> {
        let mut state = self.state.lock().await;
        let mut count = 0_u64;
        for ((session_realm, _), record) in &mut state.sessions {
            if *session_realm == realm_id
                && record.session.user_id == user_id
                && record.session.revoked_at.is_none()
            {
                record.session.revoked_at = Some(now);
                count += 1;
            }
        }
        if count > 0 {
            state.audit_records.push(audit);
        }
        Ok(count)
    }

    async fn list_sessions(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Session>, AuthError> {
        let state = self.state.lock().await;
        let mut sessions: Vec<Session> = state
            .sessions
            .values()
            .filter(|record| {
                record.session.realm_id == realm_id && record.session.user_id == user_id
            })
            .map(|record| record.session.clone())
            .collect();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.created_at));
        Ok(sessions)
    }
}

#[async_trait]
impl ChallengeStore for MemoryAuthStore {
    async fn replace_challenge(
        &self,
        realm_id: RealmId,
        challenge: OneTimeChallenge,
        event: AuthEvent,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        state
            .challenges
            .retain(|(existing_realm, _, kind), record| {
                !(*existing_realm == realm_id
                    && *kind == challenge.kind
                    && record.challenge.user_id == challenge.user_id
                    && record.consumed_at.is_none())
            });
        state.challenges.insert(
            (realm_id, challenge.digest, challenge.kind),
            ChallengeRecord {
                challenge,
                consumed_at: None,
            },
        );
        push_events(&mut state, vec![event]);
        Ok(())
    }

    async fn consume_email_verification(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
        mut audit: AuditRecord,
    ) -> Result<OneTimeOutcome, AuthError> {
        let mut state = self.state.lock().await;
        let key = (
            realm_id,
            digest,
            sdk_auth_core::ChallengeKind::EmailVerification,
        );
        let Some(record) = state.challenges.get_mut(&key) else {
            return Ok(OneTimeOutcome::Invalid);
        };
        if record.consumed_at.is_some() {
            return Ok(OneTimeOutcome::Reused);
        }
        if record.challenge.expires_at <= now {
            return Ok(OneTimeOutcome::Expired);
        }
        record.consumed_at = Some(now);
        let user_id = record.challenge.user_id;
        let Some(email) = state.user_emails.get(&(realm_id, user_id)).cloned() else {
            return Err(AuthError::storage_unavailable());
        };
        let Some(stored) = state.users.get_mut(&(realm_id, email)) else {
            return Err(AuthError::storage_unavailable());
        };
        stored.user.email_verified = true;
        stored.user.updated_at = now;
        audit.subject_user_id = Some(user_id);
        state.audit_records.push(audit);
        Ok(OneTimeOutcome::Consumed(user_id))
    }

    async fn reset_password(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        new_password_hash: String,
        now: DateTime<Utc>,
        mut event: AuthEvent,
    ) -> Result<OneTimeOutcome, AuthError> {
        let mut state = self.state.lock().await;
        let key = (
            realm_id,
            digest,
            sdk_auth_core::ChallengeKind::PasswordReset,
        );
        let Some(record) = state.challenges.get_mut(&key) else {
            return Ok(OneTimeOutcome::Invalid);
        };
        if record.consumed_at.is_some() {
            return Ok(OneTimeOutcome::Reused);
        }
        if record.challenge.expires_at <= now {
            return Ok(OneTimeOutcome::Expired);
        }
        record.consumed_at = Some(now);
        let user_id = record.challenge.user_id;
        let Some(email) = state.user_emails.get(&(realm_id, user_id)).cloned() else {
            return Err(AuthError::storage_unavailable());
        };
        let Some(stored) = state.users.get_mut(&(realm_id, email)) else {
            return Err(AuthError::storage_unavailable());
        };
        stored.password_hash = Some(new_password_hash);
        stored.user.updated_at = now;
        for ((session_realm, _), session) in &mut state.sessions {
            if *session_realm == realm_id && session.session.user_id == user_id {
                session.session.revoked_at = Some(now);
            }
        }
        for ((device_realm, _), device) in &mut state.trusted_devices {
            if *device_realm == realm_id && device.user_id == user_id {
                device.revoked_at = Some(now);
            }
        }
        event.user_id = user_id;
        push_events(&mut state, vec![event]);
        Ok(OneTimeOutcome::Consumed(user_id))
    }
}

#[async_trait]
impl RateLimitStore for MemoryAuthStore {
    async fn record_login_attempt(
        &self,
        realm_id: RealmId,
        subject: &str,
        network_hash: Option<&str>,
        now: DateTime<Utc>,
        policy: LoginAttemptPolicy,
    ) -> Result<AttemptDecision, AuthError> {
        let mut state = self.state.lock().await;
        let account_key = (realm_id, subject.to_owned(), "account".to_owned());
        let account = update_attempt(&mut state.attempts, account_key, now, policy);
        let Some(network_hash) = network_hash else {
            return Ok(account);
        };
        let network_key = (realm_id, network_hash.to_owned(), "network".to_owned());
        let network = update_attempt(&mut state.attempts, network_key, now, policy);
        Ok(later_block(account, network))
    }

    async fn clear_login_attempts(
        &self,
        realm_id: RealmId,
        subject: &str,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        state
            .attempts
            .retain(|(candidate_realm, candidate_subject, scope), _| {
                *candidate_realm != realm_id || candidate_subject != subject || scope != "account"
            });
        Ok(())
    }
}

#[async_trait]
impl EventStore for MemoryAuthStore {
    async fn pending_events(&self, limit: u32) -> Result<Vec<AuthEvent>, AuthError> {
        let state = self.state.lock().await;
        Ok(state
            .events
            .iter()
            .filter(|record| record.delivered_at.is_none() && record.claim_id.is_none())
            .take(limit as usize)
            .map(|record| record.event.clone())
            .collect())
    }

    async fn acknowledge_event(
        &self,
        event_id: EventId,
        delivered_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        let Some(record) = state
            .events
            .iter_mut()
            .find(|record| record.event.id == event_id)
        else {
            return Ok(false);
        };
        if record.delivered_at.is_some()
            || record
                .lease_expires_at
                .is_some_and(|lease_expires_at| lease_expires_at > delivered_at)
        {
            return Ok(false);
        }
        record.delivered_at = Some(delivered_at);
        record.claim_id = None;
        record._consumer_id = None;
        record.lease_expires_at = None;
        Ok(true)
    }
}

#[async_trait]
impl LeasedEventStore for MemoryAuthStore {
    async fn claim_events(
        &self,
        request: ClaimEventsRequest,
        claim_id: OutboxClaimId,
        now: DateTime<Utc>,
    ) -> Result<Vec<ClaimedEvent>, AuthError> {
        let mut state = self.state.lock().await;
        let lease_expires_at = now + request.lease_duration;
        let mut claimed = Vec::new();
        for record in &mut state.events {
            if claimed.len() >= request.limit as usize || record.delivered_at.is_some() {
                continue;
            }
            if record
                .lease_expires_at
                .is_some_and(|expires_at| expires_at > now)
            {
                continue;
            }
            record.claim_id = Some(claim_id);
            record._consumer_id = Some(request.consumer_id.clone());
            record.lease_expires_at = Some(lease_expires_at);
            claimed.push(ClaimedEvent {
                event: record.event.clone(),
                claim_id,
                lease_expires_at,
            });
        }
        Ok(claimed)
    }

    async fn acknowledge_claim(
        &self,
        event_id: EventId,
        claim_id: OutboxClaimId,
        delivered_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        let Some(record) = state
            .events
            .iter_mut()
            .find(|record| record.event.id == event_id)
        else {
            return Ok(false);
        };
        if record.delivered_at.is_some()
            || record.claim_id != Some(claim_id)
            || !record
                .lease_expires_at
                .is_some_and(|expires_at| expires_at > delivered_at)
        {
            return Ok(false);
        }
        record.delivered_at = Some(delivered_at);
        record.claim_id = None;
        record._consumer_id = None;
        record.lease_expires_at = None;
        Ok(true)
    }

    async fn release_claim(&self, claim_id: OutboxClaimId) -> Result<u64, AuthError> {
        let mut state = self.state.lock().await;
        let mut released = 0_u64;
        for record in &mut state.events {
            if record.delivered_at.is_none() && record.claim_id == Some(claim_id) {
                record.claim_id = None;
                record._consumer_id = None;
                record.lease_expires_at = None;
                released = released.saturating_add(1);
            }
        }
        Ok(released)
    }
}

#[async_trait]
impl AuditStore for MemoryAuthStore {
    async fn list_audit_records(
        &self,
        realm_id: RealmId,
        before: Option<DateTime<Utc>>,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, AuthError> {
        let state = self.state.lock().await;
        let mut records: Vec<_> = state
            .audit_records
            .iter()
            .filter(|record| {
                record.realm_id == realm_id
                    && before.is_none_or(|instant| record.occurred_at < instant)
            })
            .cloned()
            .collect();
        records.sort_by(|left, right| {
            right
                .occurred_at
                .cmp(&left.occurred_at)
                .then_with(|| right.id.to_string().cmp(&left.id.to_string()))
        });
        records.truncate(limit as usize);
        Ok(records)
    }
}

#[async_trait]
impl MfaStore for MemoryAuthStore {
    async fn find_totp_factor(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Option<StoredTotpFactor>, AuthError> {
        let state = self.state.lock().await;
        Ok(state.totp_factors.get(&(realm_id, user_id)).cloned())
    }

    async fn replace_totp_enrollment(
        &self,
        enrollment: PendingTotpEnrollment,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        let key = (enrollment.realm_id, enrollment.user_id);
        let has_factor = state.totp_factors.contains_key(&key);
        if has_factor != enrollment.replacing {
            return Err(AuthError::new(
                ErrorCode::Conflict,
                "MFA enrollment conflicts with current factor state",
                false,
            ));
        }
        state.totp_enrollments.insert(key, enrollment);
        Ok(())
    }

    async fn find_totp_enrollment(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
    ) -> Result<Option<PendingTotpEnrollment>, AuthError> {
        let state = self.state.lock().await;
        Ok(state
            .totp_enrollments
            .get(&(realm_id, user_id))
            .filter(|enrollment| enrollment.id == enrollment_id)
            .cloned())
    }

    async fn record_totp_enrollment_failure(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError> {
        let mut state = self.state.lock().await;
        let Some(enrollment) = state.totp_enrollments.get_mut(&(realm_id, user_id)) else {
            return Ok(AttemptDecision::BlockedUntil(now));
        };
        if enrollment.id != enrollment_id || enrollment.expires_at <= now {
            return Ok(AttemptDecision::BlockedUntil(now));
        }
        enrollment.attempts = enrollment.attempts.saturating_add(1);
        if enrollment.attempts >= enrollment.max_attempts {
            Ok(AttemptDecision::BlockedUntil(enrollment.expires_at))
        } else {
            Ok(AttemptDecision::Allowed)
        }
    }

    async fn activate_totp(
        &self,
        command: ActivateTotp,
    ) -> Result<MfaEnrollmentOutcome, AuthError> {
        let mut state = self.state.lock().await;
        let key = (command.factor.realm_id, command.factor.user_id);
        let Some(enrollment) = state.totp_enrollments.get(&key).cloned() else {
            return Ok(MfaEnrollmentOutcome::Invalid);
        };
        if enrollment.id != command.enrollment_id
            || enrollment.replacing != state.totp_factors.contains_key(&key)
        {
            return Ok(MfaEnrollmentOutcome::Invalid);
        }
        if enrollment.expires_at <= command.now {
            return Ok(MfaEnrollmentOutcome::Expired);
        }
        if enrollment.attempts >= enrollment.max_attempts {
            return Ok(MfaEnrollmentOutcome::RateLimited);
        }
        let Some(current) = state
            .sessions
            .get_mut(&(command.factor.realm_id, command.current_session_id))
        else {
            return Ok(MfaEnrollmentOutcome::Invalid);
        };
        if current.session.user_id != command.factor.user_id
            || current.session.revoked_at.is_some()
            || current.session.expires_at <= command.now
        {
            return Ok(MfaEnrollmentOutcome::Invalid);
        }
        current.session.authentication_method = AuthenticationMethod::PasswordTotp;
        current.session.second_factor_verified_at = Some(command.now);
        for ((session_realm, session_id), record) in &mut state.sessions {
            if *session_realm == command.factor.realm_id
                && record.session.user_id == command.factor.user_id
                && *session_id != command.current_session_id
                && record.session.revoked_at.is_none()
            {
                record.session.revoked_at = Some(command.now);
            }
        }
        for ((device_realm, _), device) in &mut state.trusted_devices {
            if *device_realm == command.factor.realm_id
                && device.user_id == command.factor.user_id
                && device.revoked_at.is_none()
            {
                device.revoked_at = Some(command.now);
            }
        }
        state
            .recovery_codes
            .retain(|(realm, user, _), _| *realm != key.0 || *user != key.1);
        for digest in command.recovery_digests {
            state.recovery_codes.insert((key.0, key.1, digest), None);
        }
        state.totp_factors.insert(key, command.factor);
        state.totp_enrollments.remove(&key);
        if let Some(trusted) = command.trusted_device {
            insert_trusted_device(&mut state, trusted)?;
        }
        push_events(&mut state, command.events);
        Ok(MfaEnrollmentOutcome::Activated)
    }

    async fn create_mfa_login_challenge(
        &self,
        challenge: StoredMfaLoginChallenge,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        state.mfa_login_challenges.retain(|_, record| {
            record.challenge.realm_id != challenge.realm_id
                || record.challenge.user_id != challenge.user_id
                || record.consumed_at.is_some()
        });
        state.mfa_login_challenges.insert(
            (challenge.realm_id, challenge.digest),
            MfaChallengeRecord {
                challenge,
                consumed_at: None,
            },
        );
        Ok(())
    }

    async fn load_mfa_login_challenge(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<MfaChallengeLookup, AuthError> {
        let state = self.state.lock().await;
        let Some(record) = state.mfa_login_challenges.get(&(realm_id, digest)) else {
            return Ok(MfaChallengeLookup::Invalid);
        };
        if record.consumed_at.is_some() {
            return Ok(MfaChallengeLookup::Invalid);
        }
        if record.challenge.expires_at <= now {
            return Ok(MfaChallengeLookup::Expired);
        }
        if record.challenge.attempts >= record.challenge.max_attempts {
            return Ok(MfaChallengeLookup::RateLimited);
        }
        let Some(factor) = state
            .totp_factors
            .get(&(realm_id, record.challenge.user_id))
            .cloned()
        else {
            return Ok(MfaChallengeLookup::Invalid);
        };
        Ok(MfaChallengeLookup::Active {
            challenge: Box::new(record.challenge.clone()),
            factor: Box::new(factor),
        })
    }

    async fn record_mfa_login_failure(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError> {
        let mut state = self.state.lock().await;
        let Some(record) = state.mfa_login_challenges.get_mut(&(realm_id, digest)) else {
            return Ok(AttemptDecision::BlockedUntil(now));
        };
        if record.consumed_at.is_some() || record.challenge.expires_at <= now {
            return Ok(AttemptDecision::BlockedUntil(now));
        }
        record.challenge.attempts = record.challenge.attempts.saturating_add(1);
        if record.challenge.attempts >= record.challenge.max_attempts {
            Ok(AttemptDecision::BlockedUntil(record.challenge.expires_at))
        } else {
            Ok(AttemptDecision::Allowed)
        }
    }

    async fn complete_mfa_login(
        &self,
        command: CompleteMfaLogin,
    ) -> Result<MfaCompletionOutcome, AuthError> {
        let mut state = self.state.lock().await;
        let realm_id = command.session.session.realm_id;
        let user_id = command.session.session.user_id;
        let Some(record) = state
            .mfa_login_challenges
            .get(&(realm_id, command.challenge_digest))
        else {
            return Ok(MfaCompletionOutcome::Invalid);
        };
        if record.consumed_at.is_some() {
            return Ok(MfaCompletionOutcome::Reused);
        }
        if record.challenge.user_id != user_id {
            return Ok(MfaCompletionOutcome::Invalid);
        }
        if record.challenge.expires_at <= command.now {
            return Ok(MfaCompletionOutcome::Expired);
        }
        if record.challenge.attempts >= record.challenge.max_attempts {
            return Ok(MfaCompletionOutcome::RateLimited);
        }
        match command.proof {
            VerifiedMfaProof::Totp { factor_id, counter } => {
                let Some(factor) = state.totp_factors.get_mut(&(realm_id, user_id)) else {
                    return Ok(MfaCompletionOutcome::Invalid);
                };
                if factor.id != factor_id {
                    return Ok(MfaCompletionOutcome::Invalid);
                }
                if factor
                    .last_accepted_counter
                    .is_some_and(|last| counter <= last)
                {
                    return Ok(MfaCompletionOutcome::Reused);
                }
                factor.last_accepted_counter = Some(counter);
                factor.updated_at = command.now;
            }
            VerifiedMfaProof::RecoveryCode(digest) => {
                let Some(consumed_at) = state.recovery_codes.get_mut(&(realm_id, user_id, digest))
                else {
                    return Ok(MfaCompletionOutcome::Invalid);
                };
                if consumed_at.is_some() {
                    return Ok(MfaCompletionOutcome::Reused);
                }
                *consumed_at = Some(command.now);
            }
        }
        let Some(record) = state
            .mfa_login_challenges
            .get_mut(&(realm_id, command.challenge_digest))
        else {
            return Err(AuthError::storage_unavailable());
        };
        record.consumed_at = Some(command.now);
        let session = command.session.session.clone();
        insert_session(&mut state, command.session)?;
        let trusted_device = command
            .trusted_device
            .map(|trusted| insert_trusted_device(&mut state, trusted))
            .transpose()?;
        push_events(&mut state, command.events);
        Ok(MfaCompletionOutcome::Completed {
            session: Box::new(session),
            trusted_device: trusted_device.map(Box::new),
        })
    }

    async fn rotate_trusted_and_create_session(
        &self,
        command: RotateTrustedLogin,
    ) -> Result<TrustedLoginOutcome, AuthError> {
        let RotateTrustedLogin {
            realm_id,
            user_id,
            presented,
            replacement,
            session,
            now,
            mut replay_event,
        } = command;
        let mut state = self.state.lock().await;
        let Some(token_record) = state.trusted_tokens.get(&(realm_id, presented)).copied() else {
            return Ok(TrustedLoginOutcome::Invalid);
        };
        let key = (realm_id, token_record.trusted_device_id);
        if token_record.consumed_at.is_some() {
            if let Some(device) = state.trusted_devices.get_mut(&key) {
                device.revoked_at = Some(now);
                replay_event.user_id = device.user_id;
                push_events(&mut state, vec![replay_event]);
            }
            return Ok(TrustedLoginOutcome::Reused);
        }
        let Some(device) = state.trusted_devices.get_mut(&key) else {
            return Ok(TrustedLoginOutcome::Invalid);
        };
        if device.user_id != user_id || device.revoked_at.is_some() || device.expires_at <= now {
            return Ok(TrustedLoginOutcome::Invalid);
        }
        device.last_used_at = now;
        let updated = device.clone();
        if let Some(current) = state.trusted_tokens.get_mut(&(realm_id, presented)) {
            current.consumed_at = Some(now);
        }
        state.trusted_tokens.insert(
            (realm_id, replacement),
            TrustedTokenRecord {
                trusted_device_id: token_record.trusted_device_id,
                consumed_at: None,
            },
        );
        let created_session = session.session.clone();
        insert_session(&mut state, session)?;
        Ok(TrustedLoginOutcome::Authenticated {
            session: Box::new(created_session),
            trusted_device: Box::new(updated),
        })
    }

    async fn accept_management_totp(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        factor_id: MfaFactorId,
        counter: u64,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        let Some(factor) = state.totp_factors.get_mut(&(realm_id, user_id)) else {
            return Ok(false);
        };
        if factor.id != factor_id
            || factor
                .last_accepted_counter
                .is_some_and(|last| counter <= last)
        {
            return Ok(false);
        }
        factor.last_accepted_counter = Some(counter);
        Ok(true)
    }

    async fn consume_management_recovery(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        digest: TokenDigest,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        let Some(consumed_at) = state.recovery_codes.get_mut(&(realm_id, user_id, digest)) else {
            return Ok(false);
        };
        if consumed_at.is_some() {
            return Ok(false);
        }
        *consumed_at = Some(event.created_at);
        push_events(&mut state, vec![event]);
        Ok(true)
    }

    async fn replace_recovery_codes(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        digests: Vec<TokenDigest>,
        event: AuthEvent,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        if !state.totp_factors.contains_key(&(realm_id, user_id)) {
            return Err(AuthError::new(
                ErrorCode::MfaNotEnrolled,
                "MFA is not enrolled",
                false,
            ));
        }
        state
            .recovery_codes
            .retain(|(realm, user, _), _| *realm != realm_id || *user != user_id);
        for digest in digests {
            state
                .recovery_codes
                .insert((realm_id, user_id, digest), None);
        }
        push_events(&mut state, vec![event]);
        Ok(())
    }

    async fn disable_mfa(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        if state.totp_factors.remove(&(realm_id, user_id)).is_none() {
            return Ok(false);
        }
        state.totp_enrollments.remove(&(realm_id, user_id));
        state
            .recovery_codes
            .retain(|(realm, user, _), _| *realm != realm_id || *user != user_id);
        state.mfa_login_challenges.retain(|_, challenge| {
            challenge.challenge.realm_id != realm_id || challenge.challenge.user_id != user_id
        });
        revoke_user_state(&mut state, realm_id, user_id, now);
        push_events(&mut state, vec![event]);
        Ok(true)
    }

    async fn list_trusted_devices(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<TrustedDevice>, AuthError> {
        let state = self.state.lock().await;
        let mut devices: Vec<_> = state
            .trusted_devices
            .values()
            .filter(|device| device.realm_id == realm_id && device.user_id == user_id)
            .cloned()
            .collect();
        devices.sort_by_key(|device| std::cmp::Reverse(device.created_at));
        Ok(devices)
    }

    async fn revoke_trusted_device(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        trusted_device_id: TrustedDeviceId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        let Some(device) = state
            .trusted_devices
            .get_mut(&(realm_id, trusted_device_id))
        else {
            return Ok(false);
        };
        if device.user_id != user_id {
            return Ok(false);
        }
        if device.revoked_at.is_none() {
            device.revoked_at = Some(now);
            push_events(&mut state, vec![event]);
        }
        Ok(true)
    }

    async fn factors_needing_rewrap(
        &self,
        realm_id: RealmId,
        active_key_id: &str,
        limit: u32,
    ) -> Result<Vec<StoredTotpFactor>, AuthError> {
        let state = self.state.lock().await;
        Ok(state
            .totp_factors
            .values()
            .filter(|factor| {
                factor.realm_id == realm_id && factor.sealed_seed.key_id() != active_key_id
            })
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn update_rewrapped_factor(
        &self,
        factor: StoredTotpFactor,
        expected_key_id: &str,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        let Some(current) = state
            .totp_factors
            .get_mut(&(factor.realm_id, factor.user_id))
        else {
            return Ok(false);
        };
        if current.id != factor.id || current.sealed_seed.key_id() != expected_key_id {
            return Ok(false);
        }
        *current = factor;
        Ok(true)
    }
}

#[async_trait]
impl PasskeyStore for MemoryAuthStore {
    async fn replace_passkey_registration(
        &self,
        ceremony: PendingPasskeyCeremony,
    ) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        if ceremony.kind != PasskeyCeremonyKind::Registration || ceremony.session_id.is_none() {
            return Err(AuthError::invalid_input());
        }
        state
            .passkey_ceremonies
            .retain(|_, current| current.ceremony.expires_at > ceremony.created_at);
        state.passkey_ceremonies.retain(|_, current| {
            current.ceremony.kind != PasskeyCeremonyKind::Registration
                || current.ceremony.realm_id != ceremony.realm_id
                || current.ceremony.user_id != ceremony.user_id
                || current.ceremony.session_id != ceremony.session_id
                || current.consumed_at.is_some()
        });
        state.passkey_ceremonies.insert(
            (ceremony.realm_id, ceremony.digest),
            PasskeyCeremonyRecord {
                ceremony,
                consumed_at: None,
            },
        );
        Ok(())
    }

    async fn create_passkey_authentication(
        &self,
        ceremony: PendingPasskeyCeremony,
    ) -> Result<(), AuthError> {
        if ceremony.kind != PasskeyCeremonyKind::Authentication || ceremony.session_id.is_some() {
            return Err(AuthError::invalid_input());
        }
        let mut state = self.state.lock().await;
        state
            .passkey_ceremonies
            .retain(|_, current| current.ceremony.expires_at > ceremony.created_at);
        let key = (ceremony.realm_id, ceremony.digest);
        if state.passkey_ceremonies.contains_key(&key) {
            return Err(conflict("WebAuthn ceremony identifier already exists"));
        }
        state.passkey_ceremonies.insert(
            key,
            PasskeyCeremonyRecord {
                ceremony,
                consumed_at: None,
            },
        );
        Ok(())
    }

    async fn load_passkey_ceremony(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        kind: PasskeyCeremonyKind,
        now: DateTime<Utc>,
    ) -> Result<PasskeyCeremonyLookup, AuthError> {
        let state = self.state.lock().await;
        let Some(record) = state.passkey_ceremonies.get(&(realm_id, digest)) else {
            return Ok(PasskeyCeremonyLookup::Invalid);
        };
        if record.ceremony.kind != kind {
            return Ok(PasskeyCeremonyLookup::Invalid);
        }
        if record.consumed_at.is_some() {
            return Ok(PasskeyCeremonyLookup::Reused);
        }
        if record.ceremony.expires_at <= now {
            return Ok(PasskeyCeremonyLookup::Expired);
        }
        if record.ceremony.attempts >= record.ceremony.max_attempts {
            return Ok(PasskeyCeremonyLookup::RateLimited);
        }
        Ok(PasskeyCeremonyLookup::Active(Box::new(
            record.ceremony.clone(),
        )))
    }

    async fn record_passkey_failure(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError> {
        let mut state = self.state.lock().await;
        let Some(record) = state.passkey_ceremonies.get_mut(&(realm_id, digest)) else {
            return Ok(AttemptDecision::Allowed);
        };
        if record.consumed_at.is_some() || record.ceremony.expires_at <= now {
            return Ok(AttemptDecision::Allowed);
        }
        record.ceremony.attempts = record.ceremony.attempts.saturating_add(1);
        if record.ceremony.attempts >= record.ceremony.max_attempts {
            Ok(AttemptDecision::BlockedUntil(record.ceremony.expires_at))
        } else {
            Ok(AttemptDecision::Allowed)
        }
    }

    async fn list_stored_passkeys(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<StoredPasskey>, AuthError> {
        let state = self.state.lock().await;
        Ok(state
            .passkeys
            .values()
            .filter(|credential| {
                credential.passkey.realm_id == realm_id
                    && credential.passkey.user_id == user_id
                    && credential.passkey.revoked_at.is_none()
            })
            .cloned()
            .collect())
    }

    async fn complete_passkey_registration(
        &self,
        command: CompletePasskeyRegistration,
    ) -> Result<PasskeyRegistrationOutcome, AuthError> {
        let mut state = self.state.lock().await;
        let realm_id = command.credential.passkey.realm_id;
        let ceremony_key = (realm_id, command.ceremony_digest);
        let Some(record) = state.passkey_ceremonies.get(&ceremony_key) else {
            return Ok(PasskeyRegistrationOutcome::Invalid);
        };
        if record.consumed_at.is_some() {
            return Ok(PasskeyRegistrationOutcome::Reused);
        }
        if record.ceremony.expires_at <= command.now {
            return Ok(PasskeyRegistrationOutcome::Expired);
        }
        if record.ceremony.attempts >= record.ceremony.max_attempts {
            return Ok(PasskeyRegistrationOutcome::RateLimited);
        }
        if record.ceremony.kind != PasskeyCeremonyKind::Registration
            || record.ceremony.user_id != command.credential.passkey.user_id
            || record.ceremony.provider_id != command.credential.provider_id
        {
            return Ok(PasskeyRegistrationOutcome::Invalid);
        }
        if state
            .passkey_credential_ids
            .contains_key(&command.credential.credential_id)
        {
            if let Some(record) = state.passkey_ceremonies.get_mut(&ceremony_key) {
                record.consumed_at = Some(command.now);
            }
            return Ok(PasskeyRegistrationOutcome::Conflict);
        }
        let passkey_key = (realm_id, command.credential.passkey.id);
        if state.passkeys.contains_key(&passkey_key) {
            return Err(conflict("passkey identifier already exists"));
        }
        let public = command.credential.passkey.clone();
        state
            .passkey_credential_ids
            .insert(command.credential.credential_id.clone(), passkey_key);
        state.passkeys.insert(passkey_key, command.credential);
        if let Some(record) = state.passkey_ceremonies.get_mut(&ceremony_key) {
            record.consumed_at = Some(command.now);
        }
        state.audit_records.push(command.audit);
        Ok(PasskeyRegistrationOutcome::Completed(Box::new(public)))
    }

    async fn complete_passkey_authentication(
        &self,
        command: CompletePasskeyAuthentication,
    ) -> Result<PasskeyAuthenticationOutcome, AuthError> {
        let mut state = self.state.lock().await;
        let realm_id = command.session.session.realm_id;
        let ceremony_key = (realm_id, command.ceremony_digest);
        let Some(record) = state.passkey_ceremonies.get(&ceremony_key) else {
            return Ok(PasskeyAuthenticationOutcome::Invalid);
        };
        if record.consumed_at.is_some() {
            return Ok(PasskeyAuthenticationOutcome::Reused);
        }
        if record.ceremony.expires_at <= command.now {
            return Ok(PasskeyAuthenticationOutcome::Expired);
        }
        if record.ceremony.attempts >= record.ceremony.max_attempts {
            return Ok(PasskeyAuthenticationOutcome::RateLimited);
        }
        if record.ceremony.kind != PasskeyCeremonyKind::Authentication
            || record.ceremony.user_id != command.session.session.user_id
        {
            return Ok(PasskeyAuthenticationOutcome::Invalid);
        }
        let passkey_key = (realm_id, command.passkey_id);
        let Some(passkey) = state.passkeys.get(&passkey_key) else {
            return Ok(PasskeyAuthenticationOutcome::Invalid);
        };
        if passkey.passkey.user_id != record.ceremony.user_id
            || passkey.passkey.revoked_at.is_some()
            || passkey.provider_id != command.provider_id
            || passkey.credential_format != command.credential_format
        {
            return Ok(PasskeyAuthenticationOutcome::Invalid);
        }
        let clone_suspected = passkey.signature_counter > 0
            && command.signature_counter > 0
            && command.signature_counter <= passkey.signature_counter;
        if clone_suspected {
            if let Some(passkey) = state.passkeys.get_mut(&passkey_key) {
                passkey.passkey.revoked_at = Some(command.now);
            }
            if let Some(record) = state.passkey_ceremonies.get_mut(&ceremony_key) {
                record.consumed_at = Some(command.now);
            }
            state.audit_records.push(command.clone_audit);
            return Ok(PasskeyAuthenticationOutcome::CloneSuspected);
        }
        let session_key = (realm_id, command.session.session.id);
        if state.sessions.contains_key(&session_key)
            || state
                .access
                .contains_key(&(realm_id, command.session.access.digest))
            || state
                .refresh
                .contains_key(&(realm_id, command.session.refresh_digest))
        {
            return Err(conflict("session credential identifier already exists"));
        }
        if let Some(passkey) = state.passkeys.get_mut(&passkey_key) {
            passkey.credential_blob = command.credential_blob;
            passkey.signature_counter = passkey.signature_counter.max(command.signature_counter);
            passkey.passkey.backup_eligible |= command.backup_eligible;
            passkey.passkey.backed_up = command.backed_up;
            passkey.passkey.last_used_at = Some(command.now);
        }
        if let Some(record) = state.passkey_ceremonies.get_mut(&ceremony_key) {
            record.consumed_at = Some(command.now);
        }
        let session = command.session.session.clone();
        insert_session(&mut state, command.session)?;
        Ok(PasskeyAuthenticationOutcome::Completed(Box::new(session)))
    }

    async fn list_passkeys(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Passkey>, AuthError> {
        let state = self.state.lock().await;
        let mut values = state
            .passkeys
            .values()
            .filter(|credential| {
                credential.passkey.realm_id == realm_id && credential.passkey.user_id == user_id
            })
            .map(|credential| credential.passkey.clone())
            .collect::<Vec<_>>();
        values.sort_by_key(|value| std::cmp::Reverse(value.created_at));
        Ok(values)
    }

    async fn rename_passkey(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        passkey_id: PasskeyId,
        label: String,
        _updated_at: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        let Some(passkey) = state.passkeys.get_mut(&(realm_id, passkey_id)) else {
            return Ok(false);
        };
        if passkey.passkey.user_id != user_id || passkey.passkey.revoked_at.is_some() {
            return Ok(false);
        }
        passkey.passkey.label = label;
        state.audit_records.push(audit);
        Ok(true)
    }

    async fn revoke_passkey(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        passkey_id: PasskeyId,
        revoked_at: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        let Some(passkey) = state.passkeys.get_mut(&(realm_id, passkey_id)) else {
            return Ok(false);
        };
        if passkey.passkey.user_id != user_id || passkey.passkey.revoked_at.is_some() {
            return Ok(false);
        }
        passkey.passkey.revoked_at = Some(revoked_at);
        state.audit_records.push(audit);
        Ok(true)
    }
}

#[async_trait]
impl IamStore for MemoryAuthStore {
    async fn iam_initialized(&self, realm_id: RealmId) -> Result<bool, AuthError> {
        Ok(self.state.lock().await.iam_realms.contains(&realm_id))
    }

    async fn bootstrap_iam(&self, command: BootstrapIam) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        if state.iam_realms.contains(&command.realm_id) {
            return Err(conflict("realm IAM is already initialized"));
        }
        if !state
            .user_emails
            .contains_key(&(command.realm_id, command.owner_user_id))
            || command.owner_role.realm_id() != command.realm_id
            || !command.owner_role.reserved()
            || command.permissions.is_empty()
            || command.permissions.len() > MAX_PERMISSIONS_PER_ROLE
        {
            return Err(AuthError::invalid_input());
        }
        let mut keys = HashSet::with_capacity(command.permissions.len());
        for permission in &command.permissions {
            if permission.realm_id() != command.realm_id
                || !permission.enabled()
                || !keys.insert(permission.key().as_str())
            {
                return Err(AuthError::invalid_input());
            }
        }
        let role_id = command.owner_role.id();
        for permission in command.permissions {
            state.permission_keys.insert(
                (command.realm_id, permission.key().as_str().to_owned()),
                permission.id(),
            );
            state
                .role_permissions
                .insert((command.realm_id, role_id, permission.id()));
            state
                .permissions
                .insert((command.realm_id, permission.id()), permission);
        }
        state.role_keys.insert(
            (
                command.realm_id,
                command.owner_role.key().as_str().to_owned(),
            ),
            role_id,
        );
        state
            .roles
            .insert((command.realm_id, role_id), command.owner_role);
        state.principal_roles.insert((
            command.realm_id,
            PrincipalId::User(command.owner_user_id),
            role_id,
        ));
        state.iam_realms.insert(command.realm_id);
        push_events(&mut state, vec![command.event]);
        Ok(())
    }

    async fn principal_permissions(
        &self,
        realm_id: RealmId,
        principal: PrincipalId,
    ) -> Result<Vec<PermissionKey>, AuthError> {
        let state = self.state.lock().await;
        Ok(effective_permissions(&state, realm_id, principal))
    }

    async fn create_permission(&self, command: CreatePermission) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        ensure_actor(
            &state,
            command.permission.realm_id(),
            command.actor_user_id,
            &command.required_permission,
        )?;
        let realm_id = command.permission.realm_id();
        let key = (realm_id, command.permission.key().as_str().to_owned());
        if state.permission_keys.contains_key(&key)
            || state
                .permissions
                .contains_key(&(realm_id, command.permission.id()))
        {
            return Err(conflict("permission already exists"));
        }
        state.permission_keys.insert(key, command.permission.id());
        state
            .permissions
            .insert((realm_id, command.permission.id()), command.permission);
        push_events(&mut state, vec![command.event]);
        Ok(())
    }

    async fn set_permission_enabled(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        permission_id: PermissionId,
        enabled: bool,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        ensure_actor(&state, realm_id, actor_user_id, &required_permission)?;
        if !enabled && permission_is_reserved(&state, realm_id, permission_id) {
            return Err(conflict("reserved IAM permissions cannot be disabled"));
        }
        let Some(current) = state.permissions.get(&(realm_id, permission_id)).cloned() else {
            return Ok(false);
        };
        if current.enabled() == enabled {
            return Ok(true);
        }
        let updated = PermissionDefinition::from_parts(
            realm_id,
            current.id(),
            current.key().clone(),
            current.description(),
            enabled,
            current.created_at(),
            now,
        )?;
        state.permissions.insert((realm_id, permission_id), updated);
        push_events(&mut state, vec![event]);
        Ok(true)
    }

    async fn list_permissions(
        &self,
        realm_id: RealmId,
    ) -> Result<Vec<PermissionDefinition>, AuthError> {
        let state = self.state.lock().await;
        let mut values: Vec<_> = state
            .permissions
            .values()
            .filter(|value| value.realm_id() == realm_id)
            .cloned()
            .collect();
        values.sort_by(|left, right| left.key().cmp(right.key()));
        Ok(values)
    }

    async fn create_role(&self, command: CreateRole) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        let realm_id = command.role.realm_id();
        ensure_actor(
            &state,
            realm_id,
            command.actor_user_id,
            &command.required_permission,
        )?;
        let key = (realm_id, command.role.key().as_str().to_owned());
        if command.role.reserved()
            || state.role_keys.contains_key(&key)
            || state.roles.contains_key(&(realm_id, command.role.id()))
        {
            return Err(conflict("role already exists or is reserved"));
        }
        state.role_keys.insert(key, command.role.id());
        state
            .roles
            .insert((realm_id, command.role.id()), command.role);
        push_events(&mut state, vec![command.event]);
        Ok(())
    }

    async fn set_role_enabled(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        role_id: RoleId,
        enabled: bool,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        ensure_actor(&state, realm_id, actor_user_id, &required_permission)?;
        let Some(current) = state.roles.get(&(realm_id, role_id)).cloned() else {
            return Ok(false);
        };
        if current.reserved() {
            return Err(conflict("reserved role cannot be changed"));
        }
        if current.enabled() == enabled {
            return Ok(true);
        }
        let updated = Role::from_parts(
            realm_id,
            current.id(),
            current.key().clone(),
            current.name(),
            current.description(),
            false,
            enabled,
            current.created_at(),
            now,
        )?;
        state.roles.insert((realm_id, role_id), updated);
        push_events(&mut state, vec![event]);
        Ok(true)
    }

    async fn list_roles(&self, realm_id: RealmId) -> Result<Vec<Role>, AuthError> {
        let state = self.state.lock().await;
        let mut values: Vec<_> = state
            .roles
            .values()
            .filter(|value| value.realm_id() == realm_id)
            .cloned()
            .collect();
        values.sort_by(|left, right| left.key().cmp(right.key()));
        Ok(values)
    }

    async fn set_role_permission(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        role_id: RoleId,
        permission_id: PermissionId,
        granted: bool,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        ensure_actor(&state, realm_id, actor_user_id, &required_permission)?;
        let Some(role) = state.roles.get(&(realm_id, role_id)) else {
            return Ok(false);
        };
        if role.reserved() {
            return Err(conflict("reserved role cannot be changed"));
        }
        if !state.permissions.contains_key(&(realm_id, permission_id)) {
            return Ok(false);
        }
        let key = (realm_id, role_id, permission_id);
        let changed = if granted {
            let count = state
                .role_permissions
                .iter()
                .filter(|(candidate_realm, candidate_role, _)| {
                    *candidate_realm == realm_id && *candidate_role == role_id
                })
                .count();
            if count >= MAX_PERMISSIONS_PER_ROLE && !state.role_permissions.contains(&key) {
                return Err(AuthError::invalid_input());
            }
            state.role_permissions.insert(key)
        } else {
            state.role_permissions.remove(&key)
        };
        if changed {
            push_events(&mut state, vec![event]);
        }
        Ok(changed)
    }

    async fn set_principal_role(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        principal: PrincipalId,
        role_id: RoleId,
        granted: bool,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        ensure_actor(&state, realm_id, actor_user_id, &required_permission)?;
        let Some(role) = state.roles.get(&(realm_id, role_id)) else {
            return Ok(false);
        };
        if !principal_exists(&state, realm_id, principal) {
            return Ok(false);
        }
        if role.reserved() && !matches!(principal, PrincipalId::User(_)) {
            return Err(permission_denied());
        }
        let key = (realm_id, principal, role_id);
        if granted {
            let count = state
                .principal_roles
                .iter()
                .filter(|(candidate_realm, candidate, _)| {
                    *candidate_realm == realm_id && *candidate == principal
                })
                .count();
            if count >= MAX_ROLES_PER_PRINCIPAL && !state.principal_roles.contains(&key) {
                return Err(AuthError::invalid_input());
            }
            let changed = state.principal_roles.insert(key);
            if changed {
                push_events(&mut state, vec![event]);
            }
            return Ok(changed);
        }
        if role.reserved() && state.principal_roles.contains(&key) {
            let owners = state
                .principal_roles
                .iter()
                .filter(|(candidate_realm, candidate, candidate_role)| {
                    *candidate_realm == realm_id
                        && *candidate_role == role_id
                        && matches!(candidate, PrincipalId::User(_))
                })
                .count();
            if owners <= 1 {
                return Err(conflict("the last human realm owner cannot be removed"));
            }
        }
        let changed = state.principal_roles.remove(&key);
        if changed {
            push_events(&mut state, vec![event]);
        }
        Ok(changed)
    }

    async fn create_service_account(&self, command: CreateServiceAccount) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        let account = command.service_account;
        ensure_actor(
            &state,
            account.realm_id(),
            command.actor_user_id,
            &command.required_permission,
        )?;
        if state
            .service_accounts
            .contains_key(&(account.realm_id(), account.id()))
            || state.service_accounts.values().any(|value| {
                value.realm_id() == account.realm_id() && value.name() == account.name()
            })
        {
            return Err(conflict("service account already exists"));
        }
        state
            .service_accounts
            .insert((account.realm_id(), account.id()), account);
        push_events(&mut state, vec![command.event]);
        Ok(())
    }

    async fn set_service_account_enabled(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        service_account_id: ServiceAccountId,
        enabled: bool,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        ensure_actor(&state, realm_id, actor_user_id, &required_permission)?;
        let Some(current) = state
            .service_accounts
            .get(&(realm_id, service_account_id))
            .cloned()
        else {
            return Ok(false);
        };
        if current.enabled() == enabled {
            return Ok(true);
        }
        let updated = ServiceAccount::from_parts(
            realm_id,
            service_account_id,
            current.name(),
            current.description(),
            enabled,
            current.created_at(),
            now,
        )?;
        state
            .service_accounts
            .insert((realm_id, service_account_id), updated);
        push_events(&mut state, vec![event]);
        Ok(true)
    }

    async fn list_service_accounts(
        &self,
        realm_id: RealmId,
    ) -> Result<Vec<ServiceAccount>, AuthError> {
        let state = self.state.lock().await;
        let mut values: Vec<_> = state
            .service_accounts
            .values()
            .filter(|value| value.realm_id() == realm_id)
            .cloned()
            .collect();
        values.sort_by_key(ServiceAccount::created_at);
        Ok(values)
    }

    async fn create_api_key(&self, command: CreateApiKey) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        let realm_id = command.stored.key.realm_id();
        ensure_actor(
            &state,
            realm_id,
            command.actor_user_id,
            &command.required_permission,
        )?;
        validate_api_key_scope(&state, &command.stored.key)?;
        let key = (realm_id, command.stored.key.id());
        if state.api_keys.contains_key(&key) {
            return Err(conflict("API key identifier already exists"));
        }
        state.api_keys.insert(key, command.stored);
        push_events(&mut state, vec![command.event]);
        Ok(())
    }

    async fn find_api_key(
        &self,
        realm_id: RealmId,
        id: ApiKeyId,
    ) -> Result<Option<ApiKey>, AuthError> {
        Ok(self
            .state
            .lock()
            .await
            .api_keys
            .get(&(realm_id, id))
            .map(|stored| stored.key.clone()))
    }

    async fn list_api_keys(
        &self,
        realm_id: RealmId,
        principal: PrincipalId,
    ) -> Result<Vec<ApiKey>, AuthError> {
        let state = self.state.lock().await;
        let mut values: Vec<_> = state
            .api_keys
            .values()
            .filter(|stored| {
                stored.key.realm_id() == realm_id && stored.key.principal() == principal
            })
            .map(|stored| stored.key.clone())
            .collect();
        values.sort_by_key(ApiKey::created_at);
        Ok(values)
    }

    async fn rotate_api_key(&self, command: RotateApiKey) -> Result<(), AuthError> {
        let mut state = self.state.lock().await;
        let realm_id = command.replacement.key.realm_id();
        ensure_actor(
            &state,
            realm_id,
            command.actor_user_id,
            &command.required_permission,
        )?;
        validate_api_key_scope(&state, &command.replacement.key)?;
        let Some(previous) = state
            .api_keys
            .get(&(realm_id, command.previous_id))
            .cloned()
        else {
            return Err(AuthError::invalid_credentials());
        };
        if previous.key.principal() != command.replacement.key.principal()
            || previous.key.scopes() != command.replacement.key.scopes()
            || previous.key.revoked_at().is_some()
            || state
                .api_keys
                .contains_key(&(realm_id, command.replacement.key.id()))
        {
            return Err(AuthError::invalid_credentials());
        }
        let updated_previous = ApiKey::from_parts(
            realm_id,
            previous.key.id(),
            previous.key.principal(),
            previous.key.name(),
            previous.key.scopes().to_vec(),
            previous.key.created_at(),
            previous.key.expires_at(),
            Some(
                command
                    .previous_grace_expires_at
                    .min(previous.key.expires_at()),
            ),
            previous.key.revoked_at(),
        )?;
        state.api_keys.insert(
            (realm_id, command.previous_id),
            StoredApiKey {
                key: updated_previous,
                digest: previous.digest,
            },
        );
        state.api_keys.insert(
            (realm_id, command.replacement.key.id()),
            command.replacement,
        );
        push_events(&mut state, vec![command.event]);
        Ok(())
    }

    async fn revoke_api_key(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        api_key_id: ApiKeyId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.lock().await;
        ensure_actor(&state, realm_id, actor_user_id, &required_permission)?;
        let Some(current) = state.api_keys.get(&(realm_id, api_key_id)).cloned() else {
            return Ok(false);
        };
        if current.key.revoked_at().is_some() {
            return Ok(true);
        }
        let revoked = ApiKey::from_parts(
            realm_id,
            api_key_id,
            current.key.principal(),
            current.key.name(),
            current.key.scopes().to_vec(),
            current.key.created_at(),
            current.key.expires_at(),
            current.key.grace_expires_at(),
            Some(now),
        )?;
        state.api_keys.insert(
            (realm_id, api_key_id),
            StoredApiKey {
                key: revoked,
                digest: current.digest,
            },
        );
        push_events(&mut state, vec![event]);
        Ok(true)
    }

    async fn authenticate_api_key(
        &self,
        realm_id: RealmId,
        parsed: sdk_auth_crypto::ParsedApiKey,
        now: DateTime<Utc>,
    ) -> Result<Option<ApiKeyAuthentication>, AuthError> {
        let state = self.state.lock().await;
        let Some(stored) = state.api_keys.get(&(realm_id, parsed.id)) else {
            return Ok(None);
        };
        if !stored.digest.constant_time_eq(&parsed.digest)
            || stored.key.revoked_at().is_some()
            || stored.key.expires_at() <= now
            || stored
                .key
                .grace_expires_at()
                .is_some_and(|value| value <= now)
            || !principal_active(&state, realm_id, stored.key.principal())
        {
            return Ok(None);
        }
        Ok(Some(ApiKeyAuthentication {
            key: stored.key.clone(),
            permissions: effective_permissions(&state, realm_id, stored.key.principal()),
        }))
    }
}

fn effective_permissions(
    state: &State,
    realm_id: RealmId,
    principal: PrincipalId,
) -> Vec<PermissionKey> {
    if !principal_active(state, realm_id, principal) {
        return Vec::new();
    }
    let mut values = HashSet::new();
    for (candidate_realm, candidate_principal, role_id) in &state.principal_roles {
        if *candidate_realm != realm_id || *candidate_principal != principal {
            continue;
        }
        let Some(role) = state.roles.get(&(realm_id, *role_id)) else {
            continue;
        };
        if !role.enabled() {
            continue;
        }
        for (permission_realm, permission_role, permission_id) in &state.role_permissions {
            if *permission_realm != realm_id || permission_role != role_id {
                continue;
            }
            let Some(permission) = state.permissions.get(&(realm_id, *permission_id)) else {
                continue;
            };
            if permission.enabled() {
                values.insert(permission.key().clone());
            }
        }
    }
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_unstable();
    values
}

fn principal_exists(state: &State, realm_id: RealmId, principal: PrincipalId) -> bool {
    match principal {
        PrincipalId::User(id) => state.user_emails.contains_key(&(realm_id, id)),
        PrincipalId::ServiceAccount(id) => state.service_accounts.contains_key(&(realm_id, id)),
        _ => false,
    }
}

fn principal_active(state: &State, realm_id: RealmId, principal: PrincipalId) -> bool {
    match principal {
        PrincipalId::User(id) => state.user_emails.contains_key(&(realm_id, id)),
        PrincipalId::ServiceAccount(id) => state
            .service_accounts
            .get(&(realm_id, id))
            .is_some_and(ServiceAccount::enabled),
        _ => false,
    }
}

fn ensure_actor(
    state: &State,
    realm_id: RealmId,
    actor: UserId,
    required: &PermissionKey,
) -> Result<(), AuthError> {
    if effective_permissions(state, realm_id, PrincipalId::User(actor))
        .iter()
        .any(|value| value == required)
    {
        Ok(())
    } else {
        Err(permission_denied())
    }
}

fn validate_api_key_scope(state: &State, key: &ApiKey) -> Result<(), AuthError> {
    if !principal_active(state, key.realm_id(), key.principal()) {
        return Err(permission_denied());
    }
    let granted = effective_permissions(state, key.realm_id(), key.principal());
    if key
        .scopes()
        .iter()
        .all(|scope| granted.iter().any(|permission| permission == scope))
    {
        Ok(())
    } else {
        Err(permission_denied())
    }
}

fn permission_is_reserved(state: &State, realm_id: RealmId, permission_id: PermissionId) -> bool {
    state
        .role_permissions
        .iter()
        .any(|(candidate_realm, role_id, candidate_permission)| {
            *candidate_realm == realm_id
                && *candidate_permission == permission_id
                && state
                    .roles
                    .get(&(realm_id, *role_id))
                    .is_some_and(Role::reserved)
        })
}

fn conflict(message: &'static str) -> AuthError {
    AuthError::new(ErrorCode::Conflict, message, false)
}

fn permission_denied() -> AuthError {
    AuthError::new(ErrorCode::PermissionDenied, "permission denied", false)
}

fn insert_session(state: &mut State, command: CreateSession) -> Result<(), AuthError> {
    let key = (command.session.realm_id, command.session.id);
    if state.sessions.contains_key(&key) {
        return Err(AuthError::new(
            ErrorCode::Conflict,
            "session identifier already exists",
            false,
        ));
    }
    state.access.insert(
        (command.session.realm_id, command.access.digest),
        AccessLink {
            session_id: command.session.id,
            expires_at: command.access.expires_at,
        },
    );
    state.refresh.insert(
        (command.session.realm_id, command.refresh_digest),
        RefreshLink {
            session_id: command.session.id,
            family_id: command.family_id,
            expires_at: command.session.expires_at,
            consumed_at: None,
        },
    );
    state.sessions.insert(
        key,
        SessionRecord {
            session: command.session,
            family_id: command.family_id,
        },
    );
    state.audit_records.push(command.audit);
    Ok(())
}

fn insert_trusted_device(
    state: &mut State,
    command: CreateTrustedDevice,
) -> Result<TrustedDevice, AuthError> {
    let key = (command.device.realm_id, command.device.id);
    if state.trusted_devices.contains_key(&key) {
        return Err(AuthError::new(
            ErrorCode::Conflict,
            "trusted-device identifier already exists",
            false,
        ));
    }
    state.trusted_tokens.insert(
        (command.device.realm_id, command.token_digest),
        TrustedTokenRecord {
            trusted_device_id: command.device.id,
            consumed_at: None,
        },
    );
    state.trusted_devices.insert(key, command.device.clone());
    Ok(command.device)
}

fn push_events(state: &mut State, events: Vec<AuthEvent>) {
    for event in events {
        state
            .audit_records
            .push(AuditRecord::from_outbox_event(&event));
        state.events.push(EventRecord {
            event,
            delivered_at: None,
            claim_id: None,
            _consumer_id: None,
            lease_expires_at: None,
        });
    }
}

fn revoke_user_state(state: &mut State, realm_id: RealmId, user_id: UserId, now: DateTime<Utc>) {
    for ((session_realm, _), session) in &mut state.sessions {
        if *session_realm == realm_id && session.session.user_id == user_id {
            session.session.revoked_at = Some(now);
        }
    }
    for ((device_realm, _), device) in &mut state.trusted_devices {
        if *device_realm == realm_id && device.user_id == user_id {
            device.revoked_at = Some(now);
        }
    }
}

fn update_attempt(
    attempts: &mut HashMap<(RealmId, String, String), AttemptRecord>,
    key: (RealmId, String, String),
    now: DateTime<Utc>,
    policy: LoginAttemptPolicy,
) -> AttemptDecision {
    let record = attempts.entry(key).or_insert(AttemptRecord {
        timestamps: VecDeque::new(),
        blocked_until: None,
    });
    if let Some(blocked_until) = record.blocked_until {
        if blocked_until > now {
            return AttemptDecision::BlockedUntil(blocked_until);
        }
        record.timestamps.clear();
        record.blocked_until = None;
    }
    let cutoff = now - policy.window;
    while record
        .timestamps
        .front()
        .is_some_and(|timestamp| *timestamp < cutoff)
    {
        record.timestamps.pop_front();
    }
    record.timestamps.push_back(now);
    if record.timestamps.len() > policy.max_failures as usize {
        let blocked_until = now + policy.lockout;
        record.blocked_until = Some(blocked_until);
        AttemptDecision::BlockedUntil(blocked_until)
    } else {
        AttemptDecision::Allowed
    }
}

fn later_block(first: AttemptDecision, second: AttemptDecision) -> AttemptDecision {
    match (first, second) {
        (AttemptDecision::BlockedUntil(left), AttemptDecision::BlockedUntil(right)) => {
            AttemptDecision::BlockedUntil(left.max(right))
        }
        (AttemptDecision::BlockedUntil(until), AttemptDecision::Allowed)
        | (AttemptDecision::Allowed, AttemptDecision::BlockedUntil(until)) => {
            AttemptDecision::BlockedUntil(until)
        }
        (AttemptDecision::Allowed, AttemptDecision::Allowed) => AttemptDecision::Allowed,
    }
}
