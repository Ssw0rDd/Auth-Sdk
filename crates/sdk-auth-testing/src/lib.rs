//! Deterministic fixtures shared by SDK-Auth adapter contract tests.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use sdk_auth_core::{
    AttemptDecision, AuthConfig, AuthService, ChallengeKind, ClaimEventsRequest, Clock, CreateUser,
    EventStore, IdentityStore, LeasedEventStore, LoginAttemptPolicy, OneTimeChallenge,
    RateLimitStore,
};
use sdk_auth_crypto::{
    Argon2PasswordEngine, OsTokenGenerator, TokenDigest, VaultKey, XChaCha20Vault,
};
use sdk_auth_error::AuthError;
use sdk_auth_memory::MemoryAuthStore;
use sdk_auth_types::{
    AuthEvent, AuthEventKind, EmailAddress, EventId, OutboxClaimId, RealmId, SecretBytes, User,
    UserId,
};

/// Thread-safe clock controlled by a test.
pub struct ManualClock {
    now: Mutex<DateTime<Utc>>,
}

impl ManualClock {
    /// Creates a clock at a known instant.
    #[must_use]
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    /// Advances the clock without waiting.
    pub fn advance(&self, duration: Duration) -> Result<(), AuthError> {
        let mut guard = self
            .now
            .lock()
            .map_err(|_| AuthError::storage_unavailable())?;
        *guard += duration;
        Ok(())
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        match self.now.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }
}

/// Builds a production-policy service backed by a fresh in-memory adapter.
pub fn memory_service() -> Result<AuthService, AuthError> {
    AuthService::builder()
        .store(Arc::new(MemoryAuthStore::new()))
        .password_engine(Arc::new(Argon2PasswordEngine::recommended()?))
        .token_generator(Arc::new(OsTokenGenerator))
        .secret_vault(Arc::new(XChaCha20Vault::new(
            "test-v1",
            vec![VaultKey::new("test-v1", SecretBytes::new(vec![0x5A; 32]))?],
        )?))
        .config(AuthConfig::default())
        .build()
}

/// Verifies exact sliding-window, independent account/network buckets and clear semantics.
pub async fn verify_rate_limit_contract(store: &dyn RateLimitStore) -> Result<(), AuthError> {
    let exact_realm = RealmId::new();
    for second in [0, 10, 20, 30, 40] {
        assert_eq!(
            store
                .record_login_attempt(exact_realm, "exact", None, instant(second)?, policy())
                .await?,
            AttemptDecision::Allowed
        );
    }
    assert_eq!(
        store
            .record_login_attempt(exact_realm, "exact", None, instant(61)?, policy())
            .await?,
        AttemptDecision::Allowed
    );
    assert!(matches!(
        store
            .record_login_attempt(exact_realm, "exact", None, instant(70)?, policy())
            .await?,
        AttemptDecision::BlockedUntil(_)
    ));

    let account_realm = RealmId::new();
    for attempt in 0..5 {
        assert_eq!(
            store
                .record_login_attempt(account_realm, "account", None, instant(attempt)?, policy())
                .await?,
            AttemptDecision::Allowed
        );
    }
    assert!(matches!(
        store
            .record_login_attempt(account_realm, "account", None, instant(5)?, policy())
            .await?,
        AttemptDecision::BlockedUntil(_)
    ));

    let network_realm = RealmId::new();
    for attempt in 0..5 {
        assert_eq!(
            store
                .record_login_attempt(
                    network_realm,
                    &format!("account-{attempt}"),
                    Some("network-a"),
                    instant(attempt)?,
                    policy(),
                )
                .await?,
            AttemptDecision::Allowed
        );
    }
    assert!(matches!(
        store
            .record_login_attempt(
                network_realm,
                "different-account",
                Some("network-a"),
                instant(5)?,
                policy(),
            )
            .await?,
        AttemptDecision::BlockedUntil(_)
    ));

    let missing_network_realm = RealmId::new();
    for attempt in 0..6 {
        assert_eq!(
            store
                .record_login_attempt(
                    missing_network_realm,
                    &format!("isolated-{attempt}"),
                    None,
                    instant(attempt)?,
                    policy(),
                )
                .await?,
            AttemptDecision::Allowed
        );
    }

    let clear_realm = RealmId::new();
    for attempt in 0..5 {
        assert_eq!(
            store
                .record_login_attempt(
                    clear_realm,
                    "clear-me",
                    Some("shared-network"),
                    instant(attempt)?,
                    policy(),
                )
                .await?,
            AttemptDecision::Allowed
        );
    }
    store.clear_login_attempts(clear_realm, "clear-me").await?;
    assert!(matches!(
        store
            .record_login_attempt(
                clear_realm,
                "other-account",
                Some("shared-network"),
                instant(5)?,
                policy(),
            )
            .await?,
        AttemptDecision::BlockedUntil(_)
    ));
    Ok(())
}

/// Verifies exclusive leasing, claim-bound acknowledgement, expiry and release behavior.
pub async fn verify_outbox_contract<S>(store: &S) -> Result<(), AuthError>
where
    S: IdentityStore + LeasedEventStore + Send + Sync,
{
    drain_test_outbox(store, instant(1_000_000_000)?).await?;
    for index in 1..=3 {
        seed_event(store, index).await?;
    }
    let now = instant(100)?;
    let first_claim = OutboxClaimId::new();
    let first = store
        .claim_events(
            ClaimEventsRequest {
                consumer_id: "worker-a".to_owned(),
                limit: 2,
                lease_duration: Duration::seconds(60),
            },
            first_claim,
            now,
        )
        .await?;
    assert_eq!(first.len(), 2);

    let second_claim = OutboxClaimId::new();
    let second = store
        .claim_events(
            ClaimEventsRequest {
                consumer_id: "worker-b".to_owned(),
                limit: 3,
                lease_duration: Duration::seconds(60),
            },
            second_claim,
            now,
        )
        .await?;
    assert_eq!(second.len(), 1);
    assert!(
        first
            .iter()
            .all(|claimed| claimed.event.id != second[0].event.id)
    );
    assert!(
        !store
            .acknowledge_claim(first[0].event.id, OutboxClaimId::new(), now)
            .await?
    );
    assert!(!EventStore::acknowledge_event(store, first[0].event.id, now).await?);
    assert!(
        store
            .acknowledge_claim(first[0].event.id, first_claim, now)
            .await?
    );

    let reclaimed_id = OutboxClaimId::new();
    let reclaimed = store
        .claim_events(
            ClaimEventsRequest {
                consumer_id: "worker-c".to_owned(),
                limit: 3,
                lease_duration: Duration::seconds(60),
            },
            reclaimed_id,
            now + Duration::seconds(61),
        )
        .await?;
    assert_eq!(reclaimed.len(), 2);
    assert!(
        !store
            .acknowledge_claim(first[1].event.id, first_claim, now + Duration::seconds(61))
            .await?
    );
    assert_eq!(store.release_claim(reclaimed_id).await?, 2);
    let final_claim_id = OutboxClaimId::new();
    let final_claim = store
        .claim_events(
            ClaimEventsRequest {
                consumer_id: "worker-d".to_owned(),
                limit: 3,
                lease_duration: Duration::seconds(60),
            },
            final_claim_id,
            now + Duration::seconds(62),
        )
        .await?;
    assert_eq!(final_claim.len(), 2);
    for claimed in final_claim {
        assert!(
            store
                .acknowledge_claim(
                    claimed.event.id,
                    final_claim_id,
                    now + Duration::seconds(62),
                )
                .await?
        );
    }
    Ok(())
}

async fn drain_test_outbox<S>(store: &S, now: DateTime<Utc>) -> Result<(), AuthError>
where
    S: LeasedEventStore + Send + Sync,
{
    loop {
        let claim_id = OutboxClaimId::new();
        let events = store
            .claim_events(
                ClaimEventsRequest {
                    consumer_id: "contract-cleanup".to_owned(),
                    limit: 100,
                    lease_duration: Duration::seconds(60),
                },
                claim_id,
                now,
            )
            .await?;
        if events.is_empty() {
            return Ok(());
        }
        for claimed in events {
            if !store
                .acknowledge_claim(claimed.event.id, claim_id, now)
                .await?
            {
                return Err(AuthError::storage_unavailable());
            }
        }
    }
}

fn instant(seconds: i64) -> Result<DateTime<Utc>, AuthError> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0)
        .single()
        .ok_or_else(AuthError::storage_unavailable)
}

fn policy() -> LoginAttemptPolicy {
    LoginAttemptPolicy {
        max_failures: 5,
        window: Duration::seconds(60),
        lockout: Duration::seconds(30),
    }
}

async fn seed_event<S>(store: &S, index: u8) -> Result<EventId, AuthError>
where
    S: IdentityStore + Send + Sync,
{
    let realm_id = RealmId::new();
    let user_id = UserId::new();
    let now = instant(i64::from(index))?;
    let event_id = EventId::new();
    store
        .create_user(CreateUser {
            user: User {
                realm_id,
                id: user_id,
                email: EmailAddress::parse(format!(
                    "outbox-{index}-{}@example.com",
                    realm_id.as_uuid().simple()
                ))?,
                email_verified: false,
                created_at: now,
                updated_at: now,
            },
            password_hash: "$argon2id$test-only".to_owned(),
            challenge: OneTimeChallenge {
                digest: TokenDigest::from_slice(&[index; 32])?,
                kind: ChallengeKind::EmailVerification,
                user_id,
                expires_at: now + Duration::minutes(5),
            },
            event: AuthEvent {
                id: event_id,
                realm_id,
                user_id,
                kind: AuthEventKind::EmailVerificationRequested,
                payload: "{}".to_owned(),
                created_at: now,
            },
        })
        .await?;
    Ok(event_id)
}
