//! SQLite authentication adapter with transactional security transitions.

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use sdk_auth_authorization::{
    ApiKey, MAX_PERMISSIONS_PER_ROLE, MAX_ROLES_PER_PRINCIPAL, PermissionDefinition, PermissionKey,
    PrincipalId, Role, RoleKey, ServiceAccount,
};
use sdk_auth_core::{
    AccessTokenRecord, ActivateTotp, ApiKeyAuthentication, AttemptDecision, AuditStore,
    BootstrapIam, ChallengeKind, ChallengeStore, ClaimEventsRequest, ClaimedEvent,
    CompleteMfaLogin, CompletePasskeyAuthentication, CompletePasskeyRegistration, CreateApiKey,
    CreatePermission, CreateRole, CreateServiceAccount, CreateSession, CreateTrustedDevice,
    CreateUser, EventStore, IamStore, IdentityStore, LeasedEventStore, LoginAttemptPolicy,
    MfaChallengeLookup, MfaCompletionOutcome, MfaEnrollmentOutcome, MfaStore, OneTimeChallenge,
    OneTimeOutcome, PasskeyAuthenticationOutcome, PasskeyCeremonyKind, PasskeyCeremonyLookup,
    PasskeyRegistrationOutcome, PasskeyStore, PendingPasskeyCeremony, PendingTotpEnrollment,
    RateLimitStore, RefreshRotation, RotateApiKey, RotateTrustedLogin, SessionStore, StoredApiKey,
    StoredMfaLoginChallenge, StoredPasskey, StoredTotpFactor, StoredUser, TrustedLoginOutcome,
    UnitOfWorkCapabilities, UnitOfWorkStore, VerifiedMfaProof,
};
use sdk_auth_crypto::{AeadAlgorithm, SealedSecret, TokenDigest};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::{
    ApiKeyId, AuditActor, AuditId, AuditOutcome, AuditRecord, AuthEvent, AuthEventKind,
    AuthenticationMethod, DeviceContext, EmailAddress, EventId, MfaEnrollmentId, MfaFactorId,
    OutboxClaimId, Passkey, PasskeyId, PermissionId, RealmId, RoleId, ServiceAccountId, Session,
    SessionId, TokenFamilyId, TrustedDevice, TrustedDeviceId, User, UserId,
};

/// Current persistent schema understood by this adapter.
pub const LATEST_SCHEMA_VERSION: u32 = 6;

const MIGRATION_1: &str = r#"
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
 realm_id TEXT NOT NULL,id TEXT NOT NULL,email TEXT NOT NULL,normalized_email TEXT NOT NULL,
 email_verified INTEGER NOT NULL CHECK(email_verified IN(0,1)),password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
 PRIMARY KEY(realm_id,id),UNIQUE(realm_id,normalized_email));
CREATE TABLE IF NOT EXISTS sessions(
 realm_id TEXT NOT NULL,id TEXT NOT NULL,user_id TEXT NOT NULL,family_id TEXT NOT NULL,
 device_name TEXT,network_hash TEXT,user_agent TEXT,created_at TEXT NOT NULL,
 authentication_method TEXT NOT NULL DEFAULT 'password',second_factor_verified_at TEXT,
 last_seen_at TEXT NOT NULL,expires_at TEXT NOT NULL,revoked_at TEXT,
 PRIMARY KEY(realm_id,id),
 FOREIGN KEY(realm_id,user_id) REFERENCES users(realm_id,id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(realm_id,user_id);
CREATE TABLE IF NOT EXISTS access_tokens(
 realm_id TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),session_id TEXT NOT NULL,
 expires_at TEXT NOT NULL,PRIMARY KEY(realm_id,digest),
 FOREIGN KEY(realm_id,session_id) REFERENCES sessions(realm_id,id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS access_session_idx ON access_tokens(realm_id,session_id);
CREATE TABLE IF NOT EXISTS refresh_tokens(
 realm_id TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),session_id TEXT NOT NULL,
 family_id TEXT NOT NULL,expires_at TEXT NOT NULL,consumed_at TEXT,
 PRIMARY KEY(realm_id,digest),
 FOREIGN KEY(realm_id,session_id) REFERENCES sessions(realm_id,id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS refresh_session_idx ON refresh_tokens(realm_id,session_id);
CREATE TABLE IF NOT EXISTS challenges(
 realm_id TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),kind TEXT NOT NULL,
 user_id TEXT NOT NULL,expires_at TEXT NOT NULL,consumed_at TEXT,
 PRIMARY KEY(realm_id,digest,kind),
 FOREIGN KEY(realm_id,user_id) REFERENCES users(realm_id,id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS challenge_user_idx ON challenges(realm_id,user_id,kind);
CREATE TABLE IF NOT EXISTS login_attempts(
 realm_id TEXT NOT NULL,subject TEXT NOT NULL,scope TEXT NOT NULL,failures INTEGER NOT NULL,
 window_started_at TEXT NOT NULL,blocked_until TEXT,PRIMARY KEY(realm_id,subject,scope));
CREATE TABLE IF NOT EXISTS outbox(
 id TEXT PRIMARY KEY,realm_id TEXT NOT NULL,user_id TEXT NOT NULL,kind TEXT NOT NULL,
 payload TEXT NOT NULL,created_at TEXT NOT NULL,delivered_at TEXT);
CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox(delivered_at,created_at);
"#;

const MIGRATION_2: &str = r#"
CREATE TABLE IF NOT EXISTS mfa_totp_factors(
 realm_id TEXT NOT NULL,user_id TEXT NOT NULL,id TEXT NOT NULL,key_id TEXT NOT NULL,
 nonce BLOB NOT NULL CHECK(length(nonce)=24),ciphertext BLOB NOT NULL,
 last_accepted_counter INTEGER,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
 PRIMARY KEY(realm_id,user_id),UNIQUE(realm_id,id),
 FOREIGN KEY(realm_id,user_id) REFERENCES users(realm_id,id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS mfa_enrollments(
 realm_id TEXT NOT NULL,user_id TEXT NOT NULL,id TEXT NOT NULL,key_id TEXT NOT NULL,
 nonce BLOB NOT NULL CHECK(length(nonce)=24),ciphertext BLOB NOT NULL,
 replacing INTEGER NOT NULL CHECK(replacing IN(0,1)),attempts INTEGER NOT NULL,
 max_attempts INTEGER NOT NULL,expires_at TEXT NOT NULL,created_at TEXT NOT NULL,
 PRIMARY KEY(realm_id,user_id),UNIQUE(realm_id,id),
 FOREIGN KEY(realm_id,user_id) REFERENCES users(realm_id,id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS mfa_login_challenges(
 realm_id TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),user_id TEXT NOT NULL,
 device_name TEXT,network_hash TEXT,user_agent TEXT,remember_me INTEGER NOT NULL CHECK(remember_me IN(0,1)),
 attempts INTEGER NOT NULL,max_attempts INTEGER NOT NULL,expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL,consumed_at TEXT,PRIMARY KEY(realm_id,digest),
 FOREIGN KEY(realm_id,user_id) REFERENCES users(realm_id,id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS mfa_login_user_idx ON mfa_login_challenges(realm_id,user_id,consumed_at);
CREATE TABLE IF NOT EXISTS mfa_recovery_codes(
 realm_id TEXT NOT NULL,user_id TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),
 consumed_at TEXT,created_at TEXT NOT NULL,PRIMARY KEY(realm_id,user_id,digest),
 FOREIGN KEY(realm_id,user_id) REFERENCES users(realm_id,id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS trusted_devices(
 realm_id TEXT NOT NULL,id TEXT NOT NULL,user_id TEXT NOT NULL,device_name TEXT,
 network_hash TEXT,user_agent TEXT,created_at TEXT NOT NULL,last_used_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,revoked_at TEXT,PRIMARY KEY(realm_id,id),
 FOREIGN KEY(realm_id,user_id) REFERENCES users(realm_id,id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS trusted_device_user_idx ON trusted_devices(realm_id,user_id,created_at);
CREATE TABLE IF NOT EXISTS trusted_device_tokens(
 realm_id TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),device_id TEXT NOT NULL,
 expires_at TEXT NOT NULL,consumed_at TEXT,PRIMARY KEY(realm_id,digest),
 FOREIGN KEY(realm_id,device_id) REFERENCES trusted_devices(realm_id,id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS trusted_token_device_idx ON trusted_device_tokens(realm_id,device_id);
"#;

const MIGRATION_3: &str = r#"
CREATE TABLE IF NOT EXISTS iam_realms(
 realm_id TEXT PRIMARY KEY,initialized_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS iam_permissions(
 realm_id TEXT NOT NULL,id TEXT NOT NULL,key TEXT NOT NULL,description TEXT NOT NULL,
 enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
 PRIMARY KEY(realm_id,id),UNIQUE(realm_id,key));
CREATE TABLE IF NOT EXISTS iam_roles(
 realm_id TEXT NOT NULL,id TEXT NOT NULL,key TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,
 reserved INTEGER NOT NULL CHECK(reserved IN(0,1)),enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
 created_at TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(realm_id,id),UNIQUE(realm_id,key));
CREATE TABLE IF NOT EXISTS iam_role_permissions(
 realm_id TEXT NOT NULL,role_id TEXT NOT NULL,permission_id TEXT NOT NULL,
 PRIMARY KEY(realm_id,role_id,permission_id),
 FOREIGN KEY(realm_id,role_id) REFERENCES iam_roles(realm_id,id) ON DELETE CASCADE,
 FOREIGN KEY(realm_id,permission_id) REFERENCES iam_permissions(realm_id,id) ON DELETE RESTRICT);
CREATE TABLE IF NOT EXISTS iam_service_accounts(
 realm_id TEXT NOT NULL,id TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,
 enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
 PRIMARY KEY(realm_id,id),UNIQUE(realm_id,name));
CREATE TABLE IF NOT EXISTS iam_principal_roles(
 realm_id TEXT NOT NULL,principal_kind TEXT NOT NULL CHECK(principal_kind IN('user','service_account')),
 principal_id TEXT NOT NULL,role_id TEXT NOT NULL,created_at TEXT NOT NULL,
 PRIMARY KEY(realm_id,principal_kind,principal_id,role_id),
 FOREIGN KEY(realm_id,role_id) REFERENCES iam_roles(realm_id,id) ON DELETE RESTRICT);
CREATE INDEX IF NOT EXISTS iam_principal_roles_lookup_idx ON iam_principal_roles(realm_id,principal_kind,principal_id);
CREATE TABLE IF NOT EXISTS iam_api_keys(
 realm_id TEXT NOT NULL,id TEXT NOT NULL,principal_kind TEXT NOT NULL CHECK(principal_kind IN('user','service_account')),
 principal_id TEXT NOT NULL,name TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),
 created_at TEXT NOT NULL,expires_at TEXT NOT NULL,grace_expires_at TEXT,revoked_at TEXT,
 PRIMARY KEY(realm_id,id));
CREATE INDEX IF NOT EXISTS iam_api_keys_principal_idx ON iam_api_keys(realm_id,principal_kind,principal_id,created_at);
CREATE TABLE IF NOT EXISTS iam_api_key_scopes(
 realm_id TEXT NOT NULL,api_key_id TEXT NOT NULL,permission_id TEXT NOT NULL,
 PRIMARY KEY(realm_id,api_key_id,permission_id),
 FOREIGN KEY(realm_id,api_key_id) REFERENCES iam_api_keys(realm_id,id) ON DELETE CASCADE,
 FOREIGN KEY(realm_id,permission_id) REFERENCES iam_permissions(realm_id,id) ON DELETE RESTRICT);
"#;

const MIGRATION_4: &str = r#"
CREATE TABLE IF NOT EXISTS sdk_schema_compatibility(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL,
 min_reader_version INTEGER NOT NULL,min_writer_version INTEGER NOT NULL);
INSERT INTO sdk_schema_compatibility(singleton,schema_version,min_reader_version,min_writer_version)
VALUES(1,4,4,4)
ON CONFLICT(singleton) DO UPDATE SET schema_version=excluded.schema_version,
 min_reader_version=excluded.min_reader_version,min_writer_version=excluded.min_writer_version;
CREATE TABLE IF NOT EXISTS audit_log(
 id TEXT PRIMARY KEY,realm_id TEXT NOT NULL,actor_kind TEXT NOT NULL,
 actor_user_id TEXT,subject_user_id TEXT,kind TEXT NOT NULL,outcome TEXT NOT NULL,
 metadata_json TEXT NOT NULL,occurred_at TEXT NOT NULL,outbox_event_id TEXT UNIQUE);
CREATE INDEX IF NOT EXISTS audit_log_realm_time_idx
 ON audit_log(realm_id,occurred_at DESC,id DESC);
INSERT OR IGNORE INTO audit_log(
 id,realm_id,actor_kind,actor_user_id,subject_user_id,kind,outcome,
 metadata_json,occurred_at,outbox_event_id)
SELECT id,realm_id,
 CASE WHEN kind IN('email_verification_requested','password_reset_requested','refresh_token_reuse_detected')
      THEN 'system' ELSE 'user' END,
 CASE WHEN kind IN('email_verification_requested','password_reset_requested','refresh_token_reuse_detected')
      THEN NULL ELSE user_id END,
 user_id,kind,
 CASE WHEN kind IN('refresh_token_reuse_detected','trusted_device_replay_detected')
      THEN 'denied' ELSE 'succeeded' END,
 payload,created_at,id
FROM outbox;
"#;

const MIGRATION_5: &str = r#"
CREATE TABLE IF NOT EXISTS passkey_credentials(
 realm_id TEXT NOT NULL,id TEXT NOT NULL,user_id TEXT NOT NULL,label TEXT NOT NULL,
 credential_id BLOB NOT NULL UNIQUE CHECK(length(credential_id) BETWEEN 1 AND 1023),
 provider_id TEXT NOT NULL,credential_format INTEGER NOT NULL,credential_blob BLOB NOT NULL,
 signature_counter INTEGER NOT NULL CHECK(signature_counter>=0),
 backup_eligible INTEGER NOT NULL CHECK(backup_eligible IN(0,1)),
 backed_up INTEGER NOT NULL CHECK(backed_up IN(0,1)),created_at TEXT NOT NULL,
 last_used_at TEXT,revoked_at TEXT,PRIMARY KEY(realm_id,id),
 FOREIGN KEY(realm_id,user_id) REFERENCES users(realm_id,id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS passkey_user_idx
 ON passkey_credentials(realm_id,user_id,revoked_at,created_at DESC);
CREATE TABLE IF NOT EXISTS passkey_ceremonies(
 realm_id TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),user_id TEXT NOT NULL,
 session_id TEXT,kind TEXT NOT NULL CHECK(kind IN('registration','authentication')),
 label TEXT,login_subject TEXT,device_name TEXT,network_hash TEXT,user_agent TEXT,
 remember_me INTEGER NOT NULL CHECK(remember_me IN(0,1)),provider_id TEXT NOT NULL,
 state_format INTEGER NOT NULL,state_blob BLOB NOT NULL,attempts INTEGER NOT NULL,
 max_attempts INTEGER NOT NULL,expires_at TEXT NOT NULL,created_at TEXT NOT NULL,consumed_at TEXT,
 PRIMARY KEY(realm_id,digest),
 FOREIGN KEY(realm_id,user_id) REFERENCES users(realm_id,id) ON DELETE CASCADE,
 FOREIGN KEY(realm_id,session_id) REFERENCES sessions(realm_id,id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS passkey_ceremony_user_idx
 ON passkey_ceremonies(realm_id,user_id,kind,consumed_at);
INSERT INTO sdk_schema_compatibility(singleton,schema_version,min_reader_version,min_writer_version)
VALUES(1,5,5,5)
ON CONFLICT(singleton) DO UPDATE SET schema_version=excluded.schema_version,
 min_reader_version=excluded.min_reader_version,min_writer_version=excluded.min_writer_version;
"#;

const MIGRATION_6: &str = r#"
DROP TABLE login_attempts;
CREATE TABLE login_attempts(
 realm_id TEXT NOT NULL,subject TEXT NOT NULL,
 scope TEXT NOT NULL CHECK(scope IN('account','network')),
 attempts_json TEXT NOT NULL,blocked_until TEXT,
 PRIMARY KEY(realm_id,subject,scope));
ALTER TABLE outbox ADD COLUMN claim_id TEXT;
ALTER TABLE outbox ADD COLUMN consumer_id TEXT;
ALTER TABLE outbox ADD COLUMN lease_expires_at TEXT;
CREATE INDEX IF NOT EXISTS outbox_claimable_idx
 ON outbox(delivered_at,lease_expires_at,created_at,id);
CREATE INDEX IF NOT EXISTS outbox_claim_idx ON outbox(claim_id,delivered_at);
INSERT INTO sdk_schema_compatibility(singleton,schema_version,min_reader_version,min_writer_version)
VALUES(1,6,6,6)
ON CONFLICT(singleton) DO UPDATE SET schema_version=excluded.schema_version,
 min_reader_version=excluded.min_reader_version,min_writer_version=excluded.min_writer_version;
"#;

/// Result returned by an explicit schema migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Version observed before migration.
    pub from: u32,
    /// Version after migration.
    pub to: u32,
    /// Ordered versions applied by this invocation.
    pub applied: Vec<u32>,
}

/// Explicit, host-controlled SQLite migrator.
pub struct SqliteMigrator;

impl SqliteMigrator {
    /// Migrates the database at `path` to [`LATEST_SCHEMA_VERSION`].
    pub fn migrate(path: impl AsRef<Path>) -> Result<MigrationReport, AuthError> {
        let mut connection = Connection::open(path).map_err(storage)?;
        configure(&connection)?;
        migrate_connection(&mut connection)
    }
}

/// SQLite-backed authentication store.
///
/// Blocking calls run on Tokio's blocking pool. `IMMEDIATE` transactions make
/// refresh and one-time-token consumption atomic across processes.
pub struct SqliteAuthStore {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteAuthStore {
    /// Opens an already-migrated database and refuses schema drift.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuthError> {
        let connection = Connection::open(path).map_err(storage)?;
        configure(&connection)?;
        require_current_schema(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Creates an isolated in-memory database with the production schema.
    pub fn in_memory() -> Result<Self, AuthError> {
        let mut connection = Connection::open_in_memory().map_err(storage)?;
        configure(&connection)?;
        migrate_connection(&mut connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    async fn run<T, F>(&self, operation: F) -> Result<T, AuthError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, AuthError> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut guard = connection
                .lock()
                .map_err(|_| AuthError::storage_unavailable())?;
            operation(&mut guard)
        })
        .await
        .map_err(|_| AuthError::storage_unavailable())?
    }
}

impl UnitOfWorkStore for SqliteAuthStore {
    fn unit_of_work_capabilities(&self) -> UnitOfWorkCapabilities {
        UnitOfWorkCapabilities::REQUIRED
    }
}

#[async_trait]
impl IdentityStore for SqliteAuthStore {
    async fn create_user(&self, command: CreateUser) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let inserted = transaction.execute(
                "INSERT INTO users(realm_id,id,email,normalized_email,email_verified,password_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                params![command.user.realm_id.to_string(),command.user.id.to_string(),command.user.email.as_str(),command.user.email.normalized(),i64::from(command.user.email_verified),command.password_hash,ts(command.user.created_at),ts(command.user.updated_at)],
            );
            if let Err(error) = inserted {
                return if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                    Err(AuthError::new(ErrorCode::Conflict,"an account with this identity already exists",false))
                } else {
                    Err(storage(error))
                };
            }
            insert_challenge(&transaction, command.user.realm_id, &command.challenge)?;
            insert_event(&transaction, &command.event)?;
            transaction.commit().map_err(storage)
        }).await
    }

    async fn find_user_by_email(
        &self,
        realm_id: RealmId,
        normalized_email: &str,
    ) -> Result<Option<StoredUser>, AuthError> {
        let normalized = normalized_email.to_owned();
        self.run(move |connection| {
            let nested = connection.query_row(
                "SELECT id,email,email_verified,password_hash,created_at,updated_at FROM users WHERE realm_id=? AND normalized_email=?",
                params![realm_id.to_string(),normalized],
                |row| stored_user(row, realm_id),
            ).optional().map_err(storage)?;
            nested.transpose()
        }).await
    }

    async fn find_user_by_id(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Option<StoredUser>, AuthError> {
        self.run(move |connection| {
            let nested = connection.query_row(
                "SELECT id,email,email_verified,password_hash,created_at,updated_at FROM users WHERE realm_id=? AND id=?",
                params![realm_id.to_string(),user_id.to_string()],
                |row| stored_user(row, realm_id),
            ).optional().map_err(storage)?;
            nested.transpose()
        }).await
    }

    async fn update_password_hash(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        password_hash: String,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.run(move |connection| {
            let changed = connection
                .execute(
                    "UPDATE users SET password_hash=?,updated_at=? WHERE realm_id=? AND id=?",
                    params![
                        password_hash,
                        ts(updated_at),
                        realm_id.to_string(),
                        user_id.to_string()
                    ],
                )
                .map_err(storage)?;
            if changed == 1 {
                Ok(())
            } else {
                Err(AuthError::storage_unavailable())
            }
        })
        .await
    }
}

#[async_trait]
impl SessionStore for SqliteAuthStore {
    async fn create_session(&self, command: CreateSession) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            insert_session(&transaction, &command)?;
            transaction.commit().map_err(storage)
        })
        .await
    }

    async fn validate_access(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let nested = transaction.query_row(
                "SELECT s.id,s.user_id,s.device_name,s.network_hash,s.user_agent,s.authentication_method,s.second_factor_verified_at,s.created_at,s.last_seen_at,s.expires_at,s.revoked_at FROM access_tokens a JOIN sessions s ON s.realm_id=a.realm_id AND s.id=a.session_id WHERE a.realm_id=? AND a.digest=? AND a.expires_at>? AND s.expires_at>? AND s.revoked_at IS NULL",
                params![realm_id.to_string(),digest.as_bytes().as_slice(),ts(now),ts(now)],
                |row| stored_session(row, realm_id),
            ).optional().map_err(storage)?;
            let mut session = nested.transpose()?;
            if let Some(active) = session.as_mut() {
                transaction.execute(
                    "UPDATE sessions SET last_seen_at=? WHERE realm_id=? AND id=?",
                    params![ts(now),realm_id.to_string(),active.id.to_string()],
                ).map_err(storage)?;
                active.last_seen_at = now;
            }
            transaction.commit().map_err(storage)?;
            Ok(session)
        }).await
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
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let refresh = transaction.query_row(
                "SELECT session_id,family_id,expires_at,consumed_at FROM refresh_tokens WHERE realm_id=? AND digest=?",
                params![realm_id.to_string(),presented.as_bytes().as_slice()],
                |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,Option<String>>(3)?)),
            ).optional().map_err(storage)?;
            let Some((session_text, family_text, refresh_expiry, consumed_at)) = refresh else {
                return Ok(RefreshRotation::Invalid);
            };
            let session_id = SessionId::parse(&session_text)?;
            let family_id = TokenFamilyId::parse(&family_text)?;
            let nested = transaction.query_row(
                "SELECT id,user_id,device_name,network_hash,user_agent,authentication_method,second_factor_verified_at,created_at,last_seen_at,expires_at,revoked_at FROM sessions WHERE realm_id=? AND id=? AND family_id=?",
                params![realm_id.to_string(),session_text,family_text],
                |row| stored_session(row, realm_id),
            ).optional().map_err(storage)?;
            let Some(mut session) = nested.transpose()? else {
                return Ok(RefreshRotation::Invalid);
            };
            if consumed_at.is_some() {
                transaction.execute(
                    "UPDATE sessions SET revoked_at=COALESCE(revoked_at,?) WHERE realm_id=? AND id=?",
                    params![ts(now),realm_id.to_string(),session_id.to_string()],
                ).map_err(storage)?;
                reuse_event.user_id = session.user_id;
                insert_event(&transaction, &reuse_event)?;
                transaction.commit().map_err(storage)?;
                return Ok(RefreshRotation::Reused);
            }
            if session.revoked_at.is_some() {
                return Ok(RefreshRotation::Revoked);
            }
            if parse_ts(&refresh_expiry)? <= now || session.expires_at <= now {
                return Ok(RefreshRotation::Expired);
            }
            let changed = transaction.execute(
                "UPDATE refresh_tokens SET consumed_at=? WHERE realm_id=? AND digest=? AND consumed_at IS NULL",
                params![ts(now),realm_id.to_string(),presented.as_bytes().as_slice()],
            ).map_err(storage)?;
            if changed != 1 {
                return Err(AuthError::storage_unavailable());
            }
            transaction.execute(
                "INSERT INTO refresh_tokens(realm_id,digest,session_id,family_id,expires_at,consumed_at) VALUES(?,?,?,?,?,NULL)",
                params![realm_id.to_string(),replacement.as_bytes().as_slice(),session_id.to_string(),family_id.to_string(),ts(session.expires_at)],
            ).map_err(storage)?;
            insert_access(&transaction, realm_id, session_id, &access)?;
            transaction.execute(
                "UPDATE sessions SET last_seen_at=? WHERE realm_id=? AND id=?",
                params![ts(now),realm_id.to_string(),session_id.to_string()],
            ).map_err(storage)?;
            transaction.commit().map_err(storage)?;
            session.last_seen_at = now;
            Ok(RefreshRotation::Rotated(session))
        }).await
    }

    async fn revoke_session(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        session_id: SessionId,
        now: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let changed = transaction.execute(
                "UPDATE sessions SET revoked_at=COALESCE(revoked_at,?) WHERE realm_id=? AND id=? AND user_id=?",
                params![ts(now),realm_id.to_string(),session_id.to_string(),user_id.to_string()],
            ).map_err(storage)?;
            if changed == 1 {
                insert_audit(&transaction, &audit)?;
            }
            transaction.commit().map_err(storage)?;
            Ok(changed == 1)
        }).await
    }

    async fn revoke_all_sessions(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        now: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<u64, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let changed = transaction.execute(
                "UPDATE sessions SET revoked_at=? WHERE realm_id=? AND user_id=? AND revoked_at IS NULL",
                params![ts(now),realm_id.to_string(),user_id.to_string()],
            ).map_err(storage)?;
            if changed > 0 {
                insert_audit(&transaction, &audit)?;
            }
            transaction.commit().map_err(storage)?;
            u64::try_from(changed).map_err(|_| AuthError::storage_unavailable())
        }).await
    }

    async fn list_sessions(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Session>, AuthError> {
        self.run(move |connection| {
            let mut statement = connection.prepare(
                "SELECT id,user_id,device_name,network_hash,user_agent,authentication_method,second_factor_verified_at,created_at,last_seen_at,expires_at,revoked_at FROM sessions WHERE realm_id=? AND user_id=? ORDER BY created_at DESC",
            ).map_err(storage)?;
            let rows = statement.query_map(params![realm_id.to_string(),user_id.to_string()], |row| stored_session(row,realm_id)).map_err(storage)?;
            let mut sessions = Vec::new();
            for row in rows {
                sessions.push(row.map_err(storage)??);
            }
            Ok(sessions)
        }).await
    }
}

#[async_trait]
impl ChallengeStore for SqliteAuthStore {
    async fn replace_challenge(
        &self,
        realm_id: RealmId,
        challenge: OneTimeChallenge,
        event: AuthEvent,
    ) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            transaction.execute(
                "DELETE FROM challenges WHERE realm_id=? AND user_id=? AND kind=? AND consumed_at IS NULL",
                params![realm_id.to_string(),challenge.user_id.to_string(),challenge_name(challenge.kind)],
            ).map_err(storage)?;
            insert_challenge(&transaction, realm_id, &challenge)?;
            insert_event(&transaction, &event)?;
            transaction.commit().map_err(storage)
        }).await
    }

    async fn consume_email_verification(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
        mut audit: AuditRecord,
    ) -> Result<OneTimeOutcome, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let outcome = challenge_outcome(&transaction,realm_id,digest,ChallengeKind::EmailVerification,now)?;
            let OneTimeOutcome::Consumed(user_id) = outcome else { return Ok(outcome); };
            let changed = transaction.execute(
                "UPDATE challenges SET consumed_at=? WHERE realm_id=? AND digest=? AND kind=? AND consumed_at IS NULL",
                params![ts(now),realm_id.to_string(),digest.as_bytes().as_slice(),challenge_name(ChallengeKind::EmailVerification)],
            ).map_err(storage)?;
            if changed != 1 { return Err(AuthError::storage_unavailable()); }
            transaction.execute(
                "UPDATE users SET email_verified=1,updated_at=? WHERE realm_id=? AND id=?",
                params![ts(now),realm_id.to_string(),user_id.to_string()],
            ).map_err(storage)?;
            audit.subject_user_id = Some(user_id);
            insert_audit(&transaction, &audit)?;
            transaction.commit().map_err(storage)?;
            Ok(OneTimeOutcome::Consumed(user_id))
        }).await
    }

    async fn reset_password(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        new_password_hash: String,
        now: DateTime<Utc>,
        mut event: AuthEvent,
    ) -> Result<OneTimeOutcome, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let outcome = challenge_outcome(&transaction,realm_id,digest,ChallengeKind::PasswordReset,now)?;
            let OneTimeOutcome::Consumed(user_id) = outcome else { return Ok(outcome); };
            let changed = transaction.execute(
                "UPDATE challenges SET consumed_at=? WHERE realm_id=? AND digest=? AND kind=? AND consumed_at IS NULL",
                params![ts(now),realm_id.to_string(),digest.as_bytes().as_slice(),challenge_name(ChallengeKind::PasswordReset)],
            ).map_err(storage)?;
            if changed != 1 { return Err(AuthError::storage_unavailable()); }
            transaction.execute(
                "UPDATE users SET password_hash=?,updated_at=? WHERE realm_id=? AND id=?",
                params![new_password_hash,ts(now),realm_id.to_string(),user_id.to_string()],
            ).map_err(storage)?;
            transaction.execute(
                "UPDATE sessions SET revoked_at=? WHERE realm_id=? AND user_id=? AND revoked_at IS NULL",
                params![ts(now),realm_id.to_string(),user_id.to_string()],
            ).map_err(storage)?;
            transaction.execute(
                "UPDATE trusted_devices SET revoked_at=? WHERE realm_id=? AND user_id=? AND revoked_at IS NULL",
                params![ts(now),realm_id.to_string(),user_id.to_string()],
            ).map_err(storage)?;
            event.user_id = user_id;
            insert_event(&transaction,&event)?;
            transaction.commit().map_err(storage)?;
            Ok(OneTimeOutcome::Consumed(user_id))
        }).await
    }
}

#[async_trait]
impl RateLimitStore for SqliteAuthStore {
    async fn record_login_attempt(
        &self,
        realm_id: RealmId,
        subject: &str,
        network_hash: Option<&str>,
        now: DateTime<Utc>,
        policy: LoginAttemptPolicy,
    ) -> Result<AttemptDecision, AuthError> {
        let subject = subject.to_owned();
        let network_hash = network_hash.map(str::to_owned);
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let account = update_attempt(&transaction, realm_id, &subject, "account", now, policy)?;
            let network = network_hash
                .as_deref()
                .map(|network_hash| {
                    update_attempt(&transaction, realm_id, network_hash, "network", now, policy)
                })
                .transpose()?;
            transaction.commit().map_err(storage)?;
            Ok(network.map_or(account, |network| later_block(account, network)))
        })
        .await
    }

    async fn clear_login_attempts(
        &self,
        realm_id: RealmId,
        subject: &str,
    ) -> Result<(), AuthError> {
        let subject = subject.to_owned();
        self.run(move |connection| {
            connection
                .execute(
                    "DELETE FROM login_attempts WHERE realm_id=? AND subject=? AND scope='account'",
                    params![realm_id.to_string(), subject],
                )
                .map(|_| ())
                .map_err(storage)
        })
        .await
    }
}

#[async_trait]
impl EventStore for SqliteAuthStore {
    async fn pending_events(&self, limit: u32) -> Result<Vec<AuthEvent>, AuthError> {
        self.run(move |connection| {
            let mut statement = connection.prepare(
                "SELECT id,realm_id,user_id,kind,payload,created_at FROM outbox WHERE delivered_at IS NULL AND claim_id IS NULL ORDER BY created_at,id LIMIT ?",
            ).map_err(storage)?;
            let rows = statement.query_map(params![i64::from(limit)], stored_event).map_err(storage)?;
            let mut events = Vec::new();
            for row in rows { events.push(row.map_err(storage)??); }
            Ok(events)
        }).await
    }

    async fn acknowledge_event(
        &self,
        event_id: EventId,
        delivered_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        self.run(move |connection| {
            connection
                .execute(
                    "UPDATE outbox SET delivered_at=?,claim_id=NULL,consumer_id=NULL,lease_expires_at=NULL WHERE id=? AND delivered_at IS NULL AND (claim_id IS NULL OR lease_expires_at<=?)",
                    params![ts(delivered_at), event_id.to_string(), ts(delivered_at)],
                )
                .map(|changed| changed == 1)
                .map_err(storage)
        })
        .await
    }
}

#[async_trait]
impl LeasedEventStore for SqliteAuthStore {
    async fn claim_events(
        &self,
        request: ClaimEventsRequest,
        claim_id: OutboxClaimId,
        now: DateTime<Utc>,
    ) -> Result<Vec<ClaimedEvent>, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let events = {
                let mut statement = transaction
                    .prepare(
                        "SELECT id,realm_id,user_id,kind,payload,created_at FROM outbox WHERE delivered_at IS NULL AND (claim_id IS NULL OR lease_expires_at<=?) ORDER BY created_at,id LIMIT ?",
                    )
                    .map_err(storage)?;
                let rows = statement
                    .query_map(params![ts(now), i64::from(request.limit)], stored_event)
                    .map_err(storage)?;
                let mut events = Vec::new();
                for row in rows {
                    events.push(row.map_err(storage)??);
                }
                events
            };
            let lease_expires_at = now + request.lease_duration;
            for event in &events {
                transaction
                    .execute(
                        "UPDATE outbox SET claim_id=?,consumer_id=?,lease_expires_at=? WHERE id=? AND delivered_at IS NULL AND (claim_id IS NULL OR lease_expires_at<=?)",
                        params![
                            claim_id.to_string(),
                            request.consumer_id,
                            ts(lease_expires_at),
                            event.id.to_string(),
                            ts(now),
                        ],
                    )
                    .map_err(storage)?;
            }
            transaction.commit().map_err(storage)?;
            Ok(events
                .into_iter()
                .map(|event| ClaimedEvent {
                    event,
                    claim_id,
                    lease_expires_at,
                })
                .collect())
        })
        .await
    }

    async fn acknowledge_claim(
        &self,
        event_id: EventId,
        claim_id: OutboxClaimId,
        delivered_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        self.run(move |connection| {
            connection
                .execute(
                    "UPDATE outbox SET delivered_at=?,claim_id=NULL,consumer_id=NULL,lease_expires_at=NULL WHERE id=? AND claim_id=? AND delivered_at IS NULL AND lease_expires_at>?",
                    params![
                        ts(delivered_at),
                        event_id.to_string(),
                        claim_id.to_string(),
                        ts(delivered_at),
                    ],
                )
                .map(|changed| changed == 1)
                .map_err(storage)
        })
        .await
    }

    async fn release_claim(&self, claim_id: OutboxClaimId) -> Result<u64, AuthError> {
        self.run(move |connection| {
            connection
                .execute(
                    "UPDATE outbox SET claim_id=NULL,consumer_id=NULL,lease_expires_at=NULL WHERE claim_id=? AND delivered_at IS NULL",
                    params![claim_id.to_string()],
                )
                .map(|changed| changed as u64)
                .map_err(storage)
        })
        .await
    }
}

#[async_trait]
impl AuditStore for SqliteAuthStore {
    async fn list_audit_records(
        &self,
        realm_id: RealmId,
        before: Option<DateTime<Utc>>,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, AuthError> {
        self.run(move |connection| {
            let mut records = Vec::new();
            if let Some(before) = before {
                let mut statement = connection.prepare(
                    "SELECT id,realm_id,actor_kind,actor_user_id,subject_user_id,kind,outcome,metadata_json,occurred_at,outbox_event_id FROM audit_log WHERE realm_id=? AND occurred_at<? ORDER BY occurred_at DESC,id DESC LIMIT ?",
                ).map_err(storage)?;
                let rows = statement
                    .query_map(
                        params![realm_id.to_string(), ts(before), i64::from(limit)],
                        stored_audit_record,
                    )
                    .map_err(storage)?;
                for row in rows {
                    records.push(row.map_err(storage)??);
                }
            } else {
                let mut statement = connection.prepare(
                    "SELECT id,realm_id,actor_kind,actor_user_id,subject_user_id,kind,outcome,metadata_json,occurred_at,outbox_event_id FROM audit_log WHERE realm_id=? ORDER BY occurred_at DESC,id DESC LIMIT ?",
                ).map_err(storage)?;
                let rows = statement
                    .query_map(
                        params![realm_id.to_string(), i64::from(limit)],
                        stored_audit_record,
                    )
                    .map_err(storage)?;
                for row in rows {
                    records.push(row.map_err(storage)??);
                }
            }
            Ok(records)
        })
        .await
    }
}

#[async_trait]
impl MfaStore for SqliteAuthStore {
    async fn find_totp_factor(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Option<StoredTotpFactor>, AuthError> {
        self.run(move |connection| {
            let nested = connection
                .query_row(
                    "SELECT id,format_version,algorithm,key_id,nonce,ciphertext,last_accepted_counter,created_at,updated_at FROM mfa_totp_factors WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                    |row| stored_factor(row, realm_id, user_id),
                )
                .optional()
                .map_err(storage)?;
            nested.transpose()
        })
        .await
    }

    async fn replace_totp_enrollment(
        &self,
        enrollment: PendingTotpEnrollment,
    ) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let has_factor: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM mfa_totp_factors WHERE realm_id=? AND user_id=?)",
                    params![
                        enrollment.realm_id.to_string(),
                        enrollment.user_id.to_string()
                    ],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if has_factor != enrollment.replacing {
                return Err(AuthError::new(
                    ErrorCode::Conflict,
                    "MFA enrollment conflicts with current factor state",
                    false,
                ));
            }
            transaction
                .execute(
                    "DELETE FROM mfa_enrollments WHERE realm_id=? AND user_id=?",
                    params![
                        enrollment.realm_id.to_string(),
                        enrollment.user_id.to_string()
                    ],
                )
                .map_err(storage)?;
            insert_enrollment(&transaction, &enrollment)?;
            transaction.commit().map_err(storage)
        })
        .await
    }

    async fn find_totp_enrollment(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
    ) -> Result<Option<PendingTotpEnrollment>, AuthError> {
        self.run(move |connection| {
            let nested = connection
                .query_row(
                    "SELECT id,format_version,algorithm,key_id,nonce,ciphertext,replacing,attempts,max_attempts,expires_at,created_at FROM mfa_enrollments WHERE realm_id=? AND user_id=? AND id=?",
                    params![realm_id.to_string(), user_id.to_string(), enrollment_id.to_string()],
                    |row| stored_enrollment(row, realm_id, user_id),
                )
                .optional()
                .map_err(storage)?;
            nested.transpose()
        })
        .await
    }

    async fn record_totp_enrollment_failure(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let row = transaction
                .query_row(
                    "SELECT attempts,max_attempts,expires_at FROM mfa_enrollments WHERE realm_id=? AND user_id=? AND id=?",
                    params![realm_id.to_string(), user_id.to_string(), enrollment_id.to_string()],
                    |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?, row.get::<_, String>(2)?)),
                )
                .optional()
                .map_err(storage)?;
            let Some((attempts, max_attempts, expires_at)) = row else {
                return Ok(AttemptDecision::BlockedUntil(now));
            };
            let expires_at = parse_ts(&expires_at)?;
            if expires_at <= now {
                return Ok(AttemptDecision::BlockedUntil(now));
            }
            let attempts = attempts.saturating_add(1);
            transaction
                .execute(
                    "UPDATE mfa_enrollments SET attempts=? WHERE realm_id=? AND user_id=? AND id=?",
                    params![attempts, realm_id.to_string(), user_id.to_string(), enrollment_id.to_string()],
                )
                .map_err(storage)?;
            transaction.commit().map_err(storage)?;
            if attempts >= max_attempts {
                Ok(AttemptDecision::BlockedUntil(expires_at))
            } else {
                Ok(AttemptDecision::Allowed)
            }
        })
        .await
    }

    async fn activate_totp(
        &self,
        command: ActivateTotp,
    ) -> Result<MfaEnrollmentOutcome, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let realm_id = command.factor.realm_id;
            let user_id = command.factor.user_id;
            let nested = transaction
                .query_row(
                    "SELECT id,format_version,algorithm,key_id,nonce,ciphertext,replacing,attempts,max_attempts,expires_at,created_at FROM mfa_enrollments WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                    |row| stored_enrollment(row, realm_id, user_id),
                )
                .optional()
                .map_err(storage)?;
            let Some(enrollment) = nested.transpose()? else {
                return Ok(MfaEnrollmentOutcome::Invalid);
            };
            let has_factor: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM mfa_totp_factors WHERE realm_id=? AND user_id=?)",
                    params![realm_id.to_string(), user_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if enrollment.id != command.enrollment_id || enrollment.replacing != has_factor {
                return Ok(MfaEnrollmentOutcome::Invalid);
            }
            if enrollment.expires_at <= command.now {
                return Ok(MfaEnrollmentOutcome::Expired);
            }
            if enrollment.attempts >= enrollment.max_attempts {
                return Ok(MfaEnrollmentOutcome::RateLimited);
            }
            let current_session: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sessions WHERE realm_id=? AND id=? AND user_id=? AND revoked_at IS NULL AND expires_at>?)",
                    params![realm_id.to_string(), command.current_session_id.to_string(), user_id.to_string(), ts(command.now)],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if !current_session {
                return Ok(MfaEnrollmentOutcome::Invalid);
            }
            transaction
                .execute(
                    "UPDATE sessions SET authentication_method='password_totp',second_factor_verified_at=? WHERE realm_id=? AND id=?",
                    params![ts(command.now), realm_id.to_string(), command.current_session_id.to_string()],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "UPDATE sessions SET revoked_at=? WHERE realm_id=? AND user_id=? AND id<>? AND revoked_at IS NULL",
                    params![ts(command.now), realm_id.to_string(), user_id.to_string(), command.current_session_id.to_string()],
                )
                .map_err(storage)?;
            revoke_trusted_devices(&transaction, realm_id, user_id, command.now)?;
            transaction
                .execute(
                    "DELETE FROM mfa_recovery_codes WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                )
                .map_err(storage)?;
            for digest in &command.recovery_digests {
                insert_recovery_code(&transaction, realm_id, user_id, *digest, command.now)?;
            }
            transaction
                .execute(
                    "DELETE FROM mfa_totp_factors WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                )
                .map_err(storage)?;
            insert_factor(&transaction, &command.factor)?;
            transaction
                .execute(
                    "DELETE FROM mfa_enrollments WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                )
                .map_err(storage)?;
            if let Some(trusted) = &command.trusted_device {
                insert_trusted_device(&transaction, trusted)?;
            }
            insert_events(&transaction, &command.events)?;
            transaction.commit().map_err(storage)?;
            Ok(MfaEnrollmentOutcome::Activated)
        })
        .await
    }

    async fn create_mfa_login_challenge(
        &self,
        challenge: StoredMfaLoginChallenge,
    ) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            transaction
                .execute(
                    "DELETE FROM mfa_login_challenges WHERE realm_id=? AND user_id=? AND consumed_at IS NULL",
                    params![challenge.realm_id.to_string(), challenge.user_id.to_string()],
                )
                .map_err(storage)?;
            insert_mfa_challenge(&transaction, &challenge)?;
            transaction.commit().map_err(storage)
        })
        .await
    }

    async fn load_mfa_login_challenge(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<MfaChallengeLookup, AuthError> {
        self.run(move |connection| {
            let nested = connection
                .query_row(
                    "SELECT user_id,device_name,network_hash,user_agent,remember_me,attempts,max_attempts,expires_at,created_at,consumed_at FROM mfa_login_challenges WHERE realm_id=? AND digest=?",
                    params![realm_id.to_string(), digest.as_bytes().as_slice()],
                    |row| stored_mfa_challenge(row, realm_id, digest),
                )
                .optional()
                .map_err(storage)?;
            let Some(stored) = nested.transpose()? else {
                return Ok(MfaChallengeLookup::Invalid);
            };
            if stored.consumed_at.is_some() {
                return Ok(MfaChallengeLookup::Invalid);
            }
            let challenge = stored.challenge;
            if challenge.expires_at <= now {
                return Ok(MfaChallengeLookup::Expired);
            }
            if challenge.attempts >= challenge.max_attempts {
                return Ok(MfaChallengeLookup::RateLimited);
            }
            let nested = connection
                .query_row(
                    "SELECT id,format_version,algorithm,key_id,nonce,ciphertext,last_accepted_counter,created_at,updated_at FROM mfa_totp_factors WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), challenge.user_id.to_string()],
                    |row| stored_factor(row, realm_id, challenge.user_id),
                )
                .optional()
                .map_err(storage)?;
            let Some(factor) = nested.transpose()? else {
                return Ok(MfaChallengeLookup::Invalid);
            };
            Ok(MfaChallengeLookup::Active {
                challenge: Box::new(challenge),
                factor: Box::new(factor),
            })
        })
        .await
    }

    async fn record_mfa_login_failure(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let row = transaction
                .query_row(
                    "SELECT attempts,max_attempts,expires_at,consumed_at FROM mfa_login_challenges WHERE realm_id=? AND digest=?",
                    params![realm_id.to_string(), digest.as_bytes().as_slice()],
                    |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?)),
                )
                .optional()
                .map_err(storage)?;
            let Some((attempts, max_attempts, expires_at, consumed_at)) = row else {
                return Ok(AttemptDecision::BlockedUntil(now));
            };
            let expires_at = parse_ts(&expires_at)?;
            if consumed_at.is_some() || expires_at <= now {
                return Ok(AttemptDecision::BlockedUntil(now));
            }
            let attempts = attempts.saturating_add(1);
            transaction
                .execute(
                    "UPDATE mfa_login_challenges SET attempts=? WHERE realm_id=? AND digest=?",
                    params![attempts, realm_id.to_string(), digest.as_bytes().as_slice()],
                )
                .map_err(storage)?;
            transaction.commit().map_err(storage)?;
            if attempts >= max_attempts {
                Ok(AttemptDecision::BlockedUntil(expires_at))
            } else {
                Ok(AttemptDecision::Allowed)
            }
        })
        .await
    }

    async fn complete_mfa_login(
        &self,
        command: CompleteMfaLogin,
    ) -> Result<MfaCompletionOutcome, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let realm_id = command.session.session.realm_id;
            let user_id = command.session.session.user_id;
            let row = transaction
                .query_row(
                    "SELECT user_id,attempts,max_attempts,expires_at,consumed_at FROM mfa_login_challenges WHERE realm_id=? AND digest=?",
                    params![realm_id.to_string(), command.challenge_digest.as_bytes().as_slice()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?, row.get::<_, u32>(2)?, row.get::<_, String>(3)?, row.get::<_, Option<String>>(4)?)),
                )
                .optional()
                .map_err(storage)?;
            let Some((challenge_user, attempts, max_attempts, expires_at, consumed_at)) = row else {
                return Ok(MfaCompletionOutcome::Invalid);
            };
            if UserId::parse(&challenge_user)? != user_id {
                return Ok(MfaCompletionOutcome::Invalid);
            }
            if consumed_at.is_some() {
                return Ok(MfaCompletionOutcome::Reused);
            }
            if parse_ts(&expires_at)? <= command.now {
                return Ok(MfaCompletionOutcome::Expired);
            }
            if attempts >= max_attempts {
                return Ok(MfaCompletionOutcome::RateLimited);
            }
            match command.proof {
                VerifiedMfaProof::Totp { factor_id, counter } => {
                    let row = transaction
                        .query_row(
                            "SELECT id,last_accepted_counter FROM mfa_totp_factors WHERE realm_id=? AND user_id=?",
                            params![realm_id.to_string(), user_id.to_string()],
                            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
                        )
                        .optional()
                        .map_err(storage)?;
                    let Some((stored_id, last_counter)) = row else {
                        return Ok(MfaCompletionOutcome::Invalid);
                    };
                    if MfaFactorId::parse(&stored_id)? != factor_id {
                        return Ok(MfaCompletionOutcome::Invalid);
                    }
                    let counter = counter_to_sql(counter)?;
                    if last_counter.is_some_and(|last| counter <= last) {
                        return Ok(MfaCompletionOutcome::Reused);
                    }
                    transaction
                        .execute(
                            "UPDATE mfa_totp_factors SET last_accepted_counter=?,updated_at=? WHERE realm_id=? AND user_id=? AND id=?",
                            params![counter, ts(command.now), realm_id.to_string(), user_id.to_string(), factor_id.to_string()],
                        )
                        .map_err(storage)?;
                }
                VerifiedMfaProof::RecoveryCode(digest) => {
                    let consumed_at = transaction
                        .query_row(
                            "SELECT consumed_at FROM mfa_recovery_codes WHERE realm_id=? AND user_id=? AND digest=?",
                            params![realm_id.to_string(), user_id.to_string(), digest.as_bytes().as_slice()],
                            |row| row.get::<_, Option<String>>(0),
                        )
                        .optional()
                        .map_err(storage)?;
                    let Some(consumed_at) = consumed_at else {
                        return Ok(MfaCompletionOutcome::Invalid);
                    };
                    if consumed_at.is_some() {
                        return Ok(MfaCompletionOutcome::Reused);
                    }
                    transaction
                        .execute(
                            "UPDATE mfa_recovery_codes SET consumed_at=? WHERE realm_id=? AND user_id=? AND digest=? AND consumed_at IS NULL",
                            params![ts(command.now), realm_id.to_string(), user_id.to_string(), digest.as_bytes().as_slice()],
                        )
                        .map_err(storage)?;
                }
            }
            let consumed = transaction
                .execute(
                    "UPDATE mfa_login_challenges SET consumed_at=? WHERE realm_id=? AND digest=? AND consumed_at IS NULL",
                    params![ts(command.now), realm_id.to_string(), command.challenge_digest.as_bytes().as_slice()],
                )
                .map_err(storage)?;
            if consumed != 1 {
                return Ok(MfaCompletionOutcome::Reused);
            }
            insert_session(&transaction, &command.session)?;
            let trusted_device = command.trusted_device.as_ref().map(|trusted| {
                insert_trusted_device(&transaction, trusted)?;
                Ok::<_, AuthError>(trusted.device.clone())
            }).transpose()?;
            insert_events(&transaction, &command.events)?;
            let session = command.session.session.clone();
            transaction.commit().map_err(storage)?;
            Ok(MfaCompletionOutcome::Completed {
                session: Box::new(session),
                trusted_device: trusted_device.map(Box::new),
            })
        })
        .await
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
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let nested = transaction
                .query_row(
                    "SELECT d.id,d.user_id,d.device_name,d.network_hash,d.user_agent,d.created_at,d.last_used_at,d.expires_at,d.revoked_at,t.expires_at,t.consumed_at FROM trusted_device_tokens t JOIN trusted_devices d ON d.realm_id=t.realm_id AND d.id=t.device_id WHERE t.realm_id=? AND t.digest=?",
                    params![realm_id.to_string(), presented.as_bytes().as_slice()],
                    |row| stored_trusted_token(row, realm_id),
                )
                .optional()
                .map_err(storage)?;
            let Some(stored) = nested.transpose()? else {
                return Ok(TrustedLoginOutcome::Invalid);
            };
            let mut device = stored.device;
            if stored.consumed_at.is_some() {
                transaction
                    .execute(
                        "UPDATE trusted_devices SET revoked_at=COALESCE(revoked_at,?) WHERE realm_id=? AND id=?",
                        params![ts(now), realm_id.to_string(), device.id.to_string()],
                    )
                    .map_err(storage)?;
                replay_event.user_id = device.user_id;
                insert_event(&transaction, &replay_event)?;
                transaction.commit().map_err(storage)?;
                return Ok(TrustedLoginOutcome::Reused);
            }
            if device.user_id != user_id
                || device.revoked_at.is_some()
                || device.expires_at <= now
                || stored.token_expires_at <= now
            {
                return Ok(TrustedLoginOutcome::Invalid);
            }
            let changed = transaction
                .execute(
                    "UPDATE trusted_device_tokens SET consumed_at=? WHERE realm_id=? AND digest=? AND consumed_at IS NULL",
                    params![ts(now), realm_id.to_string(), presented.as_bytes().as_slice()],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Ok(TrustedLoginOutcome::Reused);
            }
            transaction
                .execute(
                    "INSERT INTO trusted_device_tokens(realm_id,digest,device_id,expires_at,consumed_at) VALUES(?,?,?,?,NULL)",
                    params![realm_id.to_string(), replacement.as_bytes().as_slice(), device.id.to_string(), ts(device.expires_at)],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "UPDATE trusted_devices SET last_used_at=? WHERE realm_id=? AND id=?",
                    params![ts(now), realm_id.to_string(), device.id.to_string()],
                )
                .map_err(storage)?;
            device.last_used_at = now;
            let created_session = session.session.clone();
            insert_session(&transaction, &session)?;
            transaction.commit().map_err(storage)?;
            Ok(TrustedLoginOutcome::Authenticated {
                session: Box::new(created_session),
                trusted_device: Box::new(device),
            })
        })
        .await
    }

    async fn accept_management_totp(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        factor_id: MfaFactorId,
        counter: u64,
    ) -> Result<bool, AuthError> {
        self.run(move |connection| {
            connection
                .execute(
                    "UPDATE mfa_totp_factors SET last_accepted_counter=? WHERE realm_id=? AND user_id=? AND id=? AND (last_accepted_counter IS NULL OR last_accepted_counter<?)",
                    params![counter_to_sql(counter)?, realm_id.to_string(), user_id.to_string(), factor_id.to_string(), counter_to_sql(counter)?],
                )
                .map(|changed| changed == 1)
                .map_err(storage)
        })
        .await
    }

    async fn consume_management_recovery(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        digest: TokenDigest,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let changed = transaction
                .execute(
                    "UPDATE mfa_recovery_codes SET consumed_at=? WHERE realm_id=? AND user_id=? AND digest=? AND consumed_at IS NULL",
                    params![ts(event.created_at), realm_id.to_string(), user_id.to_string(), digest.as_bytes().as_slice()],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Ok(false);
            }
            insert_event(&transaction, &event)?;
            transaction.commit().map_err(storage)?;
            Ok(true)
        })
        .await
    }

    async fn replace_recovery_codes(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        digests: Vec<TokenDigest>,
        event: AuthEvent,
    ) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let has_factor: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM mfa_totp_factors WHERE realm_id=? AND user_id=?)",
                    params![realm_id.to_string(), user_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if !has_factor {
                return Err(AuthError::new(
                    ErrorCode::MfaNotEnrolled,
                    "MFA is not enrolled",
                    false,
                ));
            }
            transaction
                .execute(
                    "DELETE FROM mfa_recovery_codes WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                )
                .map_err(storage)?;
            for digest in digests {
                insert_recovery_code(&transaction, realm_id, user_id, digest, event.created_at)?;
            }
            insert_event(&transaction, &event)?;
            transaction.commit().map_err(storage)
        })
        .await
    }

    async fn disable_mfa(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let changed = transaction
                .execute(
                    "DELETE FROM mfa_totp_factors WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Ok(false);
            }
            transaction
                .execute(
                    "DELETE FROM mfa_enrollments WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "DELETE FROM mfa_recovery_codes WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "DELETE FROM mfa_login_challenges WHERE realm_id=? AND user_id=?",
                    params![realm_id.to_string(), user_id.to_string()],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "UPDATE sessions SET revoked_at=? WHERE realm_id=? AND user_id=? AND revoked_at IS NULL",
                    params![ts(now), realm_id.to_string(), user_id.to_string()],
                )
                .map_err(storage)?;
            revoke_trusted_devices(&transaction, realm_id, user_id, now)?;
            insert_event(&transaction, &event)?;
            transaction.commit().map_err(storage)?;
            Ok(true)
        })
        .await
    }

    async fn list_trusted_devices(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<TrustedDevice>, AuthError> {
        self.run(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT id,user_id,device_name,network_hash,user_agent,created_at,last_used_at,expires_at,revoked_at FROM trusted_devices WHERE realm_id=? AND user_id=? ORDER BY created_at DESC",
                )
                .map_err(storage)?;
            let rows = statement
                .query_map(params![realm_id.to_string(), user_id.to_string()], |row| {
                    stored_trusted_device(row, realm_id)
                })
                .map_err(storage)?;
            let mut devices = Vec::new();
            for row in rows {
                devices.push(row.map_err(storage)??);
            }
            Ok(devices)
        })
        .await
    }

    async fn revoke_trusted_device(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        trusted_device_id: TrustedDeviceId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let row = transaction
                .query_row(
                    "SELECT user_id,revoked_at FROM trusted_devices WHERE realm_id=? AND id=?",
                    params![realm_id.to_string(), trusted_device_id.to_string()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()
                .map_err(storage)?;
            let Some((stored_user, revoked_at)) = row else {
                return Ok(false);
            };
            if UserId::parse(&stored_user)? != user_id {
                return Ok(false);
            }
            if revoked_at.is_none() {
                transaction
                    .execute(
                        "UPDATE trusted_devices SET revoked_at=? WHERE realm_id=? AND id=? AND revoked_at IS NULL",
                        params![ts(now), realm_id.to_string(), trusted_device_id.to_string()],
                    )
                    .map_err(storage)?;
                insert_event(&transaction, &event)?;
            }
            transaction.commit().map_err(storage)?;
            Ok(true)
        })
        .await
    }

    async fn factors_needing_rewrap(
        &self,
        realm_id: RealmId,
        active_key_id: &str,
        limit: u32,
    ) -> Result<Vec<StoredTotpFactor>, AuthError> {
        let active_key_id = active_key_id.to_owned();
        self.run(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT id,user_id,format_version,algorithm,key_id,nonce,ciphertext,last_accepted_counter,created_at,updated_at FROM mfa_totp_factors WHERE realm_id=? AND key_id<>? ORDER BY updated_at LIMIT ?",
                )
                .map_err(storage)?;
            let rows = statement
                .query_map(
                    params![realm_id.to_string(), active_key_id, i64::from(limit)],
                    |row| stored_factor_with_user(row, realm_id),
                )
                .map_err(storage)?;
            let mut factors = Vec::new();
            for row in rows {
                factors.push(row.map_err(storage)??);
            }
            Ok(factors)
        })
        .await
    }

    async fn update_rewrapped_factor(
        &self,
        factor: StoredTotpFactor,
        expected_key_id: &str,
    ) -> Result<bool, AuthError> {
        let expected_key_id = expected_key_id.to_owned();
        self.run(move |connection| {
            connection
                .execute(
                    "UPDATE mfa_totp_factors SET format_version=?,algorithm=?,key_id=?,nonce=?,ciphertext=?,last_accepted_counter=?,updated_at=? WHERE realm_id=? AND user_id=? AND id=? AND key_id=?",
                    params![factor.sealed_seed.format_version(), factor.sealed_seed.algorithm().as_str(), factor.sealed_seed.key_id(), factor.sealed_seed.nonce().as_slice(), factor.sealed_seed.ciphertext(), factor.last_accepted_counter.map(counter_to_sql).transpose()?, ts(factor.updated_at), factor.realm_id.to_string(), factor.user_id.to_string(), factor.id.to_string(), expected_key_id],
                )
                .map(|changed| changed == 1)
                .map_err(storage)
        })
        .await
    }
}

#[async_trait]
impl PasskeyStore for SqliteAuthStore {
    async fn replace_passkey_registration(
        &self,
        ceremony: PendingPasskeyCeremony,
    ) -> Result<(), AuthError> {
        self.run(move |connection| {
            if ceremony.kind != PasskeyCeremonyKind::Registration || ceremony.session_id.is_none() {
                return Err(AuthError::invalid_input());
            }
            let transaction = immediate(connection)?;
            transaction
                .execute(
                    "DELETE FROM passkey_ceremonies WHERE expires_at<=?",
                    params![ts(ceremony.created_at)],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "DELETE FROM passkey_ceremonies WHERE realm_id=? AND user_id=? AND session_id=? AND kind='registration' AND consumed_at IS NULL",
                    params![
                        ceremony.realm_id.to_string(),
                        ceremony.user_id.to_string(),
                        ceremony.session_id.map(|value| value.to_string()),
                    ],
                )
                .map_err(storage)?;
            insert_passkey_ceremony(&transaction, &ceremony)?;
            transaction.commit().map_err(storage)
        })
        .await
    }

    async fn create_passkey_authentication(
        &self,
        ceremony: PendingPasskeyCeremony,
    ) -> Result<(), AuthError> {
        self.run(move |connection| {
            if ceremony.kind != PasskeyCeremonyKind::Authentication || ceremony.session_id.is_some()
            {
                return Err(AuthError::invalid_input());
            }
            let transaction = immediate(connection)?;
            transaction
                .execute(
                    "DELETE FROM passkey_ceremonies WHERE expires_at<=?",
                    params![ts(ceremony.created_at)],
                )
                .map_err(storage)?;
            insert_passkey_ceremony(&transaction, &ceremony)?;
            transaction.commit().map_err(storage)
        })
        .await
    }

    async fn load_passkey_ceremony(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        kind: PasskeyCeremonyKind,
        now: DateTime<Utc>,
    ) -> Result<PasskeyCeremonyLookup, AuthError> {
        self.run(move |connection| {
            let nested = connection
                .query_row(
                    "SELECT user_id,session_id,kind,label,login_subject,device_name,network_hash,user_agent,remember_me,provider_id,state_format,state_blob,attempts,max_attempts,expires_at,created_at,consumed_at FROM passkey_ceremonies WHERE realm_id=? AND digest=?",
                    params![realm_id.to_string(), digest.as_bytes().as_slice()],
                    |row| stored_passkey_ceremony(row, realm_id, digest),
                )
                .optional()
                .map_err(storage)?;
            let Some(row) = nested.transpose()? else {
                return Ok(PasskeyCeremonyLookup::Invalid);
            };
            passkey_ceremony_lookup(row, kind, now)
        })
        .await
    }

    async fn record_passkey_failure(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            transaction
                .execute(
                    "UPDATE passkey_ceremonies SET attempts=attempts+1 WHERE realm_id=? AND digest=? AND consumed_at IS NULL AND expires_at>? AND attempts<max_attempts",
                    params![realm_id.to_string(), digest.as_bytes().as_slice(), ts(now)],
                )
                .map_err(storage)?;
            let value = transaction
                .query_row(
                    "SELECT attempts,max_attempts,expires_at FROM passkey_ceremonies WHERE realm_id=? AND digest=?",
                    params![realm_id.to_string(), digest.as_bytes().as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, u32>(0)?,
                            row.get::<_, u32>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(storage)?;
            transaction.commit().map_err(storage)?;
            let Some((attempts, max_attempts, expires_at)) = value else {
                return Ok(AttemptDecision::Allowed);
            };
            if attempts >= max_attempts {
                Ok(AttemptDecision::BlockedUntil(parse_ts(&expires_at)?))
            } else {
                Ok(AttemptDecision::Allowed)
            }
        })
        .await
    }

    async fn list_stored_passkeys(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<StoredPasskey>, AuthError> {
        self.run(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT id,label,credential_id,provider_id,credential_format,credential_blob,signature_counter,backup_eligible,backed_up,created_at,last_used_at,revoked_at FROM passkey_credentials WHERE realm_id=? AND user_id=? AND revoked_at IS NULL ORDER BY created_at DESC",
                )
                .map_err(storage)?;
            collect_nested(
                statement
                    .query_map(params![realm_id.to_string(), user_id.to_string()], |row| {
                        stored_passkey(row, realm_id, user_id)
                    })
                    .map_err(storage)?,
            )
        })
        .await
    }

    async fn complete_passkey_registration(
        &self,
        command: CompletePasskeyRegistration,
    ) -> Result<PasskeyRegistrationOutcome, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let realm_id = command.credential.passkey.realm_id;
            let nested = transaction
                .query_row(
                    "SELECT user_id,session_id,kind,label,login_subject,device_name,network_hash,user_agent,remember_me,provider_id,state_format,state_blob,attempts,max_attempts,expires_at,created_at,consumed_at FROM passkey_ceremonies WHERE realm_id=? AND digest=?",
                    params![realm_id.to_string(), command.ceremony_digest.as_bytes().as_slice()],
                    |row| stored_passkey_ceremony(row, realm_id, command.ceremony_digest),
                )
                .optional()
                .map_err(storage)?;
            let Some(row) = nested.transpose()? else {
                return Ok(PasskeyRegistrationOutcome::Invalid);
            };
            if row.consumed_at.is_some() {
                return Ok(PasskeyRegistrationOutcome::Reused);
            }
            match passkey_ceremony_lookup(row.clone(), PasskeyCeremonyKind::Registration, command.now)? {
                PasskeyCeremonyLookup::Invalid => return Ok(PasskeyRegistrationOutcome::Invalid),
                PasskeyCeremonyLookup::Reused => return Ok(PasskeyRegistrationOutcome::Reused),
                PasskeyCeremonyLookup::Expired => return Ok(PasskeyRegistrationOutcome::Expired),
                PasskeyCeremonyLookup::RateLimited => return Ok(PasskeyRegistrationOutcome::RateLimited),
                PasskeyCeremonyLookup::Active(_) => {}
            }
            if row.ceremony.user_id != command.credential.passkey.user_id
                || row.ceremony.provider_id != command.credential.provider_id
            {
                return Ok(PasskeyRegistrationOutcome::Invalid);
            }
            let inserted = transaction.execute(
                "INSERT INTO passkey_credentials(realm_id,id,user_id,label,credential_id,provider_id,credential_format,credential_blob,signature_counter,backup_eligible,backed_up,created_at,last_used_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params![
                    realm_id.to_string(),
                    command.credential.passkey.id.to_string(),
                    command.credential.passkey.user_id.to_string(),
                    command.credential.passkey.label,
                    command.credential.credential_id,
                    command.credential.provider_id,
                    i64::from(command.credential.credential_format),
                    command.credential.credential_blob,
                    i64::from(command.credential.signature_counter),
                    i64::from(command.credential.passkey.backup_eligible),
                    i64::from(command.credential.passkey.backed_up),
                    ts(command.credential.passkey.created_at),
                    command.credential.passkey.last_used_at.map(ts),
                    command.credential.passkey.revoked_at.map(ts),
                ],
            );
            if let Err(error) = inserted {
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                    transaction.execute(
                        "UPDATE passkey_ceremonies SET consumed_at=? WHERE realm_id=? AND digest=? AND consumed_at IS NULL",
                        params![ts(command.now), realm_id.to_string(), command.ceremony_digest.as_bytes().as_slice()],
                    ).map_err(storage)?;
                    transaction.commit().map_err(storage)?;
                    return Ok(PasskeyRegistrationOutcome::Conflict);
                }
                return Err(storage(error));
            }
            transaction.execute(
                "UPDATE passkey_ceremonies SET consumed_at=? WHERE realm_id=? AND digest=? AND consumed_at IS NULL",
                params![ts(command.now), realm_id.to_string(), command.ceremony_digest.as_bytes().as_slice()],
            ).map_err(storage)?;
            insert_audit(&transaction, &command.audit)?;
            let public = command.credential.passkey;
            transaction.commit().map_err(storage)?;
            Ok(PasskeyRegistrationOutcome::Completed(Box::new(public)))
        })
        .await
    }

    async fn complete_passkey_authentication(
        &self,
        command: CompletePasskeyAuthentication,
    ) -> Result<PasskeyAuthenticationOutcome, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let realm_id = command.session.session.realm_id;
            let nested = transaction
                .query_row(
                    "SELECT user_id,session_id,kind,label,login_subject,device_name,network_hash,user_agent,remember_me,provider_id,state_format,state_blob,attempts,max_attempts,expires_at,created_at,consumed_at FROM passkey_ceremonies WHERE realm_id=? AND digest=?",
                    params![realm_id.to_string(), command.ceremony_digest.as_bytes().as_slice()],
                    |row| stored_passkey_ceremony(row, realm_id, command.ceremony_digest),
                )
                .optional()
                .map_err(storage)?;
            let Some(row) = nested.transpose()? else {
                return Ok(PasskeyAuthenticationOutcome::Invalid);
            };
            if row.consumed_at.is_some() {
                return Ok(PasskeyAuthenticationOutcome::Reused);
            }
            match passkey_ceremony_lookup(row.clone(), PasskeyCeremonyKind::Authentication, command.now)? {
                PasskeyCeremonyLookup::Invalid => return Ok(PasskeyAuthenticationOutcome::Invalid),
                PasskeyCeremonyLookup::Reused => return Ok(PasskeyAuthenticationOutcome::Reused),
                PasskeyCeremonyLookup::Expired => return Ok(PasskeyAuthenticationOutcome::Expired),
                PasskeyCeremonyLookup::RateLimited => return Ok(PasskeyAuthenticationOutcome::RateLimited),
                PasskeyCeremonyLookup::Active(_) => {}
            }
            if row.ceremony.user_id != command.session.session.user_id {
                return Ok(PasskeyAuthenticationOutcome::Invalid);
            }
            let credential = transaction
                .query_row(
                    "SELECT user_id,provider_id,credential_format,signature_counter,revoked_at FROM passkey_credentials WHERE realm_id=? AND id=?",
                    params![realm_id.to_string(), command.passkey_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(storage)?;
            let Some((user_id, provider_id, credential_format, old_counter, revoked_at)) = credential else {
                return Ok(PasskeyAuthenticationOutcome::Invalid);
            };
            if UserId::parse(&user_id)? != row.ceremony.user_id
                || revoked_at.is_some()
                || provider_id != command.provider_id
                || u16::try_from(credential_format).map_err(|_| AuthError::storage_unavailable())?
                    != command.credential_format
            {
                return Ok(PasskeyAuthenticationOutcome::Invalid);
            }
            let old_counter = u32::try_from(old_counter).map_err(|_| AuthError::storage_unavailable())?;
            if old_counter > 0
                && command.signature_counter > 0
                && command.signature_counter <= old_counter
            {
                transaction.execute(
                    "UPDATE passkey_credentials SET revoked_at=? WHERE realm_id=? AND id=? AND revoked_at IS NULL",
                    params![ts(command.now), realm_id.to_string(), command.passkey_id.to_string()],
                ).map_err(storage)?;
                transaction.execute(
                    "UPDATE passkey_ceremonies SET consumed_at=? WHERE realm_id=? AND digest=? AND consumed_at IS NULL",
                    params![ts(command.now), realm_id.to_string(), command.ceremony_digest.as_bytes().as_slice()],
                ).map_err(storage)?;
                insert_audit(&transaction, &command.clone_audit)?;
                transaction.commit().map_err(storage)?;
                return Ok(PasskeyAuthenticationOutcome::CloneSuspected);
            }
            transaction.execute(
                "UPDATE passkey_credentials SET credential_blob=?,signature_counter=?,backup_eligible=CASE WHEN backup_eligible=1 THEN 1 ELSE ? END,backed_up=?,last_used_at=? WHERE realm_id=? AND id=? AND revoked_at IS NULL",
                params![
                    command.credential_blob,
                    i64::from(old_counter.max(command.signature_counter)),
                    i64::from(command.backup_eligible),
                    i64::from(command.backed_up),
                    ts(command.now),
                    realm_id.to_string(),
                    command.passkey_id.to_string(),
                ],
            ).map_err(storage)?;
            let consumed = transaction.execute(
                "UPDATE passkey_ceremonies SET consumed_at=? WHERE realm_id=? AND digest=? AND consumed_at IS NULL",
                params![ts(command.now), realm_id.to_string(), command.ceremony_digest.as_bytes().as_slice()],
            ).map_err(storage)?;
            if consumed != 1 {
                return Ok(PasskeyAuthenticationOutcome::Reused);
            }
            let session = command.session.session.clone();
            insert_session(&transaction, &command.session)?;
            transaction.commit().map_err(storage)?;
            Ok(PasskeyAuthenticationOutcome::Completed(Box::new(session)))
        })
        .await
    }

    async fn list_passkeys(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Passkey>, AuthError> {
        self.run(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT id,label,credential_id,provider_id,credential_format,credential_blob,signature_counter,backup_eligible,backed_up,created_at,last_used_at,revoked_at FROM passkey_credentials WHERE realm_id=? AND user_id=? ORDER BY created_at DESC",
                )
                .map_err(storage)?;
            let stored = collect_nested(
                statement
                    .query_map(params![realm_id.to_string(), user_id.to_string()], |row| {
                        stored_passkey(row, realm_id, user_id)
                    })
                    .map_err(storage)?,
            )?;
            Ok(stored.into_iter().map(|value| value.passkey).collect())
        })
        .await
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
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let changed = transaction.execute(
                "UPDATE passkey_credentials SET label=? WHERE realm_id=? AND id=? AND user_id=? AND revoked_at IS NULL",
                params![label, realm_id.to_string(), passkey_id.to_string(), user_id.to_string()],
            ).map_err(storage)?;
            if changed == 1 {
                insert_audit(&transaction, &audit)?;
            }
            transaction.commit().map_err(storage)?;
            Ok(changed == 1)
        })
        .await
    }

    async fn revoke_passkey(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        passkey_id: PasskeyId,
        revoked_at: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let changed = transaction.execute(
                "UPDATE passkey_credentials SET revoked_at=? WHERE realm_id=? AND id=? AND user_id=? AND revoked_at IS NULL",
                params![ts(revoked_at), realm_id.to_string(), passkey_id.to_string(), user_id.to_string()],
            ).map_err(storage)?;
            if changed == 1 {
                insert_audit(&transaction, &audit)?;
            }
            transaction.commit().map_err(storage)?;
            Ok(changed == 1)
        })
        .await
    }
}

#[async_trait]
impl IamStore for SqliteAuthStore {
    async fn iam_initialized(&self, realm_id: RealmId) -> Result<bool, AuthError> {
        self.run(move |connection| {
            connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM iam_realms WHERE realm_id=?)",
                    params![realm_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .map(|value| value == 1)
                .map_err(storage)
        })
        .await
    }

    async fn bootstrap_iam(&self, command: BootstrapIam) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let initialized: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM iam_realms WHERE realm_id=?)",
                params![command.realm_id.to_string()],
                |row| row.get(0),
            ).map_err(storage)?;
            if initialized == 1 { return Err(conflict("realm IAM is already initialized")); }
            let user_exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE realm_id=? AND id=?)",
                params![command.realm_id.to_string(), command.owner_user_id.to_string()],
                |row| row.get(0),
            ).map_err(storage)?;
            if user_exists != 1
                || command.owner_role.realm_id() != command.realm_id
                || !command.owner_role.reserved()
                || command.permissions.is_empty()
                || command.permissions.len() > MAX_PERMISSIONS_PER_ROLE
            { return Err(AuthError::invalid_input()); }
            transaction.execute(
                "INSERT INTO iam_realms(realm_id,initialized_at) VALUES(?,?)",
                params![command.realm_id.to_string(), ts(command.event.created_at)],
            ).map_err(storage)?;
            insert_role(&transaction, &command.owner_role)?;
            for permission in &command.permissions {
                if permission.realm_id() != command.realm_id || !permission.enabled() {
                    return Err(AuthError::invalid_input());
                }
                insert_permission(&transaction, permission)?;
                transaction.execute(
                    "INSERT INTO iam_role_permissions(realm_id,role_id,permission_id) VALUES(?,?,?)",
                    params![command.realm_id.to_string(), command.owner_role.id().to_string(), permission.id().to_string()],
                ).map_err(storage)?;
            }
            transaction.execute(
                "INSERT INTO iam_principal_roles(realm_id,principal_kind,principal_id,role_id,created_at) VALUES(?,'user',?,?,?)",
                params![command.realm_id.to_string(), command.owner_user_id.to_string(), command.owner_role.id().to_string(), ts(command.event.created_at)],
            ).map_err(storage)?;
            insert_event(&transaction, &command.event)?;
            transaction.commit().map_err(storage)
        }).await
    }

    async fn principal_permissions(
        &self,
        realm_id: RealmId,
        principal: PrincipalId,
    ) -> Result<Vec<PermissionKey>, AuthError> {
        self.run(move |connection| effective_permissions(connection, realm_id, principal))
            .await
    }

    async fn create_permission(&self, command: CreatePermission) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            ensure_actor(&transaction, command.permission.realm_id(), command.actor_user_id, &command.required_permission)?;
            let exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM iam_permissions WHERE realm_id=? AND (id=? OR key=?))",
                params![command.permission.realm_id().to_string(), command.permission.id().to_string(), command.permission.key().as_str()],
                |row| row.get(0),
            ).map_err(storage)?;
            if exists == 1 { return Err(conflict("permission already exists")); }
            insert_permission(&transaction, &command.permission)?;
            insert_event(&transaction, &command.event)?;
            transaction.commit().map_err(storage)
        }).await
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
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            ensure_actor(&transaction, realm_id, actor_user_id, &required_permission)?;
            if !enabled && permission_is_reserved(&transaction, realm_id, permission_id)? {
                return Err(conflict("reserved IAM permissions cannot be disabled"));
            }
            let changed = transaction.execute(
                "UPDATE iam_permissions SET enabled=?,updated_at=? WHERE realm_id=? AND id=? AND enabled<>?",
                params![i64::from(enabled), ts(now), realm_id.to_string(), permission_id.to_string(), i64::from(enabled)],
            ).map_err(storage)?;
            let exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM iam_permissions WHERE realm_id=? AND id=?)",
                params![realm_id.to_string(), permission_id.to_string()], |row| row.get(0),
            ).map_err(storage)?;
            if changed == 1 { insert_event(&transaction, &event)?; }
            transaction.commit().map_err(storage)?;
            Ok(exists == 1)
        }).await
    }

    async fn list_permissions(
        &self,
        realm_id: RealmId,
    ) -> Result<Vec<PermissionDefinition>, AuthError> {
        self.run(move |connection| {
            let mut statement = connection.prepare(
                "SELECT id,key,description,enabled,created_at,updated_at FROM iam_permissions WHERE realm_id=? ORDER BY key",
            ).map_err(storage)?;
            let rows = statement.query_map(params![realm_id.to_string()], |row| stored_permission(row, realm_id)).map_err(storage)?;
            collect_nested(rows)
        }).await
    }

    async fn create_role(&self, command: CreateRole) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            ensure_actor(
                &transaction,
                command.role.realm_id(),
                command.actor_user_id,
                &command.required_permission,
            )?;
            if command.role.reserved() {
                return Err(conflict("role key is reserved"));
            }
            let exists: i64 = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM iam_roles WHERE realm_id=? AND (id=? OR key=?))",
                    params![
                        command.role.realm_id().to_string(),
                        command.role.id().to_string(),
                        command.role.key().as_str()
                    ],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if exists == 1 {
                return Err(conflict("role already exists"));
            }
            insert_role(&transaction, &command.role)?;
            insert_event(&transaction, &command.event)?;
            transaction.commit().map_err(storage)
        })
        .await
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
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            ensure_actor(&transaction, realm_id, actor_user_id, &required_permission)?;
            let reserved: Option<i64> = transaction.query_row(
                "SELECT reserved FROM iam_roles WHERE realm_id=? AND id=?",
                params![realm_id.to_string(), role_id.to_string()], |row| row.get(0),
            ).optional().map_err(storage)?;
            let Some(reserved) = reserved else { return Ok(false); };
            if reserved == 1 { return Err(conflict("reserved role cannot be changed")); }
            let changed = transaction.execute(
                "UPDATE iam_roles SET enabled=?,updated_at=? WHERE realm_id=? AND id=? AND enabled<>?",
                params![i64::from(enabled), ts(now), realm_id.to_string(), role_id.to_string(), i64::from(enabled)],
            ).map_err(storage)?;
            if changed == 1 { insert_event(&transaction, &event)?; }
            transaction.commit().map_err(storage)?;
            Ok(true)
        }).await
    }

    async fn list_roles(&self, realm_id: RealmId) -> Result<Vec<Role>, AuthError> {
        self.run(move |connection| {
            let mut statement = connection.prepare(
                "SELECT id,key,name,description,reserved,enabled,created_at,updated_at FROM iam_roles WHERE realm_id=? ORDER BY key",
            ).map_err(storage)?;
            let rows = statement.query_map(params![realm_id.to_string()], |row| stored_role(row, realm_id)).map_err(storage)?;
            collect_nested(rows)
        }).await
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
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            ensure_actor(&transaction, realm_id, actor_user_id, &required_permission)?;
            let reserved: Option<i64> = transaction.query_row(
                "SELECT reserved FROM iam_roles WHERE realm_id=? AND id=?",
                params![realm_id.to_string(), role_id.to_string()], |row| row.get(0),
            ).optional().map_err(storage)?;
            let Some(reserved) = reserved else { return Ok(false); };
            if reserved == 1 { return Err(conflict("reserved role cannot be changed")); }
            let permission_exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM iam_permissions WHERE realm_id=? AND id=?)",
                params![realm_id.to_string(), permission_id.to_string()], |row| row.get(0),
            ).map_err(storage)?;
            if permission_exists != 1 { return Ok(false); }
            let changed = if granted {
                let count: usize = transaction.query_row(
                    "SELECT COUNT(*) FROM iam_role_permissions WHERE realm_id=? AND role_id=?",
                    params![realm_id.to_string(), role_id.to_string()], |row| row.get(0),
                ).map_err(storage)?;
                if count >= MAX_PERMISSIONS_PER_ROLE {
                    let exists: i64 = transaction.query_row(
                        "SELECT EXISTS(SELECT 1 FROM iam_role_permissions WHERE realm_id=? AND role_id=? AND permission_id=?)",
                        params![realm_id.to_string(), role_id.to_string(), permission_id.to_string()], |row| row.get(0),
                    ).map_err(storage)?;
                    if exists != 1 { return Err(AuthError::invalid_input()); }
                }
                transaction.execute(
                    "INSERT OR IGNORE INTO iam_role_permissions(realm_id,role_id,permission_id) VALUES(?,?,?)",
                    params![realm_id.to_string(), role_id.to_string(), permission_id.to_string()],
                ).map_err(storage)?
            } else {
                transaction.execute(
                    "DELETE FROM iam_role_permissions WHERE realm_id=? AND role_id=? AND permission_id=?",
                    params![realm_id.to_string(), role_id.to_string(), permission_id.to_string()],
                ).map_err(storage)?
            };
            if changed == 1 { insert_event(&transaction, &event)?; }
            transaction.commit().map_err(storage)?;
            Ok(changed == 1)
        }).await
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
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            ensure_actor(&transaction, realm_id, actor_user_id, &required_permission)?;
            let reserved: Option<i64> = transaction.query_row(
                "SELECT reserved FROM iam_roles WHERE realm_id=? AND id=?",
                params![realm_id.to_string(), role_id.to_string()], |row| row.get(0),
            ).optional().map_err(storage)?;
            let Some(reserved) = reserved else { return Ok(false); };
            if !principal_exists(&transaction, realm_id, principal)? { return Ok(false); }
            let (kind, id) = principal_parts(principal);
            if reserved == 1 && kind != "user" { return Err(permission_denied()); }
            let changed = if granted {
                let count: usize = transaction.query_row(
                    "SELECT COUNT(*) FROM iam_principal_roles WHERE realm_id=? AND principal_kind=? AND principal_id=?",
                    params![realm_id.to_string(), kind, id], |row| row.get(0),
                ).map_err(storage)?;
                if count >= MAX_ROLES_PER_PRINCIPAL {
                    let exists: i64 = transaction.query_row(
                        "SELECT EXISTS(SELECT 1 FROM iam_principal_roles WHERE realm_id=? AND principal_kind=? AND principal_id=? AND role_id=?)",
                        params![realm_id.to_string(), kind, id, role_id.to_string()], |row| row.get(0),
                    ).map_err(storage)?;
                    if exists != 1 { return Err(AuthError::invalid_input()); }
                }
                transaction.execute(
                    "INSERT OR IGNORE INTO iam_principal_roles(realm_id,principal_kind,principal_id,role_id,created_at) VALUES(?,?,?,?,?)",
                    params![realm_id.to_string(), kind, id, role_id.to_string(), ts(event.created_at)],
                ).map_err(storage)?
            } else {
                if reserved == 1 {
                    let owners: usize = transaction.query_row(
                        "SELECT COUNT(*) FROM iam_principal_roles WHERE realm_id=? AND principal_kind='user' AND role_id=?",
                        params![realm_id.to_string(), role_id.to_string()], |row| row.get(0),
                    ).map_err(storage)?;
                    if owners <= 1 { return Err(conflict("the last human realm owner cannot be removed")); }
                }
                transaction.execute(
                    "DELETE FROM iam_principal_roles WHERE realm_id=? AND principal_kind=? AND principal_id=? AND role_id=?",
                    params![realm_id.to_string(), kind, id, role_id.to_string()],
                ).map_err(storage)?
            };
            if changed == 1 { insert_event(&transaction, &event)?; }
            transaction.commit().map_err(storage)?;
            Ok(changed == 1)
        }).await
    }

    async fn create_service_account(&self, command: CreateServiceAccount) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let account = &command.service_account;
            ensure_actor(&transaction, account.realm_id(), command.actor_user_id, &command.required_permission)?;
            let exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM iam_service_accounts WHERE realm_id=? AND (id=? OR name=?))",
                params![account.realm_id().to_string(), account.id().to_string(), account.name()], |row| row.get(0),
            ).map_err(storage)?;
            if exists == 1 { return Err(conflict("service account already exists")); }
            transaction.execute(
                "INSERT INTO iam_service_accounts(realm_id,id,name,description,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                params![account.realm_id().to_string(), account.id().to_string(), account.name(), account.description(), i64::from(account.enabled()), ts(account.created_at()), ts(account.updated_at())],
            ).map_err(storage)?;
            insert_event(&transaction, &command.event)?;
            transaction.commit().map_err(storage)
        }).await
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
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            ensure_actor(&transaction, realm_id, actor_user_id, &required_permission)?;
            let changed = transaction.execute(
                "UPDATE iam_service_accounts SET enabled=?,updated_at=? WHERE realm_id=? AND id=? AND enabled<>?",
                params![i64::from(enabled), ts(now), realm_id.to_string(), service_account_id.to_string(), i64::from(enabled)],
            ).map_err(storage)?;
            let exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM iam_service_accounts WHERE realm_id=? AND id=?)",
                params![realm_id.to_string(), service_account_id.to_string()], |row| row.get(0),
            ).map_err(storage)?;
            if changed == 1 { insert_event(&transaction, &event)?; }
            transaction.commit().map_err(storage)?;
            Ok(exists == 1)
        }).await
    }

    async fn list_service_accounts(
        &self,
        realm_id: RealmId,
    ) -> Result<Vec<ServiceAccount>, AuthError> {
        self.run(move |connection| {
            let mut statement = connection.prepare(
                "SELECT id,name,description,enabled,created_at,updated_at FROM iam_service_accounts WHERE realm_id=? ORDER BY created_at,id",
            ).map_err(storage)?;
            let rows = statement.query_map(params![realm_id.to_string()], |row| stored_service_account(row, realm_id)).map_err(storage)?;
            collect_nested(rows)
        }).await
    }

    async fn create_api_key(&self, command: CreateApiKey) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let realm_id = command.stored.key.realm_id();
            ensure_actor(
                &transaction,
                realm_id,
                command.actor_user_id,
                &command.required_permission,
            )?;
            validate_api_key_scope(&transaction, &command.stored.key)?;
            let exists: i64 = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM iam_api_keys WHERE realm_id=? AND id=?)",
                    params![realm_id.to_string(), command.stored.key.id().to_string()],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if exists == 1 {
                return Err(conflict("API key identifier already exists"));
            }
            insert_api_key(&transaction, &command.stored)?;
            insert_event(&transaction, &command.event)?;
            transaction.commit().map_err(storage)
        })
        .await
    }

    async fn find_api_key(
        &self,
        realm_id: RealmId,
        id: ApiKeyId,
    ) -> Result<Option<ApiKey>, AuthError> {
        self.run(move |connection| {
            Ok(load_api_key(connection, realm_id, id)?.map(|stored| stored.key))
        })
        .await
    }

    async fn list_api_keys(
        &self,
        realm_id: RealmId,
        principal: PrincipalId,
    ) -> Result<Vec<ApiKey>, AuthError> {
        self.run(move |connection| {
            let (kind, principal_id) = principal_parts(principal);
            let mut statement = connection.prepare(
                "SELECT id FROM iam_api_keys WHERE realm_id=? AND principal_kind=? AND principal_id=? ORDER BY created_at,id",
            ).map_err(storage)?;
            let rows = statement.query_map(params![realm_id.to_string(), kind, principal_id], |row| row.get::<_, String>(0)).map_err(storage)?;
            let mut ids = Vec::new();
            for row in rows { ids.push(ApiKeyId::parse(&row.map_err(storage)?)?); }
            drop(statement);
            let mut values = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(stored) = load_api_key(connection, realm_id, id)? { values.push(stored.key); }
            }
            Ok(values)
        }).await
    }

    async fn rotate_api_key(&self, command: RotateApiKey) -> Result<(), AuthError> {
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            let realm_id = command.replacement.key.realm_id();
            ensure_actor(&transaction, realm_id, command.actor_user_id, &command.required_permission)?;
            validate_api_key_scope(&transaction, &command.replacement.key)?;
            let previous = load_api_key(&transaction, realm_id, command.previous_id)?.ok_or_else(AuthError::invalid_credentials)?;
            if previous.key.principal() != command.replacement.key.principal()
                || previous.key.scopes() != command.replacement.key.scopes()
                || previous.key.revoked_at().is_some()
            { return Err(AuthError::invalid_credentials()); }
            let grace = command.previous_grace_expires_at.min(previous.key.expires_at());
            transaction.execute(
                "UPDATE iam_api_keys SET grace_expires_at=? WHERE realm_id=? AND id=? AND revoked_at IS NULL",
                params![ts(grace), realm_id.to_string(), command.previous_id.to_string()],
            ).map_err(storage)?;
            insert_api_key(&transaction, &command.replacement)?;
            insert_event(&transaction, &command.event)?;
            transaction.commit().map_err(storage)
        }).await
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
        self.run(move |connection| {
            let transaction = immediate(connection)?;
            ensure_actor(&transaction, realm_id, actor_user_id, &required_permission)?;
            let changed = transaction.execute(
                "UPDATE iam_api_keys SET revoked_at=? WHERE realm_id=? AND id=? AND revoked_at IS NULL",
                params![ts(now), realm_id.to_string(), api_key_id.to_string()],
            ).map_err(storage)?;
            let exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM iam_api_keys WHERE realm_id=? AND id=?)",
                params![realm_id.to_string(), api_key_id.to_string()], |row| row.get(0),
            ).map_err(storage)?;
            if changed == 1 { insert_event(&transaction, &event)?; }
            transaction.commit().map_err(storage)?;
            Ok(exists == 1)
        }).await
    }

    async fn authenticate_api_key(
        &self,
        realm_id: RealmId,
        parsed: sdk_auth_crypto::ParsedApiKey,
        now: DateTime<Utc>,
    ) -> Result<Option<ApiKeyAuthentication>, AuthError> {
        self.run(move |connection| {
            let Some(stored) = load_api_key(connection, realm_id, parsed.id)? else {
                return Ok(None);
            };
            if !stored.digest.constant_time_eq(&parsed.digest)
                || stored.key.revoked_at().is_some()
                || stored.key.expires_at() <= now
                || stored
                    .key
                    .grace_expires_at()
                    .is_some_and(|value| value <= now)
                || !principal_active(connection, realm_id, stored.key.principal())?
            {
                return Ok(None);
            }
            Ok(Some(ApiKeyAuthentication {
                permissions: effective_permissions(connection, realm_id, stored.key.principal())?,
                key: stored.key,
            }))
        })
        .await
    }
}

fn effective_permissions(
    connection: &Connection,
    realm_id: RealmId,
    principal: PrincipalId,
) -> Result<Vec<PermissionKey>, AuthError> {
    if !principal_active(connection, realm_id, principal)? {
        return Ok(Vec::new());
    }
    let (kind, principal_id) = principal_parts(principal);
    let mut statement = connection.prepare(
        "SELECT DISTINCT p.key FROM iam_principal_roles pr JOIN iam_roles r ON r.realm_id=pr.realm_id AND r.id=pr.role_id JOIN iam_role_permissions rp ON rp.realm_id=r.realm_id AND rp.role_id=r.id JOIN iam_permissions p ON p.realm_id=rp.realm_id AND p.id=rp.permission_id WHERE pr.realm_id=? AND pr.principal_kind=? AND pr.principal_id=? AND r.enabled=1 AND p.enabled=1 ORDER BY p.key",
    ).map_err(storage)?;
    let rows = statement
        .query_map(params![realm_id.to_string(), kind, principal_id], |row| {
            row.get::<_, String>(0)
        })
        .map_err(storage)?;
    let mut values = Vec::new();
    for row in rows {
        values.push(PermissionKey::parse(row.map_err(storage)?)?);
    }
    Ok(values)
}

fn ensure_actor(
    transaction: &Transaction<'_>,
    realm_id: RealmId,
    actor: UserId,
    required: &PermissionKey,
) -> Result<(), AuthError> {
    if effective_permissions(transaction, realm_id, PrincipalId::User(actor))?
        .iter()
        .any(|value| value == required)
    {
        Ok(())
    } else {
        Err(permission_denied())
    }
}

fn principal_parts(principal: PrincipalId) -> (&'static str, String) {
    match principal {
        PrincipalId::User(id) => ("user", id.to_string()),
        PrincipalId::ServiceAccount(id) => ("service_account", id.to_string()),
        _ => ("unsupported", String::new()),
    }
}

fn principal_exists(
    connection: &Connection,
    realm_id: RealmId,
    principal: PrincipalId,
) -> Result<bool, AuthError> {
    let (kind, id) = principal_parts(principal);
    let query = match kind {
        "user" => "SELECT EXISTS(SELECT 1 FROM users WHERE realm_id=? AND id=?)",
        "service_account" => {
            "SELECT EXISTS(SELECT 1 FROM iam_service_accounts WHERE realm_id=? AND id=?)"
        }
        _ => return Ok(false),
    };
    connection
        .query_row(query, params![realm_id.to_string(), id], |row| {
            row.get::<_, i64>(0)
        })
        .map(|value| value == 1)
        .map_err(storage)
}

fn principal_active(
    connection: &Connection,
    realm_id: RealmId,
    principal: PrincipalId,
) -> Result<bool, AuthError> {
    let (kind, id) = principal_parts(principal);
    let query = match kind {
        "user" => "SELECT EXISTS(SELECT 1 FROM users WHERE realm_id=? AND id=?)",
        "service_account" => {
            "SELECT EXISTS(SELECT 1 FROM iam_service_accounts WHERE realm_id=? AND id=? AND enabled=1)"
        }
        _ => return Ok(false),
    };
    connection
        .query_row(query, params![realm_id.to_string(), id], |row| {
            row.get::<_, i64>(0)
        })
        .map(|value| value == 1)
        .map_err(storage)
}

fn permission_is_reserved(
    transaction: &Transaction<'_>,
    realm_id: RealmId,
    permission_id: PermissionId,
) -> Result<bool, AuthError> {
    transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM iam_role_permissions rp JOIN iam_roles r ON r.realm_id=rp.realm_id AND r.id=rp.role_id WHERE rp.realm_id=? AND rp.permission_id=? AND r.reserved=1)",
        params![realm_id.to_string(), permission_id.to_string()],
        |row| row.get::<_, i64>(0),
    ).map(|value| value == 1).map_err(storage)
}

fn insert_permission(
    transaction: &Transaction<'_>,
    permission: &PermissionDefinition,
) -> Result<(), AuthError> {
    transaction.execute(
        "INSERT INTO iam_permissions(realm_id,id,key,description,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        params![permission.realm_id().to_string(), permission.id().to_string(), permission.key().as_str(), permission.description(), i64::from(permission.enabled()), ts(permission.created_at()), ts(permission.updated_at())],
    ).map(|_| ()).map_err(storage)
}

fn insert_role(transaction: &Transaction<'_>, role: &Role) -> Result<(), AuthError> {
    transaction.execute(
        "INSERT INTO iam_roles(realm_id,id,key,name,description,reserved,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
        params![role.realm_id().to_string(), role.id().to_string(), role.key().as_str(), role.name(), role.description(), i64::from(role.reserved()), i64::from(role.enabled()), ts(role.created_at()), ts(role.updated_at())],
    ).map(|_| ()).map_err(storage)
}

fn validate_api_key_scope(connection: &Connection, key: &ApiKey) -> Result<(), AuthError> {
    if !principal_active(connection, key.realm_id(), key.principal())? {
        return Err(permission_denied());
    }
    let granted = effective_permissions(connection, key.realm_id(), key.principal())?;
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

fn insert_api_key(transaction: &Transaction<'_>, stored: &StoredApiKey) -> Result<(), AuthError> {
    let key = &stored.key;
    let (kind, principal_id) = principal_parts(key.principal());
    transaction.execute(
        "INSERT INTO iam_api_keys(realm_id,id,principal_kind,principal_id,name,digest,created_at,expires_at,grace_expires_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        params![key.realm_id().to_string(), key.id().to_string(), kind, principal_id, key.name(), stored.digest.as_bytes().as_slice(), ts(key.created_at()), ts(key.expires_at()), key.grace_expires_at().map(ts), key.revoked_at().map(ts)],
    ).map_err(storage)?;
    for scope in key.scopes() {
        let permission_id: Option<String> = transaction
            .query_row(
                "SELECT id FROM iam_permissions WHERE realm_id=? AND key=? AND enabled=1",
                params![key.realm_id().to_string(), scope.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let Some(permission_id) = permission_id else {
            return Err(permission_denied());
        };
        transaction
            .execute(
                "INSERT INTO iam_api_key_scopes(realm_id,api_key_id,permission_id) VALUES(?,?,?)",
                params![
                    key.realm_id().to_string(),
                    key.id().to_string(),
                    permission_id
                ],
            )
            .map_err(storage)?;
    }
    Ok(())
}

fn load_api_key(
    connection: &Connection,
    realm_id: RealmId,
    id: ApiKeyId,
) -> Result<Option<StoredApiKey>, AuthError> {
    type ApiKeyRow = (
        String,
        String,
        String,
        Vec<u8>,
        String,
        String,
        Option<String>,
        Option<String>,
    );
    let row: Option<ApiKeyRow> = connection.query_row(
        "SELECT principal_kind,principal_id,name,digest,created_at,expires_at,grace_expires_at,revoked_at FROM iam_api_keys WHERE realm_id=? AND id=?",
        params![realm_id.to_string(), id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
    ).optional().map_err(storage)?;
    let Some((
        kind,
        principal_id,
        name,
        digest,
        created_at,
        expires_at,
        grace_expires_at,
        revoked_at,
    )) = row
    else {
        return Ok(None);
    };
    let principal = parse_principal(&kind, &principal_id)?;
    let mut statement = connection.prepare(
        "SELECT p.key FROM iam_api_key_scopes s JOIN iam_permissions p ON p.realm_id=s.realm_id AND p.id=s.permission_id WHERE s.realm_id=? AND s.api_key_id=? ORDER BY p.key",
    ).map_err(storage)?;
    let rows = statement
        .query_map(params![realm_id.to_string(), id.to_string()], |row| {
            row.get::<_, String>(0)
        })
        .map_err(storage)?;
    let mut scopes = Vec::new();
    for row in rows {
        scopes.push(PermissionKey::parse(row.map_err(storage)?)?);
    }
    Ok(Some(StoredApiKey {
        key: ApiKey::from_parts(
            realm_id,
            id,
            principal,
            name,
            scopes,
            parse_ts(&created_at)?,
            parse_ts(&expires_at)?,
            grace_expires_at.as_deref().map(parse_ts).transpose()?,
            revoked_at.as_deref().map(parse_ts).transpose()?,
        )?,
        digest: TokenDigest::from_slice(&digest)?,
    }))
}

fn parse_principal(kind: &str, id: &str) -> Result<PrincipalId, AuthError> {
    match kind {
        "user" => Ok(PrincipalId::User(UserId::parse(id)?)),
        "service_account" => Ok(PrincipalId::ServiceAccount(ServiceAccountId::parse(id)?)),
        _ => Err(AuthError::storage_unavailable()),
    }
}

fn stored_permission(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
) -> rusqlite::Result<Result<PermissionDefinition, AuthError>> {
    let id: String = row.get(0)?;
    let key: String = row.get(1)?;
    let description: String = row.get(2)?;
    let enabled: i64 = row.get(3)?;
    let created_at: String = row.get(4)?;
    let updated_at: String = row.get(5)?;
    Ok((|| {
        PermissionDefinition::from_parts(
            realm_id,
            PermissionId::parse(&id)?,
            PermissionKey::parse(key)?,
            description,
            parse_bool(enabled)?,
            parse_ts(&created_at)?,
            parse_ts(&updated_at)?,
        )
    })())
}

fn stored_role(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
) -> rusqlite::Result<Result<Role, AuthError>> {
    let id: String = row.get(0)?;
    let key: String = row.get(1)?;
    let name: String = row.get(2)?;
    let description: String = row.get(3)?;
    let reserved: i64 = row.get(4)?;
    let enabled: i64 = row.get(5)?;
    let created_at: String = row.get(6)?;
    let updated_at: String = row.get(7)?;
    Ok((|| {
        Role::from_parts(
            realm_id,
            RoleId::parse(&id)?,
            RoleKey::parse(key)?,
            name,
            description,
            parse_bool(reserved)?,
            parse_bool(enabled)?,
            parse_ts(&created_at)?,
            parse_ts(&updated_at)?,
        )
    })())
}

fn stored_service_account(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
) -> rusqlite::Result<Result<ServiceAccount, AuthError>> {
    let id: String = row.get(0)?;
    let name: String = row.get(1)?;
    let description: String = row.get(2)?;
    let enabled: i64 = row.get(3)?;
    let created_at: String = row.get(4)?;
    let updated_at: String = row.get(5)?;
    Ok((|| {
        ServiceAccount::from_parts(
            realm_id,
            ServiceAccountId::parse(&id)?,
            name,
            description,
            parse_bool(enabled)?,
            parse_ts(&created_at)?,
            parse_ts(&updated_at)?,
        )
    })())
}

fn collect_nested<T, I>(rows: I) -> Result<Vec<T>, AuthError>
where
    I: Iterator<Item = rusqlite::Result<Result<T, AuthError>>>,
{
    let mut values = Vec::new();
    for row in rows {
        values.push(row.map_err(storage)??);
    }
    Ok(values)
}

fn conflict(message: &'static str) -> AuthError {
    AuthError::new(ErrorCode::Conflict, message, false)
}

fn permission_denied() -> AuthError {
    AuthError::new(ErrorCode::PermissionDenied, "permission denied", false)
}

fn configure(connection: &Connection) -> Result<(), AuthError> {
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(storage)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(storage)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(storage)
}

fn migrate_connection(connection: &mut Connection) -> Result<MigrationReport, AuthError> {
    let from = schema_version(connection)?;
    if from > LATEST_SCHEMA_VERSION {
        return Err(AuthError::schema_incompatible());
    }
    let mut applied = Vec::new();
    if from < 1 {
        let transaction = immediate(connection)?;
        transaction.execute_batch(MIGRATION_1).map_err(storage)?;
        ensure_session_column(
            &transaction,
            "authentication_method",
            "TEXT NOT NULL DEFAULT 'password'",
        )?;
        ensure_session_column(&transaction, "second_factor_verified_at", "TEXT")?;
        transaction
            .pragma_update(None, "user_version", 1_u32)
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        applied.push(1);
    }
    if from < 2 {
        let transaction = immediate(connection)?;
        transaction.execute_batch(MIGRATION_2).map_err(storage)?;
        transaction
            .pragma_update(None, "user_version", 2_u32)
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        applied.push(2);
    }
    if from < 3 {
        let transaction = immediate(connection)?;
        transaction.execute_batch(MIGRATION_3).map_err(storage)?;
        transaction
            .pragma_update(None, "user_version", 3_u32)
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        applied.push(3);
    }
    if from < 4 {
        let transaction = immediate(connection)?;
        transaction.execute_batch(MIGRATION_4).map_err(storage)?;
        ensure_table_column(
            &transaction,
            "mfa_totp_factors",
            "format_version",
            "INTEGER NOT NULL DEFAULT 1",
        )?;
        ensure_table_column(
            &transaction,
            "mfa_totp_factors",
            "algorithm",
            "TEXT NOT NULL DEFAULT 'xchacha20_poly1305'",
        )?;
        ensure_table_column(
            &transaction,
            "mfa_enrollments",
            "format_version",
            "INTEGER NOT NULL DEFAULT 1",
        )?;
        ensure_table_column(
            &transaction,
            "mfa_enrollments",
            "algorithm",
            "TEXT NOT NULL DEFAULT 'xchacha20_poly1305'",
        )?;
        transaction
            .pragma_update(None, "user_version", 4_u32)
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        applied.push(4);
    }
    if from < 5 {
        let transaction = immediate(connection)?;
        transaction.execute_batch(MIGRATION_5).map_err(storage)?;
        transaction
            .pragma_update(None, "user_version", 5_u32)
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        applied.push(5);
    }
    if from < 6 {
        let transaction = immediate(connection)?;
        transaction.execute_batch(MIGRATION_6).map_err(storage)?;
        transaction
            .pragma_update(None, "user_version", 6_u32)
            .map_err(storage)?;
        transaction.commit().map_err(storage)?;
        applied.push(6);
    }
    Ok(MigrationReport {
        from,
        to: LATEST_SCHEMA_VERSION,
        applied,
    })
}

fn ensure_session_column(
    connection: &Connection,
    column: &str,
    declaration: &str,
) -> Result<(), AuthError> {
    ensure_table_column(connection, "sessions", column, declaration)
}

fn ensure_table_column(
    connection: &Connection,
    table: &str,
    column: &str,
    declaration: &str,
) -> Result<(), AuthError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(storage)?;
    for row in rows {
        if row.map_err(storage)? == column {
            return Ok(());
        }
    }
    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {declaration}");
    connection.execute(&sql, []).map_err(storage)?;
    Ok(())
}

fn require_current_schema(connection: &Connection) -> Result<(), AuthError> {
    let observed = schema_version(connection)?;
    if observed == LATEST_SCHEMA_VERSION {
        return Ok(());
    }
    if observed > LATEST_SCHEMA_VERSION {
        let compatibility = connection
            .query_row(
                "SELECT schema_version,min_reader_version,min_writer_version FROM sdk_schema_compatibility WHERE singleton=1",
                [],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?, row.get::<_, u32>(2)?)),
            )
            .optional()
            .map_err(storage)?;
        if compatibility.is_some_and(|(declared, min_reader, min_writer)| {
            declared == observed
                && min_reader <= LATEST_SCHEMA_VERSION
                && min_writer <= LATEST_SCHEMA_VERSION
        }) {
            return Ok(());
        }
    }
    Err(AuthError::schema_incompatible())
}

fn schema_version(connection: &Connection) -> Result<u32, AuthError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(storage)
}

fn immediate(connection: &mut Connection) -> Result<Transaction<'_>, AuthError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)
}

fn insert_session(transaction: &Transaction<'_>, command: &CreateSession) -> Result<(), AuthError> {
    transaction.execute(
        "INSERT INTO sessions(realm_id,id,user_id,family_id,device_name,network_hash,user_agent,authentication_method,second_factor_verified_at,created_at,last_seen_at,expires_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
        params![command.session.realm_id.to_string(),command.session.id.to_string(),command.session.user_id.to_string(),command.family_id.to_string(),command.session.device.name.as_deref(),command.session.device.network_hash.as_deref(),command.session.device.user_agent.as_deref(),authentication_method_name(command.session.authentication_method)?,command.session.second_factor_verified_at.map(ts),ts(command.session.created_at),ts(command.session.last_seen_at),ts(command.session.expires_at)],
    ).map_err(storage)?;
    insert_access(
        transaction,
        command.session.realm_id,
        command.session.id,
        &command.access,
    )?;
    transaction.execute(
        "INSERT INTO refresh_tokens(realm_id,digest,session_id,family_id,expires_at,consumed_at) VALUES(?,?,?,?,?,NULL)",
        params![command.session.realm_id.to_string(),command.refresh_digest.as_bytes().as_slice(),command.session.id.to_string(),command.family_id.to_string(),ts(command.session.expires_at)],
    ).map_err(storage)?;
    insert_audit(transaction, &command.audit)?;
    Ok(())
}

fn insert_factor(
    transaction: &Transaction<'_>,
    factor: &StoredTotpFactor,
) -> Result<(), AuthError> {
    transaction.execute(
        "INSERT INTO mfa_totp_factors(realm_id,user_id,id,format_version,algorithm,key_id,nonce,ciphertext,last_accepted_counter,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        params![factor.realm_id.to_string(),factor.user_id.to_string(),factor.id.to_string(),factor.sealed_seed.format_version(),factor.sealed_seed.algorithm().as_str(),factor.sealed_seed.key_id(),factor.sealed_seed.nonce().as_slice(),factor.sealed_seed.ciphertext(),factor.last_accepted_counter.map(counter_to_sql).transpose()?,ts(factor.created_at),ts(factor.updated_at)],
    ).map_err(storage)?;
    Ok(())
}

fn insert_enrollment(
    transaction: &Transaction<'_>,
    enrollment: &PendingTotpEnrollment,
) -> Result<(), AuthError> {
    transaction.execute(
        "INSERT INTO mfa_enrollments(realm_id,user_id,id,format_version,algorithm,key_id,nonce,ciphertext,replacing,attempts,max_attempts,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![enrollment.realm_id.to_string(),enrollment.user_id.to_string(),enrollment.id.to_string(),enrollment.sealed_seed.format_version(),enrollment.sealed_seed.algorithm().as_str(),enrollment.sealed_seed.key_id(),enrollment.sealed_seed.nonce().as_slice(),enrollment.sealed_seed.ciphertext(),i64::from(enrollment.replacing),enrollment.attempts,enrollment.max_attempts,ts(enrollment.expires_at),ts(enrollment.created_at)],
    ).map_err(storage)?;
    Ok(())
}

fn insert_mfa_challenge(
    transaction: &Transaction<'_>,
    challenge: &StoredMfaLoginChallenge,
) -> Result<(), AuthError> {
    transaction.execute(
        "INSERT INTO mfa_login_challenges(realm_id,digest,user_id,device_name,network_hash,user_agent,remember_me,attempts,max_attempts,expires_at,created_at,consumed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
        params![challenge.realm_id.to_string(),challenge.digest.as_bytes().as_slice(),challenge.user_id.to_string(),challenge.device.name.as_deref(),challenge.device.network_hash.as_deref(),challenge.device.user_agent.as_deref(),i64::from(challenge.remember_me),challenge.attempts,challenge.max_attempts,ts(challenge.expires_at),ts(challenge.created_at)],
    ).map_err(storage)?;
    Ok(())
}

fn insert_recovery_code(
    transaction: &Transaction<'_>,
    realm_id: RealmId,
    user_id: UserId,
    digest: TokenDigest,
    created_at: DateTime<Utc>,
) -> Result<(), AuthError> {
    transaction.execute(
        "INSERT INTO mfa_recovery_codes(realm_id,user_id,digest,consumed_at,created_at) VALUES(?,?,?,NULL,?)",
        params![realm_id.to_string(),user_id.to_string(),digest.as_bytes().as_slice(),ts(created_at)],
    ).map_err(storage)?;
    Ok(())
}

fn insert_trusted_device(
    transaction: &Transaction<'_>,
    trusted: &CreateTrustedDevice,
) -> Result<(), AuthError> {
    let device = &trusted.device;
    transaction.execute(
        "INSERT INTO trusted_devices(realm_id,id,user_id,device_name,network_hash,user_agent,created_at,last_used_at,expires_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        params![device.realm_id.to_string(),device.id.to_string(),device.user_id.to_string(),device.device.name.as_deref(),device.device.network_hash.as_deref(),device.device.user_agent.as_deref(),ts(device.created_at),ts(device.last_used_at),ts(device.expires_at),device.revoked_at.map(ts)],
    ).map_err(storage)?;
    transaction.execute(
        "INSERT INTO trusted_device_tokens(realm_id,digest,device_id,expires_at,consumed_at) VALUES(?,?,?,?,NULL)",
        params![device.realm_id.to_string(),trusted.token_digest.as_bytes().as_slice(),device.id.to_string(),ts(device.expires_at)],
    ).map_err(storage)?;
    Ok(())
}

fn insert_events(transaction: &Transaction<'_>, events: &[AuthEvent]) -> Result<(), AuthError> {
    for event in events {
        insert_event(transaction, event)?;
    }
    Ok(())
}

fn revoke_trusted_devices(
    transaction: &Transaction<'_>,
    realm_id: RealmId,
    user_id: UserId,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    transaction.execute(
        "UPDATE trusted_devices SET revoked_at=? WHERE realm_id=? AND user_id=? AND revoked_at IS NULL",
        params![ts(now),realm_id.to_string(),user_id.to_string()],
    ).map_err(storage)?;
    Ok(())
}

fn counter_to_sql(counter: u64) -> Result<i64, AuthError> {
    i64::try_from(counter).map_err(|_| AuthError::storage_unavailable())
}

fn insert_access(
    transaction: &Transaction<'_>,
    realm_id: RealmId,
    session_id: SessionId,
    access: &AccessTokenRecord,
) -> Result<(), AuthError> {
    transaction
        .execute(
            "INSERT INTO access_tokens(realm_id,digest,session_id,expires_at) VALUES(?,?,?,?)",
            params![
                realm_id.to_string(),
                access.digest.as_bytes().as_slice(),
                session_id.to_string(),
                ts(access.expires_at)
            ],
        )
        .map(|_| ())
        .map_err(storage)
}

fn insert_challenge(
    transaction: &Transaction<'_>,
    realm_id: RealmId,
    challenge: &OneTimeChallenge,
) -> Result<(), AuthError> {
    transaction.execute(
        "INSERT INTO challenges(realm_id,digest,kind,user_id,expires_at,consumed_at) VALUES(?,?,?,?,?,NULL)",
        params![realm_id.to_string(),challenge.digest.as_bytes().as_slice(),challenge_name(challenge.kind),challenge.user_id.to_string(),ts(challenge.expires_at)],
    ).map(|_|()).map_err(storage)
}

fn insert_event(transaction: &Transaction<'_>, event: &AuthEvent) -> Result<(), AuthError> {
    let audit = AuditRecord::from_outbox_event(event);
    insert_audit(transaction, &audit)?;
    transaction.execute(
        "INSERT INTO outbox(id,realm_id,user_id,kind,payload,created_at,delivered_at) VALUES(?,?,?,?,?,?,NULL)",
        params![event.id.to_string(),event.realm_id.to_string(),event.user_id.to_string(),event_name(event.kind)?,event.payload,ts(event.created_at)],
    ).map(|_|()).map_err(storage)
}

fn insert_audit(transaction: &Transaction<'_>, audit: &AuditRecord) -> Result<(), AuthError> {
    let (actor_kind, actor_user_id) = match audit.actor {
        AuditActor::User(user_id) => ("user", Some(user_id.to_string())),
        AuditActor::System => ("system", None),
        _ => return Err(AuthError::storage_unavailable()),
    };
    transaction.execute(
        "INSERT INTO audit_log(id,realm_id,actor_kind,actor_user_id,subject_user_id,kind,outcome,metadata_json,occurred_at,outbox_event_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
        params![
            audit.id.to_string(),
            audit.realm_id.to_string(),
            actor_kind,
            actor_user_id,
            audit.subject_user_id.map(|value| value.to_string()),
            event_name(audit.kind)?,
            audit_outcome_name(audit.outcome)?,
            audit.metadata_json,
            ts(audit.occurred_at),
            audit.outbox_event_id.map(|value| value.to_string()),
        ],
    ).map(|_|()).map_err(storage)
}

fn challenge_outcome(
    transaction: &Transaction<'_>,
    realm_id: RealmId,
    digest: TokenDigest,
    kind: ChallengeKind,
    now: DateTime<Utc>,
) -> Result<OneTimeOutcome, AuthError> {
    let row = transaction.query_row(
        "SELECT user_id,expires_at,consumed_at FROM challenges WHERE realm_id=? AND digest=? AND kind=?",
        params![realm_id.to_string(),digest.as_bytes().as_slice(),challenge_name(kind)],
        |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<String>>(2)?)),
    ).optional().map_err(storage)?;
    let Some((user_id, expires_at, consumed_at)) = row else {
        return Ok(OneTimeOutcome::Invalid);
    };
    if consumed_at.is_some() {
        return Ok(OneTimeOutcome::Reused);
    }
    if parse_ts(&expires_at)? <= now {
        return Ok(OneTimeOutcome::Expired);
    }
    Ok(OneTimeOutcome::Consumed(UserId::parse(&user_id)?))
}

fn update_attempt(
    transaction: &Transaction<'_>,
    realm_id: RealmId,
    subject: &str,
    scope: &str,
    now: DateTime<Utc>,
    policy: LoginAttemptPolicy,
) -> Result<AttemptDecision, AuthError> {
    let existing = transaction.query_row(
        "SELECT attempts_json,blocked_until FROM login_attempts WHERE realm_id=? AND subject=? AND scope=?",
        params![realm_id.to_string(),subject,scope],
        |row| Ok((row.get::<_,String>(0)?,row.get::<_,Option<String>>(1)?)),
    ).optional().map_err(storage)?;
    let (mut attempts, mut blocked_until) = if let Some((attempts_json, blocked)) = existing {
        let attempts = serde_json::from_str::<Vec<DateTime<Utc>>>(&attempts_json)
            .map_err(|_| AuthError::storage_unavailable())?;
        (attempts, blocked.as_deref().map(parse_ts).transpose()?)
    } else {
        (Vec::new(), None)
    };
    if let Some(until) = blocked_until {
        if until > now {
            return Ok(AttemptDecision::BlockedUntil(until));
        }
        attempts.clear();
        blocked_until = None;
    }
    let cutoff = now - policy.window;
    attempts.retain(|timestamp| *timestamp >= cutoff);
    attempts.push(now);
    let decision = if attempts.len() > policy.max_failures as usize {
        let until = now + policy.lockout;
        blocked_until = Some(until);
        AttemptDecision::BlockedUntil(until)
    } else {
        AttemptDecision::Allowed
    };
    let attempts_json =
        serde_json::to_string(&attempts).map_err(|_| AuthError::storage_unavailable())?;
    transaction.execute(
        "INSERT INTO login_attempts(realm_id,subject,scope,attempts_json,blocked_until) VALUES(?,?,?,?,?) ON CONFLICT(realm_id,subject,scope) DO UPDATE SET attempts_json=excluded.attempts_json,blocked_until=excluded.blocked_until",
        params![realm_id.to_string(),subject,scope,attempts_json,blocked_until.map(ts)],
    ).map_err(storage)?;
    Ok(decision)
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

fn insert_passkey_ceremony(
    transaction: &Transaction<'_>,
    ceremony: &PendingPasskeyCeremony,
) -> Result<(), AuthError> {
    transaction
        .execute(
            "INSERT INTO passkey_ceremonies(realm_id,digest,user_id,session_id,kind,label,login_subject,device_name,network_hash,user_agent,remember_me,provider_id,state_format,state_blob,attempts,max_attempts,expires_at,created_at,consumed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            params![
                ceremony.realm_id.to_string(),
                ceremony.digest.as_bytes().as_slice(),
                ceremony.user_id.to_string(),
                ceremony.session_id.map(|value| value.to_string()),
                passkey_ceremony_kind_name(ceremony.kind),
                ceremony.label,
                ceremony.login_subject,
                ceremony.device.name,
                ceremony.device.network_hash,
                ceremony.device.user_agent,
                i64::from(ceremony.remember_me),
                ceremony.provider_id,
                i64::from(ceremony.state_format),
                ceremony.state,
                ceremony.attempts,
                ceremony.max_attempts,
                ts(ceremony.expires_at),
                ts(ceremony.created_at),
            ],
        )
        .map(|_| ())
        .map_err(storage)
}

#[derive(Clone)]
struct StoredPasskeyCeremonyRow {
    ceremony: PendingPasskeyCeremony,
    consumed_at: Option<DateTime<Utc>>,
}

fn stored_passkey_ceremony(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
    digest: TokenDigest,
) -> rusqlite::Result<Result<StoredPasskeyCeremonyRow, AuthError>> {
    let user_id: String = row.get(0)?;
    let session_id: Option<String> = row.get(1)?;
    let kind: String = row.get(2)?;
    let label: Option<String> = row.get(3)?;
    let login_subject: Option<String> = row.get(4)?;
    let device_name: Option<String> = row.get(5)?;
    let network_hash: Option<String> = row.get(6)?;
    let user_agent: Option<String> = row.get(7)?;
    let remember_me: i64 = row.get(8)?;
    let provider_id: String = row.get(9)?;
    let state_format: i64 = row.get(10)?;
    let state: Vec<u8> = row.get(11)?;
    let attempts: u32 = row.get(12)?;
    let max_attempts: u32 = row.get(13)?;
    let expires_at: String = row.get(14)?;
    let created_at: String = row.get(15)?;
    let consumed_at: Option<String> = row.get(16)?;
    Ok((|| {
        Ok(StoredPasskeyCeremonyRow {
            ceremony: PendingPasskeyCeremony {
                digest,
                realm_id,
                user_id: UserId::parse(&user_id)?,
                session_id: session_id.as_deref().map(SessionId::parse).transpose()?,
                kind: parse_passkey_ceremony_kind(&kind)?,
                label,
                login_subject,
                device: DeviceContext {
                    name: device_name,
                    network_hash,
                    user_agent,
                },
                remember_me: parse_bool(remember_me)?,
                provider_id,
                state_format: u16::try_from(state_format)
                    .map_err(|_| AuthError::storage_unavailable())?,
                state,
                attempts,
                max_attempts,
                expires_at: parse_ts(&expires_at)?,
                created_at: parse_ts(&created_at)?,
            },
            consumed_at: consumed_at.as_deref().map(parse_ts).transpose()?,
        })
    })())
}

fn passkey_ceremony_lookup(
    row: StoredPasskeyCeremonyRow,
    expected_kind: PasskeyCeremonyKind,
    now: DateTime<Utc>,
) -> Result<PasskeyCeremonyLookup, AuthError> {
    if row.ceremony.kind != expected_kind {
        return Ok(PasskeyCeremonyLookup::Invalid);
    }
    if row.consumed_at.is_some() {
        return Ok(PasskeyCeremonyLookup::Reused);
    }
    if row.ceremony.expires_at <= now {
        return Ok(PasskeyCeremonyLookup::Expired);
    }
    if row.ceremony.attempts >= row.ceremony.max_attempts {
        return Ok(PasskeyCeremonyLookup::RateLimited);
    }
    Ok(PasskeyCeremonyLookup::Active(Box::new(row.ceremony)))
}

fn stored_passkey(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
    user_id: UserId,
) -> rusqlite::Result<Result<StoredPasskey, AuthError>> {
    let id: String = row.get(0)?;
    let label: String = row.get(1)?;
    let credential_id: Vec<u8> = row.get(2)?;
    let provider_id: String = row.get(3)?;
    let credential_format: i64 = row.get(4)?;
    let credential_blob: Vec<u8> = row.get(5)?;
    let signature_counter: i64 = row.get(6)?;
    let backup_eligible: i64 = row.get(7)?;
    let backed_up: i64 = row.get(8)?;
    let created_at: String = row.get(9)?;
    let last_used_at: Option<String> = row.get(10)?;
    let revoked_at: Option<String> = row.get(11)?;
    Ok((|| {
        Ok(StoredPasskey {
            passkey: Passkey {
                realm_id,
                id: PasskeyId::parse(&id)?,
                user_id,
                label,
                backup_eligible: parse_bool(backup_eligible)?,
                backed_up: parse_bool(backed_up)?,
                created_at: parse_ts(&created_at)?,
                last_used_at: last_used_at.as_deref().map(parse_ts).transpose()?,
                revoked_at: revoked_at.as_deref().map(parse_ts).transpose()?,
            },
            credential_id,
            provider_id,
            credential_format: u16::try_from(credential_format)
                .map_err(|_| AuthError::storage_unavailable())?,
            credential_blob,
            signature_counter: u32::try_from(signature_counter)
                .map_err(|_| AuthError::storage_unavailable())?,
        })
    })())
}

const fn passkey_ceremony_kind_name(kind: PasskeyCeremonyKind) -> &'static str {
    match kind {
        PasskeyCeremonyKind::Registration => "registration",
        PasskeyCeremonyKind::Authentication => "authentication",
    }
}

fn parse_passkey_ceremony_kind(value: &str) -> Result<PasskeyCeremonyKind, AuthError> {
    match value {
        "registration" => Ok(PasskeyCeremonyKind::Registration),
        "authentication" => Ok(PasskeyCeremonyKind::Authentication),
        _ => Err(AuthError::storage_unavailable()),
    }
}

fn stored_factor(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
    user_id: UserId,
) -> rusqlite::Result<Result<StoredTotpFactor, AuthError>> {
    let id: String = row.get(0)?;
    let format_version: i64 = row.get(1)?;
    let algorithm: String = row.get(2)?;
    let key_id: String = row.get(3)?;
    let nonce: Vec<u8> = row.get(4)?;
    let ciphertext: Vec<u8> = row.get(5)?;
    let last_counter: Option<i64> = row.get(6)?;
    let created_at: String = row.get(7)?;
    let updated_at: String = row.get(8)?;
    Ok((|| {
        Ok(StoredTotpFactor {
            id: MfaFactorId::parse(&id)?,
            realm_id,
            user_id,
            sealed_seed: SealedSecret::from_versioned_parts(
                u16::try_from(format_version).map_err(|_| AuthError::storage_unavailable())?,
                AeadAlgorithm::parse(&algorithm)?,
                key_id,
                &nonce,
                ciphertext,
            )?,
            last_accepted_counter: last_counter
                .map(|value| u64::try_from(value).map_err(|_| AuthError::storage_unavailable()))
                .transpose()?,
            created_at: parse_ts(&created_at)?,
            updated_at: parse_ts(&updated_at)?,
        })
    })())
}

fn stored_factor_with_user(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
) -> rusqlite::Result<Result<StoredTotpFactor, AuthError>> {
    let id: String = row.get(0)?;
    let user_id: String = row.get(1)?;
    let format_version: i64 = row.get(2)?;
    let algorithm: String = row.get(3)?;
    let key_id: String = row.get(4)?;
    let nonce: Vec<u8> = row.get(5)?;
    let ciphertext: Vec<u8> = row.get(6)?;
    let last_counter: Option<i64> = row.get(7)?;
    let created_at: String = row.get(8)?;
    let updated_at: String = row.get(9)?;
    Ok((|| {
        Ok(StoredTotpFactor {
            id: MfaFactorId::parse(&id)?,
            realm_id,
            user_id: UserId::parse(&user_id)?,
            sealed_seed: SealedSecret::from_versioned_parts(
                u16::try_from(format_version).map_err(|_| AuthError::storage_unavailable())?,
                AeadAlgorithm::parse(&algorithm)?,
                key_id,
                &nonce,
                ciphertext,
            )?,
            last_accepted_counter: last_counter
                .map(|value| u64::try_from(value).map_err(|_| AuthError::storage_unavailable()))
                .transpose()?,
            created_at: parse_ts(&created_at)?,
            updated_at: parse_ts(&updated_at)?,
        })
    })())
}

fn stored_enrollment(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
    user_id: UserId,
) -> rusqlite::Result<Result<PendingTotpEnrollment, AuthError>> {
    let id: String = row.get(0)?;
    let format_version: i64 = row.get(1)?;
    let algorithm: String = row.get(2)?;
    let key_id: String = row.get(3)?;
    let nonce: Vec<u8> = row.get(4)?;
    let ciphertext: Vec<u8> = row.get(5)?;
    let replacing: i64 = row.get(6)?;
    let attempts: u32 = row.get(7)?;
    let max_attempts: u32 = row.get(8)?;
    let expires_at: String = row.get(9)?;
    let created_at: String = row.get(10)?;
    Ok((|| {
        Ok(PendingTotpEnrollment {
            id: MfaEnrollmentId::parse(&id)?,
            realm_id,
            user_id,
            sealed_seed: SealedSecret::from_versioned_parts(
                u16::try_from(format_version).map_err(|_| AuthError::storage_unavailable())?,
                AeadAlgorithm::parse(&algorithm)?,
                key_id,
                &nonce,
                ciphertext,
            )?,
            replacing: parse_bool(replacing)?,
            attempts,
            max_attempts,
            expires_at: parse_ts(&expires_at)?,
            created_at: parse_ts(&created_at)?,
        })
    })())
}

struct StoredMfaChallengeRow {
    challenge: StoredMfaLoginChallenge,
    consumed_at: Option<DateTime<Utc>>,
}

fn stored_mfa_challenge(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
    digest: TokenDigest,
) -> rusqlite::Result<Result<StoredMfaChallengeRow, AuthError>> {
    let user_id: String = row.get(0)?;
    let device_name: Option<String> = row.get(1)?;
    let network_hash: Option<String> = row.get(2)?;
    let user_agent: Option<String> = row.get(3)?;
    let remember_me: i64 = row.get(4)?;
    let attempts: u32 = row.get(5)?;
    let max_attempts: u32 = row.get(6)?;
    let expires_at: String = row.get(7)?;
    let created_at: String = row.get(8)?;
    let consumed_at: Option<String> = row.get(9)?;
    Ok((|| {
        Ok(StoredMfaChallengeRow {
            challenge: StoredMfaLoginChallenge {
                digest,
                realm_id,
                user_id: UserId::parse(&user_id)?,
                device: DeviceContext {
                    name: device_name,
                    network_hash,
                    user_agent,
                },
                remember_me: parse_bool(remember_me)?,
                attempts,
                max_attempts,
                expires_at: parse_ts(&expires_at)?,
                created_at: parse_ts(&created_at)?,
            },
            consumed_at: consumed_at.as_deref().map(parse_ts).transpose()?,
        })
    })())
}

fn stored_trusted_device(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
) -> rusqlite::Result<Result<TrustedDevice, AuthError>> {
    let id: String = row.get(0)?;
    let user_id: String = row.get(1)?;
    let name: Option<String> = row.get(2)?;
    let network_hash: Option<String> = row.get(3)?;
    let user_agent: Option<String> = row.get(4)?;
    let created_at: String = row.get(5)?;
    let last_used_at: String = row.get(6)?;
    let expires_at: String = row.get(7)?;
    let revoked_at: Option<String> = row.get(8)?;
    Ok((|| {
        Ok(TrustedDevice {
            realm_id,
            id: TrustedDeviceId::parse(&id)?,
            user_id: UserId::parse(&user_id)?,
            device: DeviceContext {
                name,
                network_hash,
                user_agent,
            },
            created_at: parse_ts(&created_at)?,
            last_used_at: parse_ts(&last_used_at)?,
            expires_at: parse_ts(&expires_at)?,
            revoked_at: revoked_at.as_deref().map(parse_ts).transpose()?,
        })
    })())
}

struct StoredTrustedTokenRow {
    device: TrustedDevice,
    token_expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

fn stored_trusted_token(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
) -> rusqlite::Result<Result<StoredTrustedTokenRow, AuthError>> {
    let device = stored_trusted_device(row, realm_id)?;
    let token_expires_at: String = row.get(9)?;
    let consumed_at: Option<String> = row.get(10)?;
    Ok((|| {
        Ok(StoredTrustedTokenRow {
            device: device?,
            token_expires_at: parse_ts(&token_expires_at)?,
            consumed_at: consumed_at.as_deref().map(parse_ts).transpose()?,
        })
    })())
}

fn parse_bool(value: i64) -> Result<bool, AuthError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AuthError::storage_unavailable()),
    }
}

fn stored_user(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
) -> rusqlite::Result<Result<StoredUser, AuthError>> {
    let id: String = row.get(0)?;
    let email: String = row.get(1)?;
    let verified: i64 = row.get(2)?;
    let password_hash: String = row.get(3)?;
    let created: String = row.get(4)?;
    let updated: String = row.get(5)?;
    Ok((|| {
        Ok(StoredUser {
            user: User {
                realm_id,
                id: UserId::parse(&id)?,
                email: EmailAddress::parse(email)?,
                email_verified: verified == 1,
                created_at: parse_ts(&created)?,
                updated_at: parse_ts(&updated)?,
            },
            password_hash,
        })
    })())
}

fn stored_session(
    row: &rusqlite::Row<'_>,
    realm_id: RealmId,
) -> rusqlite::Result<Result<Session, AuthError>> {
    let id: String = row.get(0)?;
    let user_id: String = row.get(1)?;
    let name: Option<String> = row.get(2)?;
    let network_hash: Option<String> = row.get(3)?;
    let user_agent: Option<String> = row.get(4)?;
    let authentication_method: String = row.get(5)?;
    let second_factor_verified_at: Option<String> = row.get(6)?;
    let created: String = row.get(7)?;
    let last_seen: String = row.get(8)?;
    let expires: String = row.get(9)?;
    let revoked: Option<String> = row.get(10)?;
    Ok((|| {
        Ok(Session {
            realm_id,
            id: SessionId::parse(&id)?,
            user_id: UserId::parse(&user_id)?,
            device: DeviceContext {
                name,
                network_hash,
                user_agent,
            },
            authentication_method: parse_authentication_method(&authentication_method)?,
            second_factor_verified_at: second_factor_verified_at
                .as_deref()
                .map(parse_ts)
                .transpose()?,
            created_at: parse_ts(&created)?,
            last_seen_at: parse_ts(&last_seen)?,
            expires_at: parse_ts(&expires)?,
            revoked_at: revoked.as_deref().map(parse_ts).transpose()?,
        })
    })())
}

fn stored_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<AuthEvent, AuthError>> {
    let id: String = row.get(0)?;
    let realm_id: String = row.get(1)?;
    let user_id: String = row.get(2)?;
    let kind: String = row.get(3)?;
    let payload: String = row.get(4)?;
    let created: String = row.get(5)?;
    Ok((|| {
        Ok(AuthEvent {
            id: EventId::parse(&id)?,
            realm_id: RealmId::parse(&realm_id)?,
            user_id: UserId::parse(&user_id)?,
            kind: parse_event_name(&kind)?,
            payload,
            created_at: parse_ts(&created)?,
        })
    })())
}

fn ts(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn parse_ts(value: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| AuthError::storage_unavailable())
}

const fn challenge_name(kind: ChallengeKind) -> &'static str {
    match kind {
        ChallengeKind::EmailVerification => "email_verification",
        ChallengeKind::PasswordReset => "password_reset",
    }
}

fn stored_audit_record(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<AuditRecord, AuthError>> {
    let id: String = row.get(0)?;
    let realm_id: String = row.get(1)?;
    let actor_kind: String = row.get(2)?;
    let actor_user_id: Option<String> = row.get(3)?;
    let subject_user_id: Option<String> = row.get(4)?;
    let kind: String = row.get(5)?;
    let outcome: String = row.get(6)?;
    let metadata_json: String = row.get(7)?;
    let occurred_at: String = row.get(8)?;
    let outbox_event_id: Option<String> = row.get(9)?;
    Ok((|| {
        let actor = match (actor_kind.as_str(), actor_user_id) {
            ("system", None) => AuditActor::System,
            ("user", Some(value)) => AuditActor::User(UserId::parse(&value)?),
            _ => return Err(AuthError::storage_unavailable()),
        };
        let outcome = match outcome.as_str() {
            "succeeded" => AuditOutcome::Succeeded,
            "denied" => AuditOutcome::Denied,
            _ => return Err(AuthError::storage_unavailable()),
        };
        Ok(AuditRecord {
            id: AuditId::parse(&id)?,
            realm_id: RealmId::parse(&realm_id)?,
            actor,
            subject_user_id: subject_user_id
                .map(|value| UserId::parse(&value))
                .transpose()?,
            kind: parse_event_name(&kind)?,
            outcome,
            metadata_json,
            occurred_at: parse_ts(&occurred_at)?,
            outbox_event_id: outbox_event_id
                .map(|value| EventId::parse(&value))
                .transpose()?,
        })
    })())
}

fn audit_outcome_name(outcome: AuditOutcome) -> Result<&'static str, AuthError> {
    match outcome {
        AuditOutcome::Succeeded => Ok("succeeded"),
        AuditOutcome::Denied => Ok("denied"),
        _ => Err(AuthError::storage_unavailable()),
    }
}

fn event_name(kind: AuthEventKind) -> Result<&'static str, AuthError> {
    Ok(match kind {
        AuthEventKind::LoginSucceeded => "login_succeeded",
        AuthEventKind::SessionRevoked => "session_revoked",
        AuthEventKind::SessionsRevoked => "sessions_revoked",
        AuthEventKind::EmailVerified => "email_verified",
        AuthEventKind::EmailVerificationRequested => "email_verification_requested",
        AuthEventKind::PasswordResetRequested => "password_reset_requested",
        AuthEventKind::RefreshTokenReuseDetected => "refresh_token_reuse_detected",
        AuthEventKind::PasswordChanged => "password_changed",
        AuthEventKind::MfaEnabled => "mfa_enabled",
        AuthEventKind::MfaReplaced => "mfa_replaced",
        AuthEventKind::MfaDisabled => "mfa_disabled",
        AuthEventKind::RecoveryCodesRegenerated => "recovery_codes_regenerated",
        AuthEventKind::RecoveryCodeUsed => "recovery_code_used",
        AuthEventKind::TrustedDeviceCreated => "trusted_device_created",
        AuthEventKind::TrustedDeviceRevoked => "trusted_device_revoked",
        AuthEventKind::TrustedDeviceReplayDetected => "trusted_device_replay_detected",
        AuthEventKind::PasskeyRegistered => "passkey_registered",
        AuthEventKind::PasskeyRenamed => "passkey_renamed",
        AuthEventKind::PasskeyRevoked => "passkey_revoked",
        AuthEventKind::PasskeyCloneSuspected => "passkey_clone_suspected",
        AuthEventKind::IamRealmBootstrapped => "iam_realm_bootstrapped",
        AuthEventKind::IamPermissionChanged => "iam_permission_changed",
        AuthEventKind::IamRoleChanged => "iam_role_changed",
        AuthEventKind::IamAssignmentChanged => "iam_assignment_changed",
        AuthEventKind::IamServiceAccountChanged => "iam_service_account_changed",
        AuthEventKind::IamApiKeyChanged => "iam_api_key_changed",
        _ => return Err(AuthError::storage_unavailable()),
    })
}

fn parse_event_name(value: &str) -> Result<AuthEventKind, AuthError> {
    match value {
        "login_succeeded" => Ok(AuthEventKind::LoginSucceeded),
        "session_revoked" => Ok(AuthEventKind::SessionRevoked),
        "sessions_revoked" => Ok(AuthEventKind::SessionsRevoked),
        "email_verified" => Ok(AuthEventKind::EmailVerified),
        "email_verification_requested" => Ok(AuthEventKind::EmailVerificationRequested),
        "password_reset_requested" => Ok(AuthEventKind::PasswordResetRequested),
        "refresh_token_reuse_detected" => Ok(AuthEventKind::RefreshTokenReuseDetected),
        "password_changed" => Ok(AuthEventKind::PasswordChanged),
        "mfa_enabled" => Ok(AuthEventKind::MfaEnabled),
        "mfa_replaced" => Ok(AuthEventKind::MfaReplaced),
        "mfa_disabled" => Ok(AuthEventKind::MfaDisabled),
        "recovery_codes_regenerated" => Ok(AuthEventKind::RecoveryCodesRegenerated),
        "recovery_code_used" => Ok(AuthEventKind::RecoveryCodeUsed),
        "trusted_device_created" => Ok(AuthEventKind::TrustedDeviceCreated),
        "trusted_device_revoked" => Ok(AuthEventKind::TrustedDeviceRevoked),
        "trusted_device_replay_detected" => Ok(AuthEventKind::TrustedDeviceReplayDetected),
        "passkey_registered" => Ok(AuthEventKind::PasskeyRegistered),
        "passkey_renamed" => Ok(AuthEventKind::PasskeyRenamed),
        "passkey_revoked" => Ok(AuthEventKind::PasskeyRevoked),
        "passkey_clone_suspected" => Ok(AuthEventKind::PasskeyCloneSuspected),
        "iam_realm_bootstrapped" => Ok(AuthEventKind::IamRealmBootstrapped),
        "iam_permission_changed" => Ok(AuthEventKind::IamPermissionChanged),
        "iam_role_changed" => Ok(AuthEventKind::IamRoleChanged),
        "iam_assignment_changed" => Ok(AuthEventKind::IamAssignmentChanged),
        "iam_service_account_changed" => Ok(AuthEventKind::IamServiceAccountChanged),
        "iam_api_key_changed" => Ok(AuthEventKind::IamApiKeyChanged),
        _ => Err(AuthError::storage_unavailable()),
    }
}

fn authentication_method_name(value: AuthenticationMethod) -> Result<&'static str, AuthError> {
    #[allow(unreachable_patterns)]
    Ok(match value {
        AuthenticationMethod::Password => "password",
        AuthenticationMethod::PasswordTotp => "password_totp",
        AuthenticationMethod::PasswordRecoveryCode => "password_recovery_code",
        AuthenticationMethod::PasswordTrustedDevice => "password_trusted_device",
        AuthenticationMethod::Passkey => "passkey",
        _ => return Err(AuthError::storage_unavailable()),
    })
}

fn parse_authentication_method(value: &str) -> Result<AuthenticationMethod, AuthError> {
    match value {
        "password" => Ok(AuthenticationMethod::Password),
        "password_totp" => Ok(AuthenticationMethod::PasswordTotp),
        "password_recovery_code" => Ok(AuthenticationMethod::PasswordRecoveryCode),
        "password_trusted_device" => Ok(AuthenticationMethod::PasswordTrustedDevice),
        "passkey" => Ok(AuthenticationMethod::Passkey),
        _ => Err(AuthError::storage_unavailable()),
    }
}

fn storage(_error: rusqlite::Error) -> AuthError {
    AuthError::storage_unavailable()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_is_explicit_versioned_and_idempotent() -> Result<(), AuthError> {
        let directory = tempfile::tempdir().map_err(|_| AuthError::storage_unavailable())?;
        let path = directory.path().join("auth.db");
        assert_eq!(
            SqliteAuthStore::open(&path).err().map(|error| error.code()),
            Some(ErrorCode::SchemaIncompatible)
        );
        let first = SqliteMigrator::migrate(&path)?;
        assert_eq!(first.from, 0);
        assert_eq!(first.to, LATEST_SCHEMA_VERSION);
        assert_eq!(first.applied, vec![1, 2, 3, 4, 5, 6]);
        let _store = SqliteAuthStore::open(&path)?;
        let second = SqliteMigrator::migrate(&path)?;
        assert_eq!(second.from, LATEST_SCHEMA_VERSION);
        assert!(second.applied.is_empty());
        Ok(())
    }

    #[test]
    fn legacy_unversioned_sessions_receive_mfa_columns() -> Result<(), AuthError> {
        let directory = tempfile::tempdir().map_err(|_| AuthError::storage_unavailable())?;
        let path = directory.path().join("legacy.db");
        let connection = Connection::open(&path).map_err(storage)?;
        connection
            .execute_batch(
                r#"
                CREATE TABLE users(
                  realm_id TEXT NOT NULL,id TEXT NOT NULL,email TEXT NOT NULL,
                  normalized_email TEXT NOT NULL,email_verified INTEGER NOT NULL,
                  password_hash TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
                  PRIMARY KEY(realm_id,id),UNIQUE(realm_id,normalized_email));
                CREATE TABLE sessions(
                  realm_id TEXT NOT NULL,id TEXT NOT NULL,user_id TEXT NOT NULL,family_id TEXT NOT NULL,
                  device_name TEXT,network_hash TEXT,user_agent TEXT,created_at TEXT NOT NULL,
                  last_seen_at TEXT NOT NULL,expires_at TEXT NOT NULL,revoked_at TEXT,
                  PRIMARY KEY(realm_id,id));
                "#,
            )
            .map_err(storage)?;
        drop(connection);
        SqliteMigrator::migrate(&path)?;
        let connection = Connection::open(&path).map_err(storage)?;
        let mut statement = connection
            .prepare("PRAGMA table_info(sessions)")
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage)?;
        let mut columns = Vec::new();
        for row in rows {
            columns.push(row.map_err(storage)?);
        }
        assert!(
            columns
                .iter()
                .any(|column| column == "authentication_method")
        );
        assert!(
            columns
                .iter()
                .any(|column| column == "second_factor_verified_at")
        );
        Ok(())
    }

    #[test]
    fn migration_four_backfills_audit_and_versions_ciphertext() -> Result<(), AuthError> {
        let directory = tempfile::tempdir().map_err(|_| AuthError::storage_unavailable())?;
        let path = directory.path().join("version-three.db");
        let connection = Connection::open(&path).map_err(storage)?;
        connection.execute_batch(MIGRATION_1).map_err(storage)?;
        connection.execute_batch(MIGRATION_2).map_err(storage)?;
        connection.execute_batch(MIGRATION_3).map_err(storage)?;
        let event_id = EventId::new();
        let realm_id = RealmId::new();
        let user_id = UserId::new();
        let created_at = Utc::now();
        connection.execute(
            "INSERT INTO outbox(id,realm_id,user_id,kind,payload,created_at,delivered_at) VALUES(?,?,?,?,?,?,NULL)",
            params![
                event_id.to_string(),
                realm_id.to_string(),
                user_id.to_string(),
                "mfa_enabled",
                "{}",
                ts(created_at),
            ],
        ).map_err(storage)?;
        connection
            .pragma_update(None, "user_version", 3_u32)
            .map_err(storage)?;
        drop(connection);

        let report = SqliteMigrator::migrate(&path)?;
        assert_eq!(report.applied, vec![4, 5, 6]);
        let store = SqliteAuthStore::open(&path)?;
        let runtime =
            tokio::runtime::Runtime::new().map_err(|_| AuthError::storage_unavailable())?;
        let records = runtime.block_on(store.list_audit_records(realm_id, None, 10))?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outbox_event_id, Some(event_id));
        assert_eq!(records[0].actor, AuditActor::User(user_id));

        let connection = Connection::open(&path).map_err(storage)?;
        let factor_columns = table_columns(&connection, "mfa_totp_factors")?;
        assert!(
            factor_columns
                .iter()
                .any(|column| column == "format_version")
        );
        assert!(factor_columns.iter().any(|column| column == "algorithm"));
        Ok(())
    }

    #[test]
    fn additive_future_schema_requires_explicit_reader_and_writer_compatibility()
    -> Result<(), AuthError> {
        let directory = tempfile::tempdir().map_err(|_| AuthError::storage_unavailable())?;
        let path = directory.path().join("rolling.db");
        SqliteMigrator::migrate(&path)?;
        let connection = Connection::open(&path).map_err(storage)?;
        connection
            .execute(
                "UPDATE sdk_schema_compatibility SET schema_version=7,min_reader_version=6,min_writer_version=6 WHERE singleton=1",
                [],
            )
            .map_err(storage)?;
        connection
            .pragma_update(None, "user_version", 7_u32)
            .map_err(storage)?;
        drop(connection);
        let _compatible = SqliteAuthStore::open(&path)?;

        let connection = Connection::open(&path).map_err(storage)?;
        connection
            .execute(
                "UPDATE sdk_schema_compatibility SET min_writer_version=7 WHERE singleton=1",
                [],
            )
            .map_err(storage)?;
        drop(connection);
        assert_eq!(
            SqliteAuthStore::open(&path).err().map(|error| error.code()),
            Some(ErrorCode::SchemaIncompatible)
        );
        Ok(())
    }

    fn table_columns(connection: &Connection, table: &str) -> Result<Vec<String>, AuthError> {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage)?;
        let mut columns = Vec::new();
        for row in rows {
            columns.push(row.map_err(storage)?);
        }
        Ok(columns)
    }
}
