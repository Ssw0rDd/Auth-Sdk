use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_core::{
    ChallengeKind, ChallengeStore, CreateUser, IdentityStore, OneTimeChallenge, OneTimeOutcome,
    StoredUser,
};
use sdk_auth_crypto::TokenDigest;
use sdk_auth_error::AuthError;
use sdk_auth_types::{AuditRecord, AuthEvent, RealmId, UserId};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::{PostgresAuthStore, mapping};

#[async_trait]
impl IdentityStore for PostgresAuthStore {
    async fn create_user(&self, command: CreateUser) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let inserted = sqlx::query(
            "INSERT INTO users(realm_id,id,email,normalized_email,email_verified,password_hash,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(command.user.realm_id.as_uuid())
        .bind(command.user.id.as_uuid())
        .bind(command.user.email.as_str())
        .bind(command.user.email.normalized())
        .bind(command.user.email_verified)
        .bind(command.password_hash)
        .bind(command.user.created_at)
        .bind(command.user.updated_at)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = inserted {
            return if mapping::is_unique_violation(&error) {
                Err(mapping::conflict())
            } else {
                Err(mapping::storage(error))
            };
        }
        insert_challenge(&mut transaction, command.user.realm_id, &command.challenge).await?;
        mapping::insert_event(&mut transaction, &command.event).await?;
        transaction.commit().await.map_err(mapping::storage)
    }

    async fn find_user_by_email(
        &self,
        realm_id: RealmId,
        normalized_email: &str,
    ) -> Result<Option<StoredUser>, AuthError> {
        let row = sqlx::query(
            "SELECT id,email,email_verified,password_hash,created_at,updated_at FROM users WHERE realm_id=$1 AND normalized_email=$2",
        )
        .bind(realm_id.as_uuid())
        .bind(normalized_email)
        .fetch_optional(&self.pool)
        .await
        .map_err(mapping::storage)?;
        row.as_ref()
            .map(|row| mapping::stored_user(row, realm_id))
            .transpose()
    }

    async fn find_user_by_id(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Option<StoredUser>, AuthError> {
        let row = sqlx::query(
            "SELECT id,email,email_verified,password_hash,created_at,updated_at FROM users WHERE realm_id=$1 AND id=$2",
        )
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(mapping::storage)?;
        row.as_ref()
            .map(|row| mapping::stored_user(row, realm_id))
            .transpose()
    }

    async fn update_password_hash(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        password_hash: String,
        updated_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let changed = sqlx::query(
            "UPDATE users SET password_hash=$1,updated_at=$2 WHERE realm_id=$3 AND id=$4",
        )
        .bind(password_hash)
        .bind(updated_at)
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(AuthError::storage_unavailable())
        }
    }
}

#[async_trait]
impl ChallengeStore for PostgresAuthStore {
    async fn replace_challenge(
        &self,
        realm_id: RealmId,
        challenge: OneTimeChallenge,
        event: AuthEvent,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        sqlx::query(
            "DELETE FROM challenges WHERE realm_id=$1 AND user_id=$2 AND kind=$3 AND consumed_at IS NULL",
        )
        .bind(realm_id.as_uuid())
        .bind(challenge.user_id.as_uuid())
        .bind(mapping::challenge_name(challenge.kind))
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        insert_challenge(&mut transaction, realm_id, &challenge).await?;
        mapping::insert_event(&mut transaction, &event).await?;
        transaction.commit().await.map_err(mapping::storage)
    }

    async fn consume_email_verification(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
        mut audit: AuditRecord,
    ) -> Result<OneTimeOutcome, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let outcome = challenge_outcome(
            &mut transaction,
            realm_id,
            digest,
            ChallengeKind::EmailVerification,
            now,
        )
        .await?;
        let OneTimeOutcome::Consumed(user_id) = outcome else {
            return Ok(outcome);
        };
        let changed = sqlx::query(
            "UPDATE challenges SET consumed_at=$1 WHERE realm_id=$2 AND digest=$3 AND kind=$4 AND consumed_at IS NULL",
        )
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(digest.as_bytes().as_slice())
        .bind(mapping::challenge_name(ChallengeKind::EmailVerification))
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if changed != 1 {
            return Err(AuthError::storage_unavailable());
        }
        sqlx::query(
            "UPDATE users SET email_verified=TRUE,updated_at=$1 WHERE realm_id=$2 AND id=$3",
        )
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        audit.subject_user_id = Some(user_id);
        mapping::insert_audit(&mut transaction, &audit).await?;
        transaction.commit().await.map_err(mapping::storage)?;
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
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let outcome = challenge_outcome(
            &mut transaction,
            realm_id,
            digest,
            ChallengeKind::PasswordReset,
            now,
        )
        .await?;
        let OneTimeOutcome::Consumed(user_id) = outcome else {
            return Ok(outcome);
        };
        let changed = sqlx::query(
            "UPDATE challenges SET consumed_at=$1 WHERE realm_id=$2 AND digest=$3 AND kind=$4 AND consumed_at IS NULL",
        )
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(digest.as_bytes().as_slice())
        .bind(mapping::challenge_name(ChallengeKind::PasswordReset))
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if changed != 1 {
            return Err(AuthError::storage_unavailable());
        }
        sqlx::query("UPDATE users SET password_hash=$1,updated_at=$2 WHERE realm_id=$3 AND id=$4")
            .bind(new_password_hash)
            .bind(now)
            .bind(realm_id.as_uuid())
            .bind(user_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        sqlx::query(
            "UPDATE sessions SET revoked_at=$1 WHERE realm_id=$2 AND user_id=$3 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        sqlx::query(
            "UPDATE trusted_devices SET revoked_at=$1 WHERE realm_id=$2 AND user_id=$3 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        event.user_id = user_id;
        mapping::insert_event(&mut transaction, &event).await?;
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(OneTimeOutcome::Consumed(user_id))
    }
}

async fn insert_challenge(
    connection: &mut PgConnection,
    realm_id: RealmId,
    challenge: &OneTimeChallenge,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO challenges(realm_id,digest,kind,user_id,expires_at) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(realm_id.as_uuid())
    .bind(challenge.digest.as_bytes().as_slice())
    .bind(mapping::challenge_name(challenge.kind))
    .bind(challenge.user_id.as_uuid())
    .bind(challenge.expires_at)
    .execute(connection)
    .await
    .map(|_| ())
    .map_err(mapping::storage)
}

async fn challenge_outcome(
    connection: &mut PgConnection,
    realm_id: RealmId,
    digest: TokenDigest,
    kind: ChallengeKind,
    now: DateTime<Utc>,
) -> Result<OneTimeOutcome, AuthError> {
    let row = sqlx::query(
        "SELECT user_id,expires_at,consumed_at FROM challenges WHERE realm_id=$1 AND digest=$2 AND kind=$3 FOR UPDATE",
    )
    .bind(realm_id.as_uuid())
    .bind(digest.as_bytes().as_slice())
    .bind(mapping::challenge_name(kind))
    .fetch_optional(connection)
    .await
    .map_err(mapping::storage)?;
    let Some(row) = row else {
        return Ok(OneTimeOutcome::Invalid);
    };
    if row
        .try_get::<Option<DateTime<Utc>>, _>("consumed_at")
        .map_err(mapping::storage)?
        .is_some()
    {
        return Ok(OneTimeOutcome::Reused);
    }
    if row
        .try_get::<DateTime<Utc>, _>("expires_at")
        .map_err(mapping::storage)?
        <= now
    {
        return Ok(OneTimeOutcome::Expired);
    }
    let user_id: Uuid = row.try_get("user_id").map_err(mapping::storage)?;
    Ok(OneTimeOutcome::Consumed(UserId::from_uuid(user_id)))
}
