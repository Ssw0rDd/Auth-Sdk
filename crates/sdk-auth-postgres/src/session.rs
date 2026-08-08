use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_core::{AccessTokenRecord, CreateSession, RefreshRotation, SessionStore};
use sdk_auth_crypto::TokenDigest;
use sdk_auth_error::AuthError;
use sdk_auth_types::{
    AuditRecord, AuthEvent, DeviceContext, RealmId, Session, SessionId, TokenFamilyId, UserId,
};
use sqlx::{PgConnection, Row as _, postgres::PgRow};
use uuid::Uuid;

use crate::{PostgresAuthStore, mapping};

#[async_trait]
impl SessionStore for PostgresAuthStore {
    async fn create_session(&self, command: CreateSession) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        insert_session(&mut transaction, &command).await?;
        transaction.commit().await.map_err(mapping::storage)
    }

    async fn validate_access(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let row = sqlx::query(
            "SELECT s.id,s.user_id,s.device_name,s.network_hash,s.user_agent,s.authentication_method,s.second_factor_verified_at,s.created_at,s.last_seen_at,s.expires_at,s.revoked_at FROM access_tokens a JOIN sessions s ON s.realm_id=a.realm_id AND s.id=a.session_id WHERE a.realm_id=$1 AND a.digest=$2 AND a.expires_at>$3 AND s.expires_at>$3 AND s.revoked_at IS NULL FOR UPDATE OF s",
        )
        .bind(realm_id.as_uuid())
        .bind(digest.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        let mut session = row
            .as_ref()
            .map(|row| stored_session(row, realm_id))
            .transpose()?;
        if let Some(active) = session.as_mut() {
            sqlx::query("UPDATE sessions SET last_seen_at=$1 WHERE realm_id=$2 AND id=$3")
                .bind(now)
                .bind(realm_id.as_uuid())
                .bind(active.id.as_uuid())
                .execute(&mut *transaction)
                .await
                .map_err(mapping::storage)?;
            active.last_seen_at = now;
        }
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(session)
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
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let refresh = sqlx::query(
            "SELECT session_id,family_id,expires_at,consumed_at FROM refresh_tokens WHERE realm_id=$1 AND digest=$2 FOR UPDATE",
        )
        .bind(realm_id.as_uuid())
        .bind(presented.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        let Some(refresh) = refresh else {
            return Ok(RefreshRotation::Invalid);
        };
        let session_id = SessionId::from_uuid(
            refresh
                .try_get::<Uuid, _>("session_id")
                .map_err(mapping::storage)?,
        );
        let family_id = TokenFamilyId::from_uuid(
            refresh
                .try_get::<Uuid, _>("family_id")
                .map_err(mapping::storage)?,
        );
        let refresh_expiry: DateTime<Utc> =
            refresh.try_get("expires_at").map_err(mapping::storage)?;
        let consumed_at: Option<DateTime<Utc>> =
            refresh.try_get("consumed_at").map_err(mapping::storage)?;
        let session_row = sqlx::query(
            "SELECT id,user_id,device_name,network_hash,user_agent,authentication_method,second_factor_verified_at,created_at,last_seen_at,expires_at,revoked_at FROM sessions WHERE realm_id=$1 AND id=$2 AND family_id=$3 FOR UPDATE",
        )
        .bind(realm_id.as_uuid())
        .bind(session_id.as_uuid())
        .bind(family_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        let Some(session_row) = session_row else {
            return Ok(RefreshRotation::Invalid);
        };
        let mut session = stored_session(&session_row, realm_id)?;
        if consumed_at.is_some() {
            sqlx::query(
                "UPDATE sessions SET revoked_at=COALESCE(revoked_at,$1) WHERE realm_id=$2 AND id=$3",
            )
            .bind(now)
            .bind(realm_id.as_uuid())
            .bind(session_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
            reuse_event.user_id = session.user_id;
            mapping::insert_event(&mut transaction, &reuse_event).await?;
            transaction.commit().await.map_err(mapping::storage)?;
            return Ok(RefreshRotation::Reused);
        }
        if session.revoked_at.is_some() {
            return Ok(RefreshRotation::Revoked);
        }
        if refresh_expiry <= now || session.expires_at <= now {
            return Ok(RefreshRotation::Expired);
        }
        let changed = sqlx::query(
            "UPDATE refresh_tokens SET consumed_at=$1 WHERE realm_id=$2 AND digest=$3 AND consumed_at IS NULL",
        )
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(presented.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if changed != 1 {
            return Err(AuthError::storage_unavailable());
        }
        sqlx::query(
            "INSERT INTO refresh_tokens(realm_id,digest,session_id,family_id,expires_at) VALUES($1,$2,$3,$4,$5)",
        )
        .bind(realm_id.as_uuid())
        .bind(replacement.as_bytes().as_slice())
        .bind(session_id.as_uuid())
        .bind(family_id.as_uuid())
        .bind(session.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        insert_access(&mut transaction, realm_id, session_id, &access).await?;
        sqlx::query("UPDATE sessions SET last_seen_at=$1 WHERE realm_id=$2 AND id=$3")
            .bind(now)
            .bind(realm_id.as_uuid())
            .bind(session_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        transaction.commit().await.map_err(mapping::storage)?;
        session.last_seen_at = now;
        Ok(RefreshRotation::Rotated(session))
    }

    async fn revoke_session(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        session_id: SessionId,
        now: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let changed = sqlx::query(
            "UPDATE sessions SET revoked_at=COALESCE(revoked_at,$1) WHERE realm_id=$2 AND id=$3 AND user_id=$4",
        )
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(session_id.as_uuid())
        .bind(user_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if changed == 1 {
            mapping::insert_audit(&mut transaction, &audit).await?;
        }
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(changed == 1)
    }

    async fn revoke_all_sessions(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        now: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<u64, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let changed = sqlx::query(
            "UPDATE sessions SET revoked_at=$1 WHERE realm_id=$2 AND user_id=$3 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if changed > 0 {
            mapping::insert_audit(&mut transaction, &audit).await?;
        }
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(changed)
    }

    async fn list_sessions(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Session>, AuthError> {
        let rows = sqlx::query(
            "SELECT id,user_id,device_name,network_hash,user_agent,authentication_method,second_factor_verified_at,created_at,last_seen_at,expires_at,revoked_at FROM sessions WHERE realm_id=$1 AND user_id=$2 ORDER BY created_at DESC",
        )
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(mapping::storage)?;
        rows.iter()
            .map(|row| stored_session(row, realm_id))
            .collect()
    }
}

pub(crate) async fn insert_session(
    connection: &mut PgConnection,
    command: &CreateSession,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO sessions(realm_id,id,user_id,family_id,device_name,network_hash,user_agent,authentication_method,second_factor_verified_at,created_at,last_seen_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(command.session.realm_id.as_uuid())
    .bind(command.session.id.as_uuid())
    .bind(command.session.user_id.as_uuid())
    .bind(command.family_id.as_uuid())
    .bind(command.session.device.name.as_deref())
    .bind(command.session.device.network_hash.as_deref())
    .bind(command.session.device.user_agent.as_deref())
    .bind(mapping::authentication_method_name(
        command.session.authentication_method,
    )?)
    .bind(command.session.second_factor_verified_at)
    .bind(command.session.created_at)
    .bind(command.session.last_seen_at)
    .bind(command.session.expires_at)
    .execute(&mut *connection)
    .await
    .map_err(mapping::storage)?;
    insert_access(
        connection,
        command.session.realm_id,
        command.session.id,
        &command.access,
    )
    .await?;
    sqlx::query(
        "INSERT INTO refresh_tokens(realm_id,digest,session_id,family_id,expires_at) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(command.session.realm_id.as_uuid())
    .bind(command.refresh_digest.as_bytes().as_slice())
    .bind(command.session.id.as_uuid())
    .bind(command.family_id.as_uuid())
    .bind(command.session.expires_at)
    .execute(&mut *connection)
    .await
    .map_err(mapping::storage)?;
    mapping::insert_audit(connection, &command.audit).await
}

pub(crate) async fn insert_access(
    connection: &mut PgConnection,
    realm_id: RealmId,
    session_id: SessionId,
    access: &AccessTokenRecord,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO access_tokens(realm_id,digest,session_id,expires_at) VALUES($1,$2,$3,$4)",
    )
    .bind(realm_id.as_uuid())
    .bind(access.digest.as_bytes().as_slice())
    .bind(session_id.as_uuid())
    .bind(access.expires_at)
    .execute(connection)
    .await
    .map(|_| ())
    .map_err(mapping::storage)
}

pub(crate) fn stored_session(row: &PgRow, realm_id: RealmId) -> Result<Session, AuthError> {
    Ok(Session {
        realm_id,
        id: SessionId::from_uuid(row.try_get("id").map_err(mapping::storage)?),
        user_id: UserId::from_uuid(row.try_get("user_id").map_err(mapping::storage)?),
        device: DeviceContext {
            name: row.try_get("device_name").map_err(mapping::storage)?,
            network_hash: row.try_get("network_hash").map_err(mapping::storage)?,
            user_agent: row.try_get("user_agent").map_err(mapping::storage)?,
        },
        authentication_method: mapping::parse_authentication_method(
            &row.try_get::<String, _>("authentication_method")
                .map_err(mapping::storage)?,
        )?,
        second_factor_verified_at: row
            .try_get("second_factor_verified_at")
            .map_err(mapping::storage)?,
        created_at: row.try_get("created_at").map_err(mapping::storage)?,
        last_seen_at: row.try_get("last_seen_at").map_err(mapping::storage)?,
        expires_at: row.try_get("expires_at").map_err(mapping::storage)?,
        revoked_at: row.try_get("revoked_at").map_err(mapping::storage)?,
    })
}
