use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_core::{
    AttemptDecision, CompletePasskeyAuthentication, CompletePasskeyRegistration,
    PasskeyAuthenticationOutcome, PasskeyCeremonyKind, PasskeyCeremonyLookup,
    PasskeyRegistrationOutcome, PasskeyStore, PendingPasskeyCeremony, StoredPasskey,
};
use sdk_auth_crypto::TokenDigest;
use sdk_auth_error::AuthError;
use sdk_auth_types::{AuditRecord, DeviceContext, Passkey, PasskeyId, RealmId, SessionId, UserId};
use sqlx::{PgConnection, Row as _, postgres::PgRow};
use uuid::Uuid;

use crate::{PostgresAuthStore, mapping, session};

const CEREMONY_SELECT: &str = "SELECT user_id,session_id,kind,label,login_subject,device_name,network_hash,user_agent,remember_me,provider_id,state_format,state_blob,attempts,max_attempts,expires_at,created_at,consumed_at FROM passkey_ceremonies WHERE realm_id=$1 AND digest=$2";

#[async_trait]
impl PasskeyStore for PostgresAuthStore {
    async fn replace_passkey_registration(
        &self,
        ceremony: PendingPasskeyCeremony,
    ) -> Result<(), AuthError> {
        if ceremony.kind != PasskeyCeremonyKind::Registration || ceremony.session_id.is_none() {
            return Err(AuthError::invalid_input());
        }
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        sqlx::query("DELETE FROM passkey_ceremonies WHERE expires_at<=$1")
            .bind(ceremony.created_at)
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        sqlx::query("DELETE FROM passkey_ceremonies WHERE realm_id=$1 AND user_id=$2 AND session_id=$3 AND kind='registration' AND consumed_at IS NULL")
            .bind(ceremony.realm_id.as_uuid())
            .bind(ceremony.user_id.as_uuid())
            .bind(ceremony.session_id.map(SessionId::as_uuid))
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        insert_ceremony(&mut transaction, &ceremony).await?;
        transaction.commit().await.map_err(mapping::storage)
    }

    async fn create_passkey_authentication(
        &self,
        ceremony: PendingPasskeyCeremony,
    ) -> Result<(), AuthError> {
        if ceremony.kind != PasskeyCeremonyKind::Authentication || ceremony.session_id.is_some() {
            return Err(AuthError::invalid_input());
        }
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        sqlx::query("DELETE FROM passkey_ceremonies WHERE expires_at<=$1")
            .bind(ceremony.created_at)
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        insert_ceremony(&mut transaction, &ceremony).await?;
        transaction.commit().await.map_err(mapping::storage)
    }

    async fn load_passkey_ceremony(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        kind: PasskeyCeremonyKind,
        now: DateTime<Utc>,
    ) -> Result<PasskeyCeremonyLookup, AuthError> {
        let row = sqlx::query(CEREMONY_SELECT)
            .bind(realm_id.as_uuid())
            .bind(digest.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(PasskeyCeremonyLookup::Invalid);
        };
        ceremony_lookup(stored_ceremony(&row, realm_id, digest)?, kind, now)
    }

    async fn record_passkey_failure(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        sqlx::query("UPDATE passkey_ceremonies SET attempts=attempts+1 WHERE realm_id=$1 AND digest=$2 AND consumed_at IS NULL AND expires_at>$3 AND attempts<max_attempts")
            .bind(realm_id.as_uuid()).bind(digest.as_bytes().as_slice()).bind(now)
            .execute(&mut *transaction).await.map_err(mapping::storage)?;
        let row = sqlx::query("SELECT attempts,max_attempts,expires_at FROM passkey_ceremonies WHERE realm_id=$1 AND digest=$2 FOR UPDATE")
            .bind(realm_id.as_uuid()).bind(digest.as_bytes().as_slice())
            .fetch_optional(&mut *transaction).await.map_err(mapping::storage)?;
        transaction.commit().await.map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(AttemptDecision::Allowed);
        };
        if row
            .try_get::<i32, _>("attempts")
            .map_err(mapping::storage)?
            >= row
                .try_get::<i32, _>("max_attempts")
                .map_err(mapping::storage)?
        {
            Ok(AttemptDecision::BlockedUntil(
                row.try_get("expires_at").map_err(mapping::storage)?,
            ))
        } else {
            Ok(AttemptDecision::Allowed)
        }
    }

    async fn list_stored_passkeys(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<StoredPasskey>, AuthError> {
        let rows = sqlx::query(concat!(
            "SELECT id,label,credential_id,provider_id,credential_format,credential_blob,signature_counter,backup_eligible,backed_up,created_at,last_used_at,revoked_at FROM passkey_credentials ",
            "WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL ORDER BY created_at DESC"
        ))
        .bind(realm_id.as_uuid()).bind(user_id.as_uuid()).fetch_all(&self.pool).await.map_err(mapping::storage)?;
        rows.iter()
            .map(|row| stored_passkey(row, realm_id, user_id))
            .collect()
    }

    async fn complete_passkey_registration(
        &self,
        command: CompletePasskeyRegistration,
    ) -> Result<PasskeyRegistrationOutcome, AuthError> {
        let realm_id = command.credential.passkey.realm_id;
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let row = sqlx::query(concat!(
            "SELECT user_id,session_id,kind,label,login_subject,device_name,network_hash,user_agent,remember_me,provider_id,state_format,state_blob,attempts,max_attempts,expires_at,created_at,consumed_at ",
            "FROM passkey_ceremonies WHERE realm_id=$1 AND digest=$2 FOR UPDATE"
        ))
        .bind(realm_id.as_uuid()).bind(command.ceremony_digest.as_bytes().as_slice())
        .fetch_optional(&mut *transaction).await.map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(PasskeyRegistrationOutcome::Invalid);
        };
        let ceremony = stored_ceremony(&row, realm_id, command.ceremony_digest)?;
        match ceremony_lookup(
            ceremony.clone(),
            PasskeyCeremonyKind::Registration,
            command.now,
        )? {
            PasskeyCeremonyLookup::Invalid => return Ok(PasskeyRegistrationOutcome::Invalid),
            PasskeyCeremonyLookup::Reused => return Ok(PasskeyRegistrationOutcome::Reused),
            PasskeyCeremonyLookup::Expired => return Ok(PasskeyRegistrationOutcome::Expired),
            PasskeyCeremonyLookup::RateLimited => {
                return Ok(PasskeyRegistrationOutcome::RateLimited);
            }
            PasskeyCeremonyLookup::Active(_) => {}
        }
        if ceremony.ceremony.user_id != command.credential.passkey.user_id
            || ceremony.ceremony.provider_id != command.credential.provider_id
        {
            return Ok(PasskeyRegistrationOutcome::Invalid);
        }
        let inserted = sqlx::query("INSERT INTO passkey_credentials(realm_id,id,user_id,label,credential_id,provider_id,credential_format,credential_blob,signature_counter,backup_eligible,backed_up,created_at,last_used_at,revoked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
            .bind(realm_id.as_uuid()).bind(command.credential.passkey.id.as_uuid()).bind(command.credential.passkey.user_id.as_uuid())
            .bind(&command.credential.passkey.label).bind(&command.credential.credential_id).bind(&command.credential.provider_id)
            .bind(i16::try_from(command.credential.credential_format).map_err(|_| AuthError::storage_unavailable())?)
            .bind(&command.credential.credential_blob).bind(i64::from(command.credential.signature_counter))
            .bind(command.credential.passkey.backup_eligible).bind(command.credential.passkey.backed_up)
            .bind(command.credential.passkey.created_at).bind(command.credential.passkey.last_used_at).bind(command.credential.passkey.revoked_at)
            .execute(&mut *transaction).await;
        if let Err(error) = inserted {
            if mapping::is_unique_violation(&error) {
                consume_ceremony(
                    &mut transaction,
                    realm_id,
                    command.ceremony_digest,
                    command.now,
                )
                .await?;
                transaction.commit().await.map_err(mapping::storage)?;
                return Ok(PasskeyRegistrationOutcome::Conflict);
            }
            return Err(mapping::storage(error));
        }
        consume_ceremony(
            &mut transaction,
            realm_id,
            command.ceremony_digest,
            command.now,
        )
        .await?;
        mapping::insert_audit(&mut transaction, &command.audit).await?;
        let public = command.credential.passkey;
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(PasskeyRegistrationOutcome::Completed(Box::new(public)))
    }

    async fn complete_passkey_authentication(
        &self,
        command: CompletePasskeyAuthentication,
    ) -> Result<PasskeyAuthenticationOutcome, AuthError> {
        let realm_id = command.session.session.realm_id;
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let row = sqlx::query(concat!(
            "SELECT user_id,session_id,kind,label,login_subject,device_name,network_hash,user_agent,remember_me,provider_id,state_format,state_blob,attempts,max_attempts,expires_at,created_at,consumed_at ",
            "FROM passkey_ceremonies WHERE realm_id=$1 AND digest=$2 FOR UPDATE"
        ))
        .bind(realm_id.as_uuid()).bind(command.ceremony_digest.as_bytes().as_slice())
        .fetch_optional(&mut *transaction).await.map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(PasskeyAuthenticationOutcome::Invalid);
        };
        let ceremony = stored_ceremony(&row, realm_id, command.ceremony_digest)?;
        match ceremony_lookup(
            ceremony.clone(),
            PasskeyCeremonyKind::Authentication,
            command.now,
        )? {
            PasskeyCeremonyLookup::Invalid => return Ok(PasskeyAuthenticationOutcome::Invalid),
            PasskeyCeremonyLookup::Reused => return Ok(PasskeyAuthenticationOutcome::Reused),
            PasskeyCeremonyLookup::Expired => return Ok(PasskeyAuthenticationOutcome::Expired),
            PasskeyCeremonyLookup::RateLimited => {
                return Ok(PasskeyAuthenticationOutcome::RateLimited);
            }
            PasskeyCeremonyLookup::Active(_) => {}
        }
        if ceremony.ceremony.user_id != command.session.session.user_id {
            return Ok(PasskeyAuthenticationOutcome::Invalid);
        }
        let credential = sqlx::query("SELECT user_id,provider_id,credential_format,signature_counter,revoked_at FROM passkey_credentials WHERE realm_id=$1 AND id=$2 FOR UPDATE")
            .bind(realm_id.as_uuid()).bind(command.passkey_id.as_uuid()).fetch_optional(&mut *transaction).await.map_err(mapping::storage)?;
        let Some(credential) = credential else {
            return Ok(PasskeyAuthenticationOutcome::Invalid);
        };
        let stored_user = UserId::from_uuid(
            credential
                .try_get::<Uuid, _>("user_id")
                .map_err(mapping::storage)?,
        );
        let provider_id: String = credential
            .try_get("provider_id")
            .map_err(mapping::storage)?;
        let format = u16::try_from(
            credential
                .try_get::<i16, _>("credential_format")
                .map_err(mapping::storage)?,
        )
        .map_err(|_| AuthError::storage_unavailable())?;
        let revoked_at: Option<DateTime<Utc>> =
            credential.try_get("revoked_at").map_err(mapping::storage)?;
        if stored_user != ceremony.ceremony.user_id
            || revoked_at.is_some()
            || provider_id != command.provider_id
            || format != command.credential_format
        {
            return Ok(PasskeyAuthenticationOutcome::Invalid);
        }
        let old_counter = u32::try_from(
            credential
                .try_get::<i64, _>("signature_counter")
                .map_err(mapping::storage)?,
        )
        .map_err(|_| AuthError::storage_unavailable())?;
        if old_counter > 0
            && command.signature_counter > 0
            && command.signature_counter <= old_counter
        {
            sqlx::query("UPDATE passkey_credentials SET revoked_at=$1 WHERE realm_id=$2 AND id=$3 AND revoked_at IS NULL")
                .bind(command.now).bind(realm_id.as_uuid()).bind(command.passkey_id.as_uuid()).execute(&mut *transaction).await.map_err(mapping::storage)?;
            consume_ceremony(
                &mut transaction,
                realm_id,
                command.ceremony_digest,
                command.now,
            )
            .await?;
            mapping::insert_audit(&mut transaction, &command.clone_audit).await?;
            transaction.commit().await.map_err(mapping::storage)?;
            return Ok(PasskeyAuthenticationOutcome::CloneSuspected);
        }
        sqlx::query("UPDATE passkey_credentials SET credential_blob=$1,signature_counter=$2,backup_eligible=(backup_eligible OR $3),backed_up=$4,last_used_at=$5 WHERE realm_id=$6 AND id=$7 AND revoked_at IS NULL")
            .bind(command.credential_blob).bind(i64::from(old_counter.max(command.signature_counter))).bind(command.backup_eligible)
            .bind(command.backed_up).bind(command.now).bind(realm_id.as_uuid()).bind(command.passkey_id.as_uuid())
            .execute(&mut *transaction).await.map_err(mapping::storage)?;
        if consume_ceremony(
            &mut transaction,
            realm_id,
            command.ceremony_digest,
            command.now,
        )
        .await?
            != 1
        {
            return Ok(PasskeyAuthenticationOutcome::Reused);
        }
        let session_value = command.session.session.clone();
        session::insert_session(&mut transaction, &command.session).await?;
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(PasskeyAuthenticationOutcome::Completed(Box::new(
            session_value,
        )))
    }

    async fn list_passkeys(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Passkey>, AuthError> {
        let rows = sqlx::query(concat!(
            "SELECT id,label,credential_id,provider_id,credential_format,credential_blob,signature_counter,backup_eligible,backed_up,created_at,last_used_at,revoked_at FROM passkey_credentials ",
            "WHERE realm_id=$1 AND user_id=$2 ORDER BY created_at DESC"
        )).bind(realm_id.as_uuid()).bind(user_id.as_uuid()).fetch_all(&self.pool).await.map_err(mapping::storage)?;
        rows.iter()
            .map(|row| stored_passkey(row, realm_id, user_id).map(|stored| stored.passkey))
            .collect()
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
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let changed = sqlx::query("UPDATE passkey_credentials SET label=$1 WHERE realm_id=$2 AND id=$3 AND user_id=$4 AND revoked_at IS NULL")
            .bind(label).bind(realm_id.as_uuid()).bind(passkey_id.as_uuid()).bind(user_id.as_uuid()).execute(&mut *transaction).await.map_err(mapping::storage)?.rows_affected();
        if changed == 1 {
            mapping::insert_audit(&mut transaction, &audit).await?;
        }
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(changed == 1)
    }

    async fn revoke_passkey(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        passkey_id: PasskeyId,
        revoked_at: DateTime<Utc>,
        audit: AuditRecord,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let changed = sqlx::query("UPDATE passkey_credentials SET revoked_at=$1 WHERE realm_id=$2 AND id=$3 AND user_id=$4 AND revoked_at IS NULL")
            .bind(revoked_at).bind(realm_id.as_uuid()).bind(passkey_id.as_uuid()).bind(user_id.as_uuid()).execute(&mut *transaction).await.map_err(mapping::storage)?.rows_affected();
        if changed == 1 {
            mapping::insert_audit(&mut transaction, &audit).await?;
        }
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(changed == 1)
    }
}

async fn insert_ceremony(
    connection: &mut PgConnection,
    ceremony: &PendingPasskeyCeremony,
) -> Result<(), AuthError> {
    sqlx::query("INSERT INTO passkey_ceremonies(realm_id,digest,user_id,session_id,kind,label,login_subject,device_name,network_hash,user_agent,remember_me,provider_id,state_format,state_blob,attempts,max_attempts,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)")
        .bind(ceremony.realm_id.as_uuid()).bind(ceremony.digest.as_bytes().as_slice()).bind(ceremony.user_id.as_uuid())
        .bind(ceremony.session_id.map(SessionId::as_uuid)).bind(ceremony_kind_name(ceremony.kind)).bind(&ceremony.label).bind(&ceremony.login_subject)
        .bind(&ceremony.device.name).bind(&ceremony.device.network_hash).bind(&ceremony.device.user_agent).bind(ceremony.remember_me).bind(&ceremony.provider_id)
        .bind(i16::try_from(ceremony.state_format).map_err(|_| AuthError::storage_unavailable())?).bind(&ceremony.state)
        .bind(i32::try_from(ceremony.attempts).map_err(|_| AuthError::storage_unavailable())?).bind(i32::try_from(ceremony.max_attempts).map_err(|_| AuthError::storage_unavailable())?)
        .bind(ceremony.expires_at).bind(ceremony.created_at).execute(connection).await.map(|_| ()).map_err(mapping::storage)
}

async fn consume_ceremony(
    connection: &mut PgConnection,
    realm_id: RealmId,
    digest: TokenDigest,
    now: DateTime<Utc>,
) -> Result<u64, AuthError> {
    sqlx::query("UPDATE passkey_ceremonies SET consumed_at=$1 WHERE realm_id=$2 AND digest=$3 AND consumed_at IS NULL")
        .bind(now).bind(realm_id.as_uuid()).bind(digest.as_bytes().as_slice()).execute(connection).await.map(|result| result.rows_affected()).map_err(mapping::storage)
}

#[derive(Clone)]
struct StoredCeremonyRow {
    ceremony: PendingPasskeyCeremony,
    consumed_at: Option<DateTime<Utc>>,
}

fn stored_ceremony(
    row: &PgRow,
    realm_id: RealmId,
    digest: TokenDigest,
) -> Result<StoredCeremonyRow, AuthError> {
    Ok(StoredCeremonyRow {
        ceremony: PendingPasskeyCeremony {
            digest,
            realm_id,
            user_id: UserId::from_uuid(row.try_get("user_id").map_err(mapping::storage)?),
            session_id: row
                .try_get::<Option<Uuid>, _>("session_id")
                .map_err(mapping::storage)?
                .map(SessionId::from_uuid),
            kind: parse_ceremony_kind(
                &row.try_get::<String, _>("kind").map_err(mapping::storage)?,
            )?,
            label: row.try_get("label").map_err(mapping::storage)?,
            login_subject: row.try_get("login_subject").map_err(mapping::storage)?,
            device: DeviceContext {
                name: row.try_get("device_name").map_err(mapping::storage)?,
                network_hash: row.try_get("network_hash").map_err(mapping::storage)?,
                user_agent: row.try_get("user_agent").map_err(mapping::storage)?,
            },
            remember_me: row.try_get("remember_me").map_err(mapping::storage)?,
            provider_id: row.try_get("provider_id").map_err(mapping::storage)?,
            state_format: u16::try_from(
                row.try_get::<i16, _>("state_format")
                    .map_err(mapping::storage)?,
            )
            .map_err(|_| AuthError::storage_unavailable())?,
            state: row.try_get("state_blob").map_err(mapping::storage)?,
            attempts: u32::try_from(
                row.try_get::<i32, _>("attempts")
                    .map_err(mapping::storage)?,
            )
            .map_err(|_| AuthError::storage_unavailable())?,
            max_attempts: u32::try_from(
                row.try_get::<i32, _>("max_attempts")
                    .map_err(mapping::storage)?,
            )
            .map_err(|_| AuthError::storage_unavailable())?,
            expires_at: row.try_get("expires_at").map_err(mapping::storage)?,
            created_at: row.try_get("created_at").map_err(mapping::storage)?,
        },
        consumed_at: row.try_get("consumed_at").map_err(mapping::storage)?,
    })
}

fn ceremony_lookup(
    row: StoredCeremonyRow,
    expected: PasskeyCeremonyKind,
    now: DateTime<Utc>,
) -> Result<PasskeyCeremonyLookup, AuthError> {
    if row.ceremony.kind != expected {
        Ok(PasskeyCeremonyLookup::Invalid)
    } else if row.consumed_at.is_some() {
        Ok(PasskeyCeremonyLookup::Reused)
    } else if row.ceremony.expires_at <= now {
        Ok(PasskeyCeremonyLookup::Expired)
    } else if row.ceremony.attempts >= row.ceremony.max_attempts {
        Ok(PasskeyCeremonyLookup::RateLimited)
    } else {
        Ok(PasskeyCeremonyLookup::Active(Box::new(row.ceremony)))
    }
}

fn stored_passkey(
    row: &PgRow,
    realm_id: RealmId,
    user_id: UserId,
) -> Result<StoredPasskey, AuthError> {
    Ok(StoredPasskey {
        passkey: Passkey {
            realm_id,
            id: PasskeyId::from_uuid(row.try_get("id").map_err(mapping::storage)?),
            user_id,
            label: row.try_get("label").map_err(mapping::storage)?,
            backup_eligible: row.try_get("backup_eligible").map_err(mapping::storage)?,
            backed_up: row.try_get("backed_up").map_err(mapping::storage)?,
            created_at: row.try_get("created_at").map_err(mapping::storage)?,
            last_used_at: row.try_get("last_used_at").map_err(mapping::storage)?,
            revoked_at: row.try_get("revoked_at").map_err(mapping::storage)?,
        },
        credential_id: row.try_get("credential_id").map_err(mapping::storage)?,
        provider_id: row.try_get("provider_id").map_err(mapping::storage)?,
        credential_format: u16::try_from(
            row.try_get::<i16, _>("credential_format")
                .map_err(mapping::storage)?,
        )
        .map_err(|_| AuthError::storage_unavailable())?,
        credential_blob: row.try_get("credential_blob").map_err(mapping::storage)?,
        signature_counter: u32::try_from(
            row.try_get::<i64, _>("signature_counter")
                .map_err(mapping::storage)?,
        )
        .map_err(|_| AuthError::storage_unavailable())?,
    })
}

const fn ceremony_kind_name(kind: PasskeyCeremonyKind) -> &'static str {
    match kind {
        PasskeyCeremonyKind::Registration => "registration",
        PasskeyCeremonyKind::Authentication => "authentication",
    }
}
fn parse_ceremony_kind(value: &str) -> Result<PasskeyCeremonyKind, AuthError> {
    match value {
        "registration" => Ok(PasskeyCeremonyKind::Registration),
        "authentication" => Ok(PasskeyCeremonyKind::Authentication),
        _ => Err(AuthError::storage_unavailable()),
    }
}
