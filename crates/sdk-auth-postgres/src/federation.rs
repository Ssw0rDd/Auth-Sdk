use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_core::{
    CompleteFederatedLink, FederatedIdentity, FederatedIdentityKey, FederatedLinkResolution,
    FederatedRegistrationResolution, FederatedResolution, FederationStore, PendingFederatedLink,
    RegisterFederatedUser,
};
use sdk_auth_error::AuthError;
use sdk_auth_types::{EmailAddress, FederatedIdentityId, RealmId, UserId};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{PostgresAuthStore, mapping, session};

#[async_trait]
impl FederationStore for PostgresAuthStore {
    async fn resolve_federated_user(
        &self,
        realm_id: RealmId,
        identity: FederatedIdentityKey,
        now: DateTime<Utc>,
    ) -> Result<Option<UserId>, AuthError> {
        sqlx::query_scalar::<_, Uuid>(
            "UPDATE federated_identities SET last_used_at=GREATEST(COALESCE(last_used_at,$4),$4) WHERE realm_id=$1 AND issuer=$2 AND subject=$3 AND revoked_at IS NULL RETURNING user_id",
        )
        .bind(realm_id.as_uuid())
        .bind(identity.issuer)
        .bind(identity.subject)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(mapping::storage)
        .map(|value| value.map(UserId::from_uuid))
    }

    async fn begin_federated_link(
        &self,
        pending: PendingFederatedLink,
    ) -> Result<FederatedResolution, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let linked_user = sqlx::query_scalar::<_, Uuid>(
            "SELECT user_id FROM federated_identities WHERE realm_id=$1 AND issuer=$2 AND subject=$3 AND revoked_at IS NULL",
        )
        .bind(pending.realm_id.as_uuid())
        .bind(&pending.identity.issuer)
        .bind(&pending.identity.subject)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        if let Some(user_id) = linked_user {
            return Ok(FederatedResolution::KnownIdentity(UserId::from_uuid(
                user_id,
            )));
        }
        let matched_user = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM users WHERE realm_id=$1 AND normalized_email=$2 FOR UPDATE",
        )
        .bind(pending.realm_id.as_uuid())
        .bind(pending.verified_email.normalized())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        let Some(user_id) = matched_user else {
            return Ok(FederatedResolution::RegistrationRequired);
        };
        sqlx::query(
            "DELETE FROM federated_link_challenges WHERE realm_id=$1 AND user_id=$2 AND issuer=$3 AND subject=$4 AND consumed_at IS NULL",
        )
        .bind(pending.realm_id.as_uuid())
        .bind(user_id)
        .bind(&pending.identity.issuer)
        .bind(&pending.identity.subject)
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        sqlx::query(
            "INSERT INTO federated_link_challenges(realm_id,digest,user_id,identity_id,provider_id,issuer,subject,verified_email,normalized_verified_email,expires_at,created_at,consumed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL)",
        )
        .bind(pending.realm_id.as_uuid())
        .bind(pending.digest.as_bytes().as_slice())
        .bind(user_id)
        .bind(pending.identity_id.as_uuid())
        .bind(&pending.provider_id)
        .bind(&pending.identity.issuer)
        .bind(&pending.identity.subject)
        .bind(pending.verified_email.as_str())
        .bind(pending.verified_email.normalized())
        .bind(pending.expires_at)
        .bind(pending.created_at)
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(FederatedResolution::LinkRequired(UserId::from_uuid(
            user_id,
        )))
    }

    async fn complete_federated_link(
        &self,
        command: CompleteFederatedLink,
    ) -> Result<FederatedLinkResolution, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let row = sqlx::query(
            "SELECT user_id,identity_id,provider_id,issuer,subject,verified_email,expires_at,consumed_at FROM federated_link_challenges WHERE realm_id=$1 AND digest=$2 FOR UPDATE",
        )
        .bind(command.realm_id.as_uuid())
        .bind(command.digest.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(FederatedLinkResolution::Invalid);
        };
        let consumed_at = row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("consumed_at")
            .map_err(mapping::storage)?;
        if consumed_at.is_some() {
            return Ok(FederatedLinkResolution::Reused);
        }
        let expires_at = row
            .try_get::<chrono::DateTime<chrono::Utc>, _>("expires_at")
            .map_err(mapping::storage)?;
        if expires_at <= command.now {
            return Ok(FederatedLinkResolution::Expired);
        }
        let user_id = UserId::from_uuid(row.try_get("user_id").map_err(mapping::storage)?);
        if user_id != command.user_id {
            return Ok(FederatedLinkResolution::Invalid);
        }
        let identity_id =
            FederatedIdentityId::from_uuid(row.try_get("identity_id").map_err(mapping::storage)?);
        let provider_id: String = row.try_get("provider_id").map_err(mapping::storage)?;
        let issuer: String = row.try_get("issuer").map_err(mapping::storage)?;
        let subject: String = row.try_get("subject").map_err(mapping::storage)?;
        let email = EmailAddress::parse(
            row.try_get::<String, _>("verified_email")
                .map_err(mapping::storage)?,
        )
        .map_err(|_| AuthError::storage_unavailable())?;
        let inserted = sqlx::query(
            "INSERT INTO federated_identities(realm_id,id,user_id,provider_id,issuer,subject,verified_email,normalized_verified_email,created_at,last_used_at,revoked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,NULL) ON CONFLICT(realm_id,issuer,subject) DO NOTHING",
        )
        .bind(command.realm_id.as_uuid())
        .bind(identity_id.as_uuid())
        .bind(command.user_id.as_uuid())
        .bind(&provider_id)
        .bind(&issuer)
        .bind(&subject)
        .bind(email.as_str())
        .bind(email.normalized())
        .bind(command.now)
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if inserted != 1 {
            let existing_user = sqlx::query_scalar::<_, Uuid>(
                "SELECT user_id FROM federated_identities WHERE realm_id=$1 AND issuer=$2 AND subject=$3",
            )
            .bind(command.realm_id.as_uuid())
            .bind(&issuer)
            .bind(&subject)
            .fetch_one(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
            return if existing_user == command.user_id.as_uuid() {
                Ok(FederatedLinkResolution::Reused)
            } else {
                Ok(FederatedLinkResolution::Conflict)
            };
        }
        let changed = sqlx::query(
            "UPDATE federated_link_challenges SET consumed_at=$1 WHERE realm_id=$2 AND digest=$3 AND consumed_at IS NULL",
        )
        .bind(command.now)
        .bind(command.realm_id.as_uuid())
        .bind(command.digest.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if changed != 1 {
            return Err(AuthError::storage_unavailable());
        }
        mapping::insert_audit(&mut transaction, &command.audit).await?;
        let identity = FederatedIdentity {
            id: identity_id,
            realm_id: command.realm_id,
            user_id: command.user_id,
            provider_id,
            issuer,
            subject,
            verified_email: email,
            created_at: command.now,
            last_used_at: None,
            revoked_at: None,
        };
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(FederatedLinkResolution::Linked(Box::new(identity)))
    }

    async fn register_federated_user(
        &self,
        command: RegisterFederatedUser,
    ) -> Result<FederatedRegistrationResolution, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let inserted_user = sqlx::query(
            "INSERT INTO users(realm_id,id,email,normalized_email,email_verified,password_hash,created_at,updated_at) VALUES($1,$2,$3,$4,$5,NULL,$6,$7) ON CONFLICT DO NOTHING",
        )
        .bind(command.user.realm_id.as_uuid())
        .bind(command.user.id.as_uuid())
        .bind(command.user.email.as_str())
        .bind(command.user.email.normalized())
        .bind(command.user.email_verified)
        .bind(command.user.created_at)
        .bind(command.user.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if inserted_user != 1 {
            return Ok(FederatedRegistrationResolution::Retry);
        }
        let inserted_identity = sqlx::query(
            "INSERT INTO federated_identities(realm_id,id,user_id,provider_id,issuer,subject,verified_email,normalized_verified_email,created_at,last_used_at,revoked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL) ON CONFLICT DO NOTHING",
        )
        .bind(command.identity.realm_id.as_uuid())
        .bind(command.identity.id.as_uuid())
        .bind(command.identity.user_id.as_uuid())
        .bind(&command.identity.provider_id)
        .bind(&command.identity.issuer)
        .bind(&command.identity.subject)
        .bind(command.identity.verified_email.as_str())
        .bind(command.identity.verified_email.normalized())
        .bind(command.identity.created_at)
        .bind(command.identity.last_used_at)
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        if inserted_identity != 1 {
            return Ok(FederatedRegistrationResolution::Retry);
        }
        session::insert_session(&mut transaction, &command.session).await?;
        mapping::insert_event(&mut transaction, &command.event).await?;
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(FederatedRegistrationResolution::Registered)
    }
}
