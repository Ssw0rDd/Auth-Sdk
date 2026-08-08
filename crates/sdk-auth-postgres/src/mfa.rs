use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_core::{
    ActivateTotp, AttemptDecision, CompleteMfaLogin, CreateTrustedDevice, MfaChallengeLookup,
    MfaCompletionOutcome, MfaEnrollmentOutcome, MfaStore, PendingTotpEnrollment,
    RotateTrustedLogin, StoredMfaLoginChallenge, StoredTotpFactor, TrustedLoginOutcome,
    VerifiedMfaProof,
};
use sdk_auth_crypto::{AeadAlgorithm, SealedSecret, TokenDigest};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::{
    AuthEvent, DeviceContext, MfaEnrollmentId, MfaFactorId, RealmId, TrustedDevice,
    TrustedDeviceId, UserId,
};
use sqlx::{PgConnection, Row as _, postgres::PgRow};
use uuid::Uuid;

use crate::{PostgresAuthStore, mapping, session};

#[async_trait]
impl MfaStore for PostgresAuthStore {
    async fn find_totp_factor(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Option<StoredTotpFactor>, AuthError> {
        let row = sqlx::query(
            "SELECT id,format_version,algorithm,key_id,nonce,ciphertext,last_accepted_counter,created_at,updated_at FROM mfa_totp_factors WHERE realm_id=$1 AND user_id=$2",
        )
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(mapping::storage)?;
        row.as_ref()
            .map(|row| stored_factor(row, realm_id, user_id))
            .transpose()
    }

    async fn replace_totp_enrollment(
        &self,
        enrollment: PendingTotpEnrollment,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        lock_user(&mut transaction, enrollment.realm_id, enrollment.user_id).await?;
        let has_factor = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM mfa_totp_factors WHERE realm_id=$1 AND user_id=$2)",
        )
        .bind(enrollment.realm_id.as_uuid())
        .bind(enrollment.user_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        if has_factor != enrollment.replacing {
            return Err(AuthError::new(
                ErrorCode::Conflict,
                "MFA enrollment conflicts with current factor state",
                false,
            ));
        }
        sqlx::query("DELETE FROM mfa_enrollments WHERE realm_id=$1 AND user_id=$2")
            .bind(enrollment.realm_id.as_uuid())
            .bind(enrollment.user_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        insert_enrollment(&mut transaction, &enrollment).await?;
        transaction.commit().await.map_err(mapping::storage)
    }

    async fn find_totp_enrollment(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
    ) -> Result<Option<PendingTotpEnrollment>, AuthError> {
        let row = sqlx::query(
            "SELECT id,format_version,algorithm,key_id,nonce,ciphertext,replacing,attempts,max_attempts,expires_at,created_at FROM mfa_enrollments WHERE realm_id=$1 AND user_id=$2 AND id=$3",
        )
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(enrollment_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(mapping::storage)?;
        row.as_ref()
            .map(|row| stored_enrollment(row, realm_id, user_id))
            .transpose()
    }

    async fn record_totp_enrollment_failure(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        enrollment_id: MfaEnrollmentId,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let row = sqlx::query(
            "SELECT attempts,max_attempts,expires_at FROM mfa_enrollments WHERE realm_id=$1 AND user_id=$2 AND id=$3 FOR UPDATE",
        )
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(enrollment_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(AttemptDecision::BlockedUntil(now));
        };
        let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(mapping::storage)?;
        if expires_at <= now {
            return Ok(AttemptDecision::BlockedUntil(now));
        }
        let attempts = row
            .try_get::<i32, _>("attempts")
            .map_err(mapping::storage)?
            .saturating_add(1);
        let max_attempts: i32 = row.try_get("max_attempts").map_err(mapping::storage)?;
        sqlx::query(
            "UPDATE mfa_enrollments SET attempts=$1 WHERE realm_id=$2 AND user_id=$3 AND id=$4",
        )
        .bind(attempts)
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(enrollment_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        transaction.commit().await.map_err(mapping::storage)?;
        if attempts >= max_attempts {
            Ok(AttemptDecision::BlockedUntil(expires_at))
        } else {
            Ok(AttemptDecision::Allowed)
        }
    }

    async fn activate_totp(
        &self,
        command: ActivateTotp,
    ) -> Result<MfaEnrollmentOutcome, AuthError> {
        let realm_id = command.factor.realm_id;
        let user_id = command.factor.user_id;
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        lock_user(&mut transaction, realm_id, user_id).await?;
        let row = sqlx::query(
            "SELECT id,format_version,algorithm,key_id,nonce,ciphertext,replacing,attempts,max_attempts,expires_at,created_at FROM mfa_enrollments WHERE realm_id=$1 AND user_id=$2 FOR UPDATE",
        )
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(MfaEnrollmentOutcome::Invalid);
        };
        let enrollment = stored_enrollment(&row, realm_id, user_id)?;
        let has_factor = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM mfa_totp_factors WHERE realm_id=$1 AND user_id=$2)",
        )
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        if enrollment.id != command.enrollment_id || enrollment.replacing != has_factor {
            return Ok(MfaEnrollmentOutcome::Invalid);
        }
        if enrollment.expires_at <= command.now {
            return Ok(MfaEnrollmentOutcome::Expired);
        }
        if enrollment.attempts >= enrollment.max_attempts {
            return Ok(MfaEnrollmentOutcome::RateLimited);
        }
        let current_session = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND revoked_at IS NULL AND expires_at>$4)",
        )
        .bind(realm_id.as_uuid())
        .bind(command.current_session_id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(command.now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        if !current_session {
            return Ok(MfaEnrollmentOutcome::Invalid);
        }
        sqlx::query("UPDATE sessions SET authentication_method='password_totp',second_factor_verified_at=$1 WHERE realm_id=$2 AND id=$3")
            .bind(command.now)
            .bind(realm_id.as_uuid())
            .bind(command.current_session_id.as_uuid())
            .execute(&mut *transaction).await.map_err(mapping::storage)?;
        sqlx::query("UPDATE sessions SET revoked_at=$1 WHERE realm_id=$2 AND user_id=$3 AND id<>$4 AND revoked_at IS NULL")
            .bind(command.now).bind(realm_id.as_uuid()).bind(user_id.as_uuid())
            .bind(command.current_session_id.as_uuid()).execute(&mut *transaction).await.map_err(mapping::storage)?;
        revoke_trusted_devices(&mut transaction, realm_id, user_id, command.now).await?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE realm_id=$1 AND user_id=$2")
            .bind(realm_id.as_uuid())
            .bind(user_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        for digest in &command.recovery_digests {
            insert_recovery_code(&mut transaction, realm_id, user_id, *digest, command.now).await?;
        }
        sqlx::query("DELETE FROM mfa_totp_factors WHERE realm_id=$1 AND user_id=$2")
            .bind(realm_id.as_uuid())
            .bind(user_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        insert_factor(&mut transaction, &command.factor).await?;
        sqlx::query("DELETE FROM mfa_enrollments WHERE realm_id=$1 AND user_id=$2")
            .bind(realm_id.as_uuid())
            .bind(user_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        if let Some(trusted) = &command.trusted_device {
            insert_trusted_device(&mut transaction, trusted).await?;
        }
        insert_events(&mut transaction, &command.events).await?;
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(MfaEnrollmentOutcome::Activated)
    }

    async fn create_mfa_login_challenge(
        &self,
        challenge: StoredMfaLoginChallenge,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        sqlx::query("DELETE FROM mfa_login_challenges WHERE realm_id=$1 AND user_id=$2 AND consumed_at IS NULL")
            .bind(challenge.realm_id.as_uuid()).bind(challenge.user_id.as_uuid())
            .execute(&mut *transaction).await.map_err(mapping::storage)?;
        insert_mfa_challenge(&mut transaction, &challenge).await?;
        transaction.commit().await.map_err(mapping::storage)
    }

    async fn load_mfa_login_challenge(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<MfaChallengeLookup, AuthError> {
        let row = sqlx::query("SELECT user_id,device_name,network_hash,user_agent,remember_me,attempts,max_attempts,expires_at,created_at,consumed_at FROM mfa_login_challenges WHERE realm_id=$1 AND digest=$2")
            .bind(realm_id.as_uuid()).bind(digest.as_bytes().as_slice())
            .fetch_optional(&self.pool).await.map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(MfaChallengeLookup::Invalid);
        };
        let stored = stored_mfa_challenge(&row, realm_id, digest)?;
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
        let factor = self.find_totp_factor(realm_id, challenge.user_id).await?;
        let Some(factor) = factor else {
            return Ok(MfaChallengeLookup::Invalid);
        };
        Ok(MfaChallengeLookup::Active {
            challenge: Box::new(challenge),
            factor: Box::new(factor),
        })
    }

    async fn record_mfa_login_failure(
        &self,
        realm_id: RealmId,
        digest: TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<AttemptDecision, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let row = sqlx::query("SELECT attempts,max_attempts,expires_at,consumed_at FROM mfa_login_challenges WHERE realm_id=$1 AND digest=$2 FOR UPDATE")
            .bind(realm_id.as_uuid()).bind(digest.as_bytes().as_slice())
            .fetch_optional(&mut *transaction).await.map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(AttemptDecision::BlockedUntil(now));
        };
        let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(mapping::storage)?;
        let consumed_at: Option<DateTime<Utc>> =
            row.try_get("consumed_at").map_err(mapping::storage)?;
        if consumed_at.is_some() || expires_at <= now {
            return Ok(AttemptDecision::BlockedUntil(now));
        }
        let attempts = row
            .try_get::<i32, _>("attempts")
            .map_err(mapping::storage)?
            .saturating_add(1);
        let max_attempts: i32 = row.try_get("max_attempts").map_err(mapping::storage)?;
        sqlx::query("UPDATE mfa_login_challenges SET attempts=$1 WHERE realm_id=$2 AND digest=$3")
            .bind(attempts)
            .bind(realm_id.as_uuid())
            .bind(digest.as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        transaction.commit().await.map_err(mapping::storage)?;
        if attempts >= max_attempts {
            Ok(AttemptDecision::BlockedUntil(expires_at))
        } else {
            Ok(AttemptDecision::Allowed)
        }
    }

    async fn complete_mfa_login(
        &self,
        command: CompleteMfaLogin,
    ) -> Result<MfaCompletionOutcome, AuthError> {
        let realm_id = command.session.session.realm_id;
        let user_id = command.session.session.user_id;
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let row = sqlx::query("SELECT user_id,attempts,max_attempts,expires_at,consumed_at FROM mfa_login_challenges WHERE realm_id=$1 AND digest=$2 FOR UPDATE")
            .bind(realm_id.as_uuid()).bind(command.challenge_digest.as_bytes().as_slice())
            .fetch_optional(&mut *transaction).await.map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(MfaCompletionOutcome::Invalid);
        };
        if UserId::from_uuid(
            row.try_get::<Uuid, _>("user_id")
                .map_err(mapping::storage)?,
        ) != user_id
        {
            return Ok(MfaCompletionOutcome::Invalid);
        }
        let consumed_at: Option<DateTime<Utc>> =
            row.try_get("consumed_at").map_err(mapping::storage)?;
        if consumed_at.is_some() {
            return Ok(MfaCompletionOutcome::Reused);
        }
        if row
            .try_get::<DateTime<Utc>, _>("expires_at")
            .map_err(mapping::storage)?
            <= command.now
        {
            return Ok(MfaCompletionOutcome::Expired);
        }
        if row
            .try_get::<i32, _>("attempts")
            .map_err(mapping::storage)?
            >= row
                .try_get::<i32, _>("max_attempts")
                .map_err(mapping::storage)?
        {
            return Ok(MfaCompletionOutcome::RateLimited);
        }
        match command.proof {
            VerifiedMfaProof::Totp { factor_id, counter } => {
                let factor = sqlx::query("SELECT id,last_accepted_counter FROM mfa_totp_factors WHERE realm_id=$1 AND user_id=$2 FOR UPDATE")
                    .bind(realm_id.as_uuid()).bind(user_id.as_uuid()).fetch_optional(&mut *transaction).await.map_err(mapping::storage)?;
                let Some(factor) = factor else {
                    return Ok(MfaCompletionOutcome::Invalid);
                };
                if MfaFactorId::from_uuid(
                    factor.try_get::<Uuid, _>("id").map_err(mapping::storage)?,
                ) != factor_id
                {
                    return Ok(MfaCompletionOutcome::Invalid);
                }
                let counter = counter_to_sql(counter)?;
                if factor
                    .try_get::<Option<i64>, _>("last_accepted_counter")
                    .map_err(mapping::storage)?
                    .is_some_and(|last| counter <= last)
                {
                    return Ok(MfaCompletionOutcome::Reused);
                }
                sqlx::query("UPDATE mfa_totp_factors SET last_accepted_counter=$1,updated_at=$2 WHERE realm_id=$3 AND user_id=$4 AND id=$5")
                    .bind(counter).bind(command.now).bind(realm_id.as_uuid()).bind(user_id.as_uuid()).bind(factor_id.as_uuid())
                    .execute(&mut *transaction).await.map_err(mapping::storage)?;
            }
            VerifiedMfaProof::RecoveryCode(digest) => {
                let recovery = sqlx::query("SELECT consumed_at FROM mfa_recovery_codes WHERE realm_id=$1 AND user_id=$2 AND digest=$3 FOR UPDATE")
                    .bind(realm_id.as_uuid()).bind(user_id.as_uuid()).bind(digest.as_bytes().as_slice())
                    .fetch_optional(&mut *transaction).await.map_err(mapping::storage)?;
                let Some(recovery) = recovery else {
                    return Ok(MfaCompletionOutcome::Invalid);
                };
                if recovery
                    .try_get::<Option<DateTime<Utc>>, _>("consumed_at")
                    .map_err(mapping::storage)?
                    .is_some()
                {
                    return Ok(MfaCompletionOutcome::Reused);
                }
                sqlx::query("UPDATE mfa_recovery_codes SET consumed_at=$1 WHERE realm_id=$2 AND user_id=$3 AND digest=$4 AND consumed_at IS NULL")
                    .bind(command.now).bind(realm_id.as_uuid()).bind(user_id.as_uuid()).bind(digest.as_bytes().as_slice())
                    .execute(&mut *transaction).await.map_err(mapping::storage)?;
            }
        }
        let consumed = sqlx::query("UPDATE mfa_login_challenges SET consumed_at=$1 WHERE realm_id=$2 AND digest=$3 AND consumed_at IS NULL")
            .bind(command.now).bind(realm_id.as_uuid()).bind(command.challenge_digest.as_bytes().as_slice())
            .execute(&mut *transaction).await.map_err(mapping::storage)?.rows_affected();
        if consumed != 1 {
            return Ok(MfaCompletionOutcome::Reused);
        }
        session::insert_session(&mut transaction, &command.session).await?;
        let trusted_device = if let Some(trusted) = &command.trusted_device {
            insert_trusted_device(&mut transaction, trusted).await?;
            Some(Box::new(trusted.device.clone()))
        } else {
            None
        };
        insert_events(&mut transaction, &command.events).await?;
        let session = command.session.session.clone();
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(MfaCompletionOutcome::Completed {
            session: Box::new(session),
            trusted_device,
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
            session: new_session,
            now,
            mut replay_event,
        } = command;
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let row = sqlx::query("SELECT d.id,d.user_id,d.device_name,d.network_hash,d.user_agent,d.created_at,d.last_used_at,d.expires_at,d.revoked_at,t.expires_at AS token_expires_at,t.consumed_at FROM trusted_device_tokens t JOIN trusted_devices d ON d.realm_id=t.realm_id AND d.id=t.device_id WHERE t.realm_id=$1 AND t.digest=$2 FOR UPDATE OF t,d")
            .bind(realm_id.as_uuid()).bind(presented.as_bytes().as_slice())
            .fetch_optional(&mut *transaction).await.map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(TrustedLoginOutcome::Invalid);
        };
        let stored = stored_trusted_token(&row, realm_id)?;
        let mut device = stored.device;
        if stored.consumed_at.is_some() {
            sqlx::query("UPDATE trusted_devices SET revoked_at=COALESCE(revoked_at,$1) WHERE realm_id=$2 AND id=$3")
                .bind(now).bind(realm_id.as_uuid()).bind(device.id.as_uuid()).execute(&mut *transaction).await.map_err(mapping::storage)?;
            replay_event.user_id = device.user_id;
            mapping::insert_event(&mut transaction, &replay_event).await?;
            transaction.commit().await.map_err(mapping::storage)?;
            return Ok(TrustedLoginOutcome::Reused);
        }
        if device.user_id != user_id
            || device.revoked_at.is_some()
            || device.expires_at <= now
            || stored.token_expires_at <= now
        {
            return Ok(TrustedLoginOutcome::Invalid);
        }
        let changed = sqlx::query("UPDATE trusted_device_tokens SET consumed_at=$1 WHERE realm_id=$2 AND digest=$3 AND consumed_at IS NULL")
            .bind(now).bind(realm_id.as_uuid()).bind(presented.as_bytes().as_slice()).execute(&mut *transaction).await.map_err(mapping::storage)?.rows_affected();
        if changed != 1 {
            return Ok(TrustedLoginOutcome::Reused);
        }
        sqlx::query("INSERT INTO trusted_device_tokens(realm_id,digest,device_id,expires_at) VALUES($1,$2,$3,$4)")
            .bind(realm_id.as_uuid()).bind(replacement.as_bytes().as_slice()).bind(device.id.as_uuid()).bind(device.expires_at)
            .execute(&mut *transaction).await.map_err(mapping::storage)?;
        sqlx::query("UPDATE trusted_devices SET last_used_at=$1 WHERE realm_id=$2 AND id=$3")
            .bind(now)
            .bind(realm_id.as_uuid())
            .bind(device.id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        device.last_used_at = now;
        let created_session = new_session.session.clone();
        session::insert_session(&mut transaction, &new_session).await?;
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(TrustedLoginOutcome::Authenticated {
            session: Box::new(created_session),
            trusted_device: Box::new(device),
        })
    }

    async fn accept_management_totp(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        factor_id: MfaFactorId,
        counter: u64,
    ) -> Result<bool, AuthError> {
        let counter = counter_to_sql(counter)?;
        let changed = sqlx::query("UPDATE mfa_totp_factors SET last_accepted_counter=$1 WHERE realm_id=$2 AND user_id=$3 AND id=$4 AND (last_accepted_counter IS NULL OR last_accepted_counter<$1)")
            .bind(counter).bind(realm_id.as_uuid()).bind(user_id.as_uuid()).bind(factor_id.as_uuid())
            .execute(&self.pool).await.map_err(mapping::storage)?.rows_affected();
        Ok(changed == 1)
    }

    async fn consume_management_recovery(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        digest: TokenDigest,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let changed = sqlx::query("UPDATE mfa_recovery_codes SET consumed_at=$1 WHERE realm_id=$2 AND user_id=$3 AND digest=$4 AND consumed_at IS NULL")
            .bind(event.created_at).bind(realm_id.as_uuid()).bind(user_id.as_uuid()).bind(digest.as_bytes().as_slice())
            .execute(&mut *transaction).await.map_err(mapping::storage)?.rows_affected();
        if changed != 1 {
            return Ok(false);
        }
        mapping::insert_event(&mut transaction, &event).await?;
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(true)
    }

    async fn replace_recovery_codes(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        digests: Vec<TokenDigest>,
        event: AuthEvent,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let factor = sqlx::query(
            "SELECT 1 FROM mfa_totp_factors WHERE realm_id=$1 AND user_id=$2 FOR UPDATE",
        )
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        if factor.is_none() {
            return Err(AuthError::new(
                ErrorCode::MfaNotEnrolled,
                "MFA is not enrolled",
                false,
            ));
        }
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE realm_id=$1 AND user_id=$2")
            .bind(realm_id.as_uuid())
            .bind(user_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        for digest in digests {
            insert_recovery_code(
                &mut transaction,
                realm_id,
                user_id,
                digest,
                event.created_at,
            )
            .await?;
        }
        mapping::insert_event(&mut transaction, &event).await?;
        transaction.commit().await.map_err(mapping::storage)
    }

    async fn disable_mfa(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let changed = sqlx::query("DELETE FROM mfa_totp_factors WHERE realm_id=$1 AND user_id=$2")
            .bind(realm_id.as_uuid())
            .bind(user_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?
            .rows_affected();
        if changed != 1 {
            return Ok(false);
        }
        for sql in [
            "DELETE FROM mfa_enrollments WHERE realm_id=$1 AND user_id=$2",
            "DELETE FROM mfa_recovery_codes WHERE realm_id=$1 AND user_id=$2",
            "DELETE FROM mfa_login_challenges WHERE realm_id=$1 AND user_id=$2",
        ] {
            sqlx::query(sql)
                .bind(realm_id.as_uuid())
                .bind(user_id.as_uuid())
                .execute(&mut *transaction)
                .await
                .map_err(mapping::storage)?;
        }
        sqlx::query("UPDATE sessions SET revoked_at=$1 WHERE realm_id=$2 AND user_id=$3 AND revoked_at IS NULL")
            .bind(now).bind(realm_id.as_uuid()).bind(user_id.as_uuid()).execute(&mut *transaction).await.map_err(mapping::storage)?;
        revoke_trusted_devices(&mut transaction, realm_id, user_id, now).await?;
        mapping::insert_event(&mut transaction, &event).await?;
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(true)
    }

    async fn list_trusted_devices(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Vec<TrustedDevice>, AuthError> {
        let rows = sqlx::query("SELECT id,user_id,device_name,network_hash,user_agent,created_at,last_used_at,expires_at,revoked_at FROM trusted_devices WHERE realm_id=$1 AND user_id=$2 ORDER BY created_at DESC")
            .bind(realm_id.as_uuid()).bind(user_id.as_uuid()).fetch_all(&self.pool).await.map_err(mapping::storage)?;
        rows.iter()
            .map(|row| stored_trusted_device(row, realm_id))
            .collect()
    }

    async fn revoke_trusted_device(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        trusted_device_id: TrustedDeviceId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let row = sqlx::query(
            "SELECT user_id,revoked_at FROM trusted_devices WHERE realm_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(realm_id.as_uuid())
        .bind(trusted_device_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        let Some(row) = row else {
            return Ok(false);
        };
        if UserId::from_uuid(
            row.try_get::<Uuid, _>("user_id")
                .map_err(mapping::storage)?,
        ) != user_id
        {
            return Ok(false);
        }
        if row
            .try_get::<Option<DateTime<Utc>>, _>("revoked_at")
            .map_err(mapping::storage)?
            .is_none()
        {
            sqlx::query("UPDATE trusted_devices SET revoked_at=$1 WHERE realm_id=$2 AND id=$3 AND revoked_at IS NULL")
                .bind(now).bind(realm_id.as_uuid()).bind(trusted_device_id.as_uuid()).execute(&mut *transaction).await.map_err(mapping::storage)?;
            mapping::insert_event(&mut transaction, &event).await?;
        }
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(true)
    }

    async fn factors_needing_rewrap(
        &self,
        realm_id: RealmId,
        active_key_id: &str,
        limit: u32,
    ) -> Result<Vec<StoredTotpFactor>, AuthError> {
        let rows = sqlx::query("SELECT id,user_id,format_version,algorithm,key_id,nonce,ciphertext,last_accepted_counter,created_at,updated_at FROM mfa_totp_factors WHERE realm_id=$1 AND key_id<>$2 ORDER BY updated_at LIMIT $3")
            .bind(realm_id.as_uuid()).bind(active_key_id).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(mapping::storage)?;
        rows.iter()
            .map(|row| stored_factor_with_user(row, realm_id))
            .collect()
    }

    async fn update_rewrapped_factor(
        &self,
        factor: StoredTotpFactor,
        expected_key_id: &str,
    ) -> Result<bool, AuthError> {
        let format_version = i16::try_from(factor.sealed_seed.format_version())
            .map_err(|_| AuthError::storage_unavailable())?;
        let changed = sqlx::query("UPDATE mfa_totp_factors SET format_version=$1,algorithm=$2,key_id=$3,nonce=$4,ciphertext=$5,last_accepted_counter=$6,updated_at=$7 WHERE realm_id=$8 AND user_id=$9 AND id=$10 AND key_id=$11")
            .bind(format_version).bind(factor.sealed_seed.algorithm().as_str()).bind(factor.sealed_seed.key_id())
            .bind(factor.sealed_seed.nonce().as_slice()).bind(factor.sealed_seed.ciphertext())
            .bind(factor.last_accepted_counter.map(counter_to_sql).transpose()?).bind(factor.updated_at)
            .bind(factor.realm_id.as_uuid()).bind(factor.user_id.as_uuid()).bind(factor.id.as_uuid()).bind(expected_key_id)
            .execute(&self.pool).await.map_err(mapping::storage)?.rows_affected();
        Ok(changed == 1)
    }
}

async fn lock_user(
    connection: &mut PgConnection,
    realm_id: RealmId,
    user_id: UserId,
) -> Result<(), AuthError> {
    sqlx::query("SELECT id FROM users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(realm_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(connection)
        .await
        .map_err(mapping::storage)?
        .ok_or_else(AuthError::storage_unavailable)
        .map(|_| ())
}

async fn insert_factor(
    connection: &mut PgConnection,
    factor: &StoredTotpFactor,
) -> Result<(), AuthError> {
    sqlx::query("INSERT INTO mfa_totp_factors(realm_id,user_id,id,format_version,algorithm,key_id,nonce,ciphertext,last_accepted_counter,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(factor.realm_id.as_uuid()).bind(factor.user_id.as_uuid()).bind(factor.id.as_uuid())
        .bind(i16::try_from(factor.sealed_seed.format_version()).map_err(|_| AuthError::storage_unavailable())?)
        .bind(factor.sealed_seed.algorithm().as_str()).bind(factor.sealed_seed.key_id())
        .bind(factor.sealed_seed.nonce().as_slice()).bind(factor.sealed_seed.ciphertext())
        .bind(factor.last_accepted_counter.map(counter_to_sql).transpose()?).bind(factor.created_at).bind(factor.updated_at)
        .execute(connection).await.map(|_| ()).map_err(mapping::storage)
}

async fn insert_enrollment(
    connection: &mut PgConnection,
    enrollment: &PendingTotpEnrollment,
) -> Result<(), AuthError> {
    sqlx::query("INSERT INTO mfa_enrollments(realm_id,user_id,id,format_version,algorithm,key_id,nonce,ciphertext,replacing,attempts,max_attempts,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
        .bind(enrollment.realm_id.as_uuid()).bind(enrollment.user_id.as_uuid()).bind(enrollment.id.as_uuid())
        .bind(i16::try_from(enrollment.sealed_seed.format_version()).map_err(|_| AuthError::storage_unavailable())?)
        .bind(enrollment.sealed_seed.algorithm().as_str()).bind(enrollment.sealed_seed.key_id())
        .bind(enrollment.sealed_seed.nonce().as_slice()).bind(enrollment.sealed_seed.ciphertext()).bind(enrollment.replacing)
        .bind(i32::try_from(enrollment.attempts).map_err(|_| AuthError::storage_unavailable())?)
        .bind(i32::try_from(enrollment.max_attempts).map_err(|_| AuthError::storage_unavailable())?)
        .bind(enrollment.expires_at).bind(enrollment.created_at).execute(connection).await.map(|_| ()).map_err(mapping::storage)
}

async fn insert_mfa_challenge(
    connection: &mut PgConnection,
    challenge: &StoredMfaLoginChallenge,
) -> Result<(), AuthError> {
    sqlx::query("INSERT INTO mfa_login_challenges(realm_id,digest,user_id,device_name,network_hash,user_agent,remember_me,attempts,max_attempts,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(challenge.realm_id.as_uuid()).bind(challenge.digest.as_bytes().as_slice()).bind(challenge.user_id.as_uuid())
        .bind(challenge.device.name.as_deref()).bind(challenge.device.network_hash.as_deref()).bind(challenge.device.user_agent.as_deref())
        .bind(challenge.remember_me).bind(i32::try_from(challenge.attempts).map_err(|_| AuthError::storage_unavailable())?)
        .bind(i32::try_from(challenge.max_attempts).map_err(|_| AuthError::storage_unavailable())?)
        .bind(challenge.expires_at).bind(challenge.created_at).execute(connection).await.map(|_| ()).map_err(mapping::storage)
}

async fn insert_recovery_code(
    connection: &mut PgConnection,
    realm_id: RealmId,
    user_id: UserId,
    digest: TokenDigest,
    created_at: DateTime<Utc>,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO mfa_recovery_codes(realm_id,user_id,digest,created_at) VALUES($1,$2,$3,$4)",
    )
    .bind(realm_id.as_uuid())
    .bind(user_id.as_uuid())
    .bind(digest.as_bytes().as_slice())
    .bind(created_at)
    .execute(connection)
    .await
    .map(|_| ())
    .map_err(mapping::storage)
}

pub(crate) async fn insert_trusted_device(
    connection: &mut PgConnection,
    trusted: &CreateTrustedDevice,
) -> Result<(), AuthError> {
    let device = &trusted.device;
    sqlx::query("INSERT INTO trusted_devices(realm_id,id,user_id,device_name,network_hash,user_agent,created_at,last_used_at,expires_at,revoked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(device.realm_id.as_uuid()).bind(device.id.as_uuid()).bind(device.user_id.as_uuid())
        .bind(device.device.name.as_deref()).bind(device.device.network_hash.as_deref()).bind(device.device.user_agent.as_deref())
        .bind(device.created_at).bind(device.last_used_at).bind(device.expires_at).bind(device.revoked_at)
        .execute(&mut *connection).await.map_err(mapping::storage)?;
    sqlx::query("INSERT INTO trusted_device_tokens(realm_id,digest,device_id,expires_at) VALUES($1,$2,$3,$4)")
        .bind(device.realm_id.as_uuid()).bind(trusted.token_digest.as_bytes().as_slice()).bind(device.id.as_uuid()).bind(device.expires_at)
        .execute(connection).await.map(|_| ()).map_err(mapping::storage)
}

async fn insert_events(
    connection: &mut PgConnection,
    events: &[AuthEvent],
) -> Result<(), AuthError> {
    for event in events {
        mapping::insert_event(&mut *connection, event).await?;
    }
    Ok(())
}

async fn revoke_trusted_devices(
    connection: &mut PgConnection,
    realm_id: RealmId,
    user_id: UserId,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    sqlx::query("UPDATE trusted_devices SET revoked_at=$1 WHERE realm_id=$2 AND user_id=$3 AND revoked_at IS NULL")
        .bind(now).bind(realm_id.as_uuid()).bind(user_id.as_uuid()).execute(connection).await.map(|_| ()).map_err(mapping::storage)
}

fn counter_to_sql(counter: u64) -> Result<i64, AuthError> {
    i64::try_from(counter).map_err(|_| AuthError::storage_unavailable())
}

fn sealed(row: &PgRow) -> Result<SealedSecret, AuthError> {
    let format: i16 = row.try_get("format_version").map_err(mapping::storage)?;
    let algorithm: String = row.try_get("algorithm").map_err(mapping::storage)?;
    let nonce: Vec<u8> = row.try_get("nonce").map_err(mapping::storage)?;
    SealedSecret::from_versioned_parts(
        u16::try_from(format).map_err(|_| AuthError::storage_unavailable())?,
        AeadAlgorithm::parse(&algorithm)?,
        row.try_get("key_id").map_err(mapping::storage)?,
        &nonce,
        row.try_get("ciphertext").map_err(mapping::storage)?,
    )
}

fn stored_factor(
    row: &PgRow,
    realm_id: RealmId,
    user_id: UserId,
) -> Result<StoredTotpFactor, AuthError> {
    Ok(StoredTotpFactor {
        id: MfaFactorId::from_uuid(row.try_get("id").map_err(mapping::storage)?),
        realm_id,
        user_id,
        sealed_seed: sealed(row)?,
        last_accepted_counter: row
            .try_get::<Option<i64>, _>("last_accepted_counter")
            .map_err(mapping::storage)?
            .map(|value| u64::try_from(value).map_err(|_| AuthError::storage_unavailable()))
            .transpose()?,
        created_at: row.try_get("created_at").map_err(mapping::storage)?,
        updated_at: row.try_get("updated_at").map_err(mapping::storage)?,
    })
}

fn stored_factor_with_user(row: &PgRow, realm_id: RealmId) -> Result<StoredTotpFactor, AuthError> {
    stored_factor(
        row,
        realm_id,
        UserId::from_uuid(row.try_get("user_id").map_err(mapping::storage)?),
    )
}

fn stored_enrollment(
    row: &PgRow,
    realm_id: RealmId,
    user_id: UserId,
) -> Result<PendingTotpEnrollment, AuthError> {
    Ok(PendingTotpEnrollment {
        id: MfaEnrollmentId::from_uuid(row.try_get("id").map_err(mapping::storage)?),
        realm_id,
        user_id,
        sealed_seed: sealed(row)?,
        replacing: row.try_get("replacing").map_err(mapping::storage)?,
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
    })
}

struct StoredMfaChallengeRow {
    challenge: StoredMfaLoginChallenge,
    consumed_at: Option<DateTime<Utc>>,
}

fn stored_mfa_challenge(
    row: &PgRow,
    realm_id: RealmId,
    digest: TokenDigest,
) -> Result<StoredMfaChallengeRow, AuthError> {
    Ok(StoredMfaChallengeRow {
        challenge: StoredMfaLoginChallenge {
            digest,
            realm_id,
            user_id: UserId::from_uuid(row.try_get("user_id").map_err(mapping::storage)?),
            device: DeviceContext {
                name: row.try_get("device_name").map_err(mapping::storage)?,
                network_hash: row.try_get("network_hash").map_err(mapping::storage)?,
                user_agent: row.try_get("user_agent").map_err(mapping::storage)?,
            },
            remember_me: row.try_get("remember_me").map_err(mapping::storage)?,
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

fn stored_trusted_device(row: &PgRow, realm_id: RealmId) -> Result<TrustedDevice, AuthError> {
    Ok(TrustedDevice {
        realm_id,
        id: TrustedDeviceId::from_uuid(row.try_get("id").map_err(mapping::storage)?),
        user_id: UserId::from_uuid(row.try_get("user_id").map_err(mapping::storage)?),
        device: DeviceContext {
            name: row.try_get("device_name").map_err(mapping::storage)?,
            network_hash: row.try_get("network_hash").map_err(mapping::storage)?,
            user_agent: row.try_get("user_agent").map_err(mapping::storage)?,
        },
        created_at: row.try_get("created_at").map_err(mapping::storage)?,
        last_used_at: row.try_get("last_used_at").map_err(mapping::storage)?,
        expires_at: row.try_get("expires_at").map_err(mapping::storage)?,
        revoked_at: row.try_get("revoked_at").map_err(mapping::storage)?,
    })
}

struct StoredTrustedTokenRow {
    device: TrustedDevice,
    token_expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}
fn stored_trusted_token(
    row: &PgRow,
    realm_id: RealmId,
) -> Result<StoredTrustedTokenRow, AuthError> {
    Ok(StoredTrustedTokenRow {
        device: stored_trusted_device(row, realm_id)?,
        token_expires_at: row.try_get("token_expires_at").map_err(mapping::storage)?,
        consumed_at: row.try_get("consumed_at").map_err(mapping::storage)?,
    })
}
