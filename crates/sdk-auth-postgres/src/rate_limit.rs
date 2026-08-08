use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_core::{AttemptDecision, LoginAttemptPolicy, RateLimitStore};
use sdk_auth_error::AuthError;
use sdk_auth_types::RealmId;
use sqlx::{PgConnection, Row as _};

use crate::{PostgresAuthStore, mapping};

#[async_trait]
impl RateLimitStore for PostgresAuthStore {
    async fn record_login_attempt(
        &self,
        realm_id: RealmId,
        subject: &str,
        network_hash: Option<&str>,
        now: DateTime<Utc>,
        policy: LoginAttemptPolicy,
    ) -> Result<AttemptDecision, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(mapping::storage)?;
        let account =
            update_attempt(&mut transaction, realm_id, subject, "account", now, policy).await?;
        let network = if let Some(network_hash) = network_hash {
            Some(
                update_attempt(
                    &mut transaction,
                    realm_id,
                    network_hash,
                    "network",
                    now,
                    policy,
                )
                .await?,
            )
        } else {
            None
        };
        transaction.commit().await.map_err(mapping::storage)?;
        Ok(network.map_or(account, |network| later_block(account, network)))
    }

    async fn clear_login_attempts(
        &self,
        realm_id: RealmId,
        subject: &str,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "DELETE FROM login_attempts WHERE realm_id=$1 AND subject=$2 AND scope='account'",
        )
        .bind(realm_id.as_uuid())
        .bind(subject)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(mapping::storage)
    }
}

async fn update_attempt(
    connection: &mut PgConnection,
    realm_id: RealmId,
    subject: &str,
    scope: &str,
    now: DateTime<Utc>,
    policy: LoginAttemptPolicy,
) -> Result<AttemptDecision, AuthError> {
    sqlx::query(
        "INSERT INTO login_attempts(realm_id,subject,scope,attempts) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
    )
    .bind(realm_id.as_uuid())
    .bind(subject)
    .bind(scope)
    .bind(Vec::<DateTime<Utc>>::new())
    .execute(&mut *connection)
    .await
    .map_err(mapping::storage)?;
    let row = sqlx::query(
        "SELECT attempts,blocked_until FROM login_attempts WHERE realm_id=$1 AND subject=$2 AND scope=$3 FOR UPDATE",
    )
    .bind(realm_id.as_uuid())
    .bind(subject)
    .bind(scope)
    .fetch_one(&mut *connection)
    .await
    .map_err(mapping::storage)?;
    let mut attempts: Vec<DateTime<Utc>> = row.try_get("attempts").map_err(mapping::storage)?;
    let mut blocked_until: Option<DateTime<Utc>> =
        row.try_get("blocked_until").map_err(mapping::storage)?;
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
    sqlx::query(
        "UPDATE login_attempts SET attempts=$1,blocked_until=$2 WHERE realm_id=$3 AND subject=$4 AND scope=$5",
    )
    .bind(attempts)
    .bind(blocked_until)
    .bind(realm_id.as_uuid())
    .bind(subject)
    .bind(scope)
    .execute(connection)
    .await
    .map_err(mapping::storage)?;
    Ok(decision)
}

fn later_block(first: AttemptDecision, second: AttemptDecision) -> AttemptDecision {
    match (first, second) {
        (AttemptDecision::BlockedUntil(left), AttemptDecision::BlockedUntil(right)) => {
            AttemptDecision::BlockedUntil(if left > right { left } else { right })
        }
        (AttemptDecision::BlockedUntil(until), AttemptDecision::Allowed)
        | (AttemptDecision::Allowed, AttemptDecision::BlockedUntil(until)) => {
            AttemptDecision::BlockedUntil(until)
        }
        (AttemptDecision::Allowed, AttemptDecision::Allowed) => AttemptDecision::Allowed,
    }
}
