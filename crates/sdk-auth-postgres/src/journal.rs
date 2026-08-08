use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_core::{AuditStore, ClaimEventsRequest, ClaimedEvent, EventStore, LeasedEventStore};
use sdk_auth_error::AuthError;
use sdk_auth_types::{AuditRecord, AuthEvent, EventId, OutboxClaimId, RealmId};

use crate::{PostgresAuthStore, mapping};

#[async_trait]
impl EventStore for PostgresAuthStore {
    async fn pending_events(&self, limit: u32) -> Result<Vec<AuthEvent>, AuthError> {
        let rows = sqlx::query(
            "SELECT id,realm_id,user_id,kind,payload,created_at FROM outbox WHERE delivered_at IS NULL AND (claim_id IS NULL OR lease_expires_at<=CURRENT_TIMESTAMP) ORDER BY created_at,id LIMIT $1",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(mapping::storage)?;
        rows.iter().map(mapping::stored_event).collect()
    }

    async fn acknowledge_event(
        &self,
        event_id: EventId,
        delivered_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let changed = sqlx::query(
            "UPDATE outbox SET delivered_at=$1,claim_id=NULL,consumer_id=NULL,lease_expires_at=NULL WHERE id=$2 AND delivered_at IS NULL AND (claim_id IS NULL OR lease_expires_at<=$1)",
        )
        .bind(delivered_at)
        .bind(event_id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        Ok(changed == 1)
    }
}

#[async_trait]
impl LeasedEventStore for PostgresAuthStore {
    async fn claim_events(
        &self,
        request: ClaimEventsRequest,
        claim_id: OutboxClaimId,
        now: DateTime<Utc>,
    ) -> Result<Vec<ClaimedEvent>, AuthError> {
        let lease_expires_at = now + request.lease_duration;
        let rows = sqlx::query(
            "WITH candidates AS (SELECT id FROM outbox WHERE delivered_at IS NULL AND (claim_id IS NULL OR lease_expires_at<=$1) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT $2) UPDATE outbox AS event SET claim_id=$3,consumer_id=$4,lease_expires_at=$5 FROM candidates WHERE event.id=candidates.id RETURNING event.id,event.realm_id,event.user_id,event.kind,event.payload,event.created_at",
        )
        .bind(now)
        .bind(i64::from(request.limit))
        .bind(claim_id.as_uuid())
        .bind(request.consumer_id)
        .bind(lease_expires_at)
        .fetch_all(&self.pool)
        .await
        .map_err(mapping::storage)?;
        let mut events = rows
            .iter()
            .map(mapping::stored_event)
            .collect::<Result<Vec<_>, _>>()?;
        events.sort_by_key(|event| (event.created_at, event.id.as_uuid()));
        Ok(events
            .into_iter()
            .map(|event| ClaimedEvent {
                event,
                claim_id,
                lease_expires_at,
            })
            .collect())
    }

    async fn acknowledge_claim(
        &self,
        event_id: EventId,
        claim_id: OutboxClaimId,
        delivered_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let changed = sqlx::query(
            "UPDATE outbox SET delivered_at=$1,claim_id=NULL,consumer_id=NULL,lease_expires_at=NULL WHERE id=$2 AND claim_id=$3 AND delivered_at IS NULL AND lease_expires_at>$1",
        )
        .bind(delivered_at)
        .bind(event_id.as_uuid())
        .bind(claim_id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(mapping::storage)?
        .rows_affected();
        Ok(changed == 1)
    }

    async fn release_claim(&self, claim_id: OutboxClaimId) -> Result<u64, AuthError> {
        sqlx::query(
            "UPDATE outbox SET claim_id=NULL,consumer_id=NULL,lease_expires_at=NULL WHERE claim_id=$1 AND delivered_at IS NULL",
        )
        .bind(claim_id.as_uuid())
        .execute(&self.pool)
        .await
        .map(|result| result.rows_affected())
        .map_err(mapping::storage)
    }
}

#[async_trait]
impl AuditStore for PostgresAuthStore {
    async fn list_audit_records(
        &self,
        realm_id: RealmId,
        before: Option<DateTime<Utc>>,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, AuthError> {
        let rows = if let Some(before) = before {
            sqlx::query(
                "SELECT id,realm_id,actor_kind,actor_user_id,subject_user_id,kind,outcome,metadata,occurred_at,outbox_event_id FROM audit_log WHERE realm_id=$1 AND occurred_at<$2 ORDER BY occurred_at DESC,id DESC LIMIT $3",
            )
            .bind(realm_id.as_uuid())
            .bind(before)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(mapping::storage)?
        } else {
            sqlx::query(
                "SELECT id,realm_id,actor_kind,actor_user_id,subject_user_id,kind,outcome,metadata,occurred_at,outbox_event_id FROM audit_log WHERE realm_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT $2",
            )
            .bind(realm_id.as_uuid())
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(mapping::storage)?
        };
        rows.iter().map(mapping::stored_audit).collect()
    }
}
