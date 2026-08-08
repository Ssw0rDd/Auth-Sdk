use chrono::Utc;
use sdk_auth_error::AuthError;
use sqlx::Row as _;

use crate::{PostgresConfig, config, mapping};

/// Current PostgreSQL schema understood by this SDK release.
pub const POSTGRES_SCHEMA_VERSION: u32 = 6;

const SCHEMA: &str = include_str!("../migrations/0001_v6.sql");
const MIGRATION_LOCK_ID: i64 = 0x5344_4B41_5554_4806;

/// Result of an explicit PostgreSQL migration invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresMigrationReport {
    /// Highest migration found before this invocation.
    pub from: u32,
    /// Schema version after this invocation.
    pub to: u32,
    /// Ordered migration versions applied now.
    pub applied: Vec<u32>,
}

/// Explicit, advisory-lock protected PostgreSQL migrator.
pub struct PostgresMigrator;

impl PostgresMigrator {
    /// Applies immutable embedded migrations without starting the SDK.
    pub async fn migrate(config: &PostgresConfig) -> Result<PostgresMigrationReport, AuthError> {
        let pool = config::connect_pool(config).await?;
        let mut transaction = pool.begin().await.map_err(mapping::storage)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(MIGRATION_LOCK_ID)
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS sdk_migrations(version INTEGER PRIMARY KEY,checksum BYTEA NOT NULL CHECK(octet_length(checksum)=32),applied_at TIMESTAMPTZ NOT NULL)",
        )
        .execute(&mut *transaction)
        .await
        .map_err(mapping::storage)?;
        let existing = sqlx::query("SELECT version,checksum FROM sdk_migrations ORDER BY version")
            .fetch_all(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        let from = existing
            .last()
            .map(|row| row.try_get::<i32, _>("version"))
            .transpose()
            .map_err(mapping::storage)?
            .map_or(0, |version| u32::try_from(version).unwrap_or(u32::MAX));
        if from > POSTGRES_SCHEMA_VERSION {
            return Err(AuthError::schema_incompatible());
        }
        let checksum = blake3::hash(SCHEMA.as_bytes());
        if let Some(row) = existing
            .iter()
            .find(|row| row.try_get::<i32, _>("version").ok() == Some(6))
        {
            let stored: Vec<u8> = row.try_get("checksum").map_err(mapping::storage)?;
            if stored.as_slice() != checksum.as_bytes() {
                return Err(AuthError::schema_incompatible());
            }
            transaction.commit().await.map_err(mapping::storage)?;
            pool.close().await;
            return Ok(PostgresMigrationReport {
                from,
                to: POSTGRES_SCHEMA_VERSION,
                applied: Vec::new(),
            });
        }
        sqlx::raw_sql(SCHEMA)
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        sqlx::query("INSERT INTO sdk_migrations(version,checksum,applied_at) VALUES($1,$2,$3)")
            .bind(6_i32)
            .bind(checksum.as_bytes().as_slice())
            .bind(Utc::now())
            .execute(&mut *transaction)
            .await
            .map_err(mapping::storage)?;
        transaction.commit().await.map_err(mapping::storage)?;
        pool.close().await;
        Ok(PostgresMigrationReport {
            from,
            to: POSTGRES_SCHEMA_VERSION,
            applied: vec![POSTGRES_SCHEMA_VERSION],
        })
    }
}
