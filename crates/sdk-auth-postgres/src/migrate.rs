use chrono::Utc;
use sdk_auth_error::AuthError;
use sqlx::Row as _;

use crate::{PostgresConfig, config, mapping};

/// Current PostgreSQL schema understood by this SDK release.
pub const POSTGRES_SCHEMA_VERSION: u32 = 7;

const SCHEMA_V6: &str = include_str!("../migrations/0001_v6.sql");
const SCHEMA_V7: &str = include_str!("../migrations/0002_v7.sql");
const MIGRATIONS: &[(u32, &str)] = &[(6, SCHEMA_V6), (7, SCHEMA_V7)];
const MIGRATION_LOCK_ID: i64 = 0x5344_4B41_5554_4806;

fn validate_migration_prefix(installed: &[u32]) -> Result<(), AuthError> {
    if installed.len() > MIGRATIONS.len()
        || installed
            .iter()
            .zip(MIGRATIONS)
            .any(|(installed, (expected, _))| installed != expected)
    {
        return Err(AuthError::schema_incompatible());
    }
    Ok(())
}

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
        let installed_versions = existing
            .iter()
            .map(|row| {
                let version: i32 = row.try_get("version").map_err(mapping::storage)?;
                u32::try_from(version).map_err(|_| AuthError::schema_incompatible())
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_migration_prefix(&installed_versions)?;
        for row in &existing {
            let version: i32 = row.try_get("version").map_err(mapping::storage)?;
            let version = u32::try_from(version).map_err(|_| AuthError::schema_incompatible())?;
            let Some((_, migration)) = MIGRATIONS
                .iter()
                .find(|(known_version, _)| *known_version == version)
            else {
                return Err(AuthError::schema_incompatible());
            };
            let stored: Vec<u8> = row.try_get("checksum").map_err(mapping::storage)?;
            if stored.as_slice() != blake3::hash(migration.as_bytes()).as_bytes() {
                return Err(AuthError::schema_incompatible());
            }
        }
        let mut applied = Vec::new();
        for (version, migration) in MIGRATIONS {
            if existing
                .iter()
                .any(|row| row.try_get::<i32, _>("version").ok() == i32::try_from(*version).ok())
            {
                continue;
            }
            sqlx::raw_sql(*migration)
                .execute(&mut *transaction)
                .await
                .map_err(mapping::storage)?;
            let checksum = blake3::hash(migration.as_bytes());
            sqlx::query("INSERT INTO sdk_migrations(version,checksum,applied_at) VALUES($1,$2,$3)")
                .bind(i32::try_from(*version).map_err(|_| AuthError::schema_incompatible())?)
                .bind(checksum.as_bytes().as_slice())
                .bind(Utc::now())
                .execute(&mut *transaction)
                .await
                .map_err(mapping::storage)?;
            applied.push(*version);
        }
        transaction.commit().await.map_err(mapping::storage)?;
        pool.close().await;
        Ok(PostgresMigrationReport {
            from,
            to: POSTGRES_SCHEMA_VERSION,
            applied,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_migrations_must_be_an_exact_prefix() {
        assert!(validate_migration_prefix(&[]).is_ok());
        assert!(validate_migration_prefix(&[6]).is_ok());
        assert!(validate_migration_prefix(&[6, 7]).is_ok());
        assert!(validate_migration_prefix(&[7]).is_err());
        assert!(validate_migration_prefix(&[6, 8]).is_err());
        assert!(validate_migration_prefix(&[6, 7, 8]).is_err());
    }
}
