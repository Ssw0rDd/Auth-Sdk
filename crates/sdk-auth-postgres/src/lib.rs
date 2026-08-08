//! Production PostgreSQL persistence adapter for SDK-Auth.
//!
//! Schema migration is always explicit. [`PostgresAuthStore::connect`] refuses
//! missing, incompatible, or partially imported schemas.

mod config;
mod federation;
mod iam;
mod identity;
mod journal;
mod mapping;
mod mfa;
mod migrate;
mod passkey;
mod rate_limit;
mod session;

use sdk_auth_core::{UnitOfWorkCapabilities, UnitOfWorkStore};
use sdk_auth_error::AuthError;
use sqlx::{PgPool, Row as _};

const REQUIRED_TABLES: &[&str] = &[
    "access_tokens",
    "audit_log",
    "challenges",
    "federated_identities",
    "federated_link_challenges",
    "iam_api_key_scopes",
    "iam_api_keys",
    "iam_permissions",
    "iam_principal_roles",
    "iam_realms",
    "iam_role_permissions",
    "iam_roles",
    "iam_service_accounts",
    "login_attempts",
    "mfa_enrollments",
    "mfa_login_challenges",
    "mfa_recovery_codes",
    "mfa_totp_factors",
    "outbox",
    "passkey_ceremonies",
    "passkey_credentials",
    "refresh_tokens",
    "sdk_import_status",
    "sdk_migrations",
    "sdk_schema_compatibility",
    "sessions",
    "trusted_device_tokens",
    "trusted_devices",
    "users",
];

pub use config::{PostgresConfig, PostgresPoolConfig};
pub use migrate::{POSTGRES_SCHEMA_VERSION, PostgresMigrationReport, PostgresMigrator};

/// Snapshot of the bounded SQLx connection pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostgresPoolStatus {
    /// Current total number of open connections.
    pub size: u32,
    /// Current number of idle connections.
    pub idle: u32,
    /// Configured upper bound.
    pub max: u32,
}

/// PostgreSQL-backed implementation of all SDK-Auth persistence ports.
#[derive(Clone)]
pub struct PostgresAuthStore {
    pub(crate) pool: PgPool,
    max_connections: u32,
}

impl PostgresAuthStore {
    /// Connects to an explicitly migrated and compatible database.
    pub async fn connect(config: PostgresConfig) -> Result<Self, AuthError> {
        let max_connections = config.pool.max_connections;
        let pool = config::connect_pool(&config).await?;
        require_compatible_schema(&pool).await?;
        require_complete_import(&pool).await?;
        Ok(Self {
            pool,
            max_connections,
        })
    }

    /// Runs a bounded primary-database liveness check.
    pub async fn health_check(&self) -> Result<(), AuthError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(mapping::storage)
    }

    /// Returns non-secret pool occupancy information.
    #[must_use]
    pub fn pool_status(&self) -> PostgresPoolStatus {
        PostgresPoolStatus {
            size: self.pool.size(),
            idle: u32::try_from(self.pool.num_idle()).unwrap_or(u32::MAX),
            max: self.max_connections,
        }
    }

    /// Closes the pool after waiting for checked-out connections to return.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

impl UnitOfWorkStore for PostgresAuthStore {
    fn unit_of_work_capabilities(&self) -> UnitOfWorkCapabilities {
        UnitOfWorkCapabilities::REQUIRED
    }
}

async fn require_compatible_schema(pool: &PgPool) -> Result<(), AuthError> {
    let row = sqlx::query(
        "SELECT schema_version,min_reader_version,min_writer_version FROM sdk_schema_compatibility WHERE singleton=TRUE",
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| AuthError::schema_incompatible())?
    .ok_or_else(AuthError::schema_incompatible)?;
    let schema_version: i32 = row.try_get("schema_version").map_err(mapping::storage)?;
    let min_reader: i32 = row
        .try_get("min_reader_version")
        .map_err(mapping::storage)?;
    let min_writer: i32 = row
        .try_get("min_writer_version")
        .map_err(mapping::storage)?;
    let current =
        i32::try_from(POSTGRES_SCHEMA_VERSION).map_err(|_| AuthError::schema_incompatible())?;
    if schema_version == current
        || (schema_version > current && min_reader <= current && min_writer <= current)
    {
        require_complete_table_set(pool).await
    } else {
        Err(AuthError::schema_incompatible())
    }
}

async fn require_complete_table_set(pool: &PgPool) -> Result<(), AuthError> {
    let required = REQUIRED_TABLES
        .iter()
        .map(|table| (*table).to_owned())
        .collect::<Vec<_>>();
    let found: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind IN('r','p') AND c.relname=ANY($1)",
    )
    .bind(required)
    .fetch_one(pool)
    .await
    .map_err(mapping::storage)?;
    if usize::try_from(found).ok() == Some(REQUIRED_TABLES.len()) {
        Ok(())
    } else {
        Err(AuthError::schema_incompatible())
    }
}

async fn require_complete_import(pool: &PgPool) -> Result<(), AuthError> {
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM sdk_import_status WHERE singleton=TRUE",
    )
    .fetch_optional(pool)
    .await
    .map_err(mapping::storage)?;
    if status.as_deref().is_none_or(|status| status == "complete") {
        Ok(())
    } else {
        Err(AuthError::migration_incomplete())
    }
}
