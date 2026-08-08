//! Offline, all-or-nothing SQLite to PostgreSQL migration command.

use std::{env, path::PathBuf, process::ExitCode, str::FromStr as _, time::Duration};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags, types::Value};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_postgres::{PostgresConfig, PostgresMigrator};
use sdk_auth_sqlite::LATEST_SCHEMA_VERSION;
use sdk_auth_types::SecretString;
use sqlx::{
    ConnectOptions as _, PgPool, Postgres, QueryBuilder,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use url::Url;
use uuid::Uuid;

const IMPORT_LOCK_ID: i64 = 0x5344_4B41_494D_5006;

#[derive(Clone, Copy)]
enum Kind {
    Uuid,
    OptionalUuid,
    Text,
    OptionalText,
    Bool,
    I16,
    I32,
    I64,
    OptionalI64,
    Bytes,
    Timestamp,
    OptionalTimestamp,
    Json,
    TimestampArray,
}

struct TableSpec {
    name: &'static str,
    source_columns: &'static [&'static str],
    target_columns: &'static [&'static str],
    kinds: &'static [Kind],
}

const fn table(
    name: &'static str,
    source_columns: &'static [&'static str],
    target_columns: &'static [&'static str],
    kinds: &'static [Kind],
) -> TableSpec {
    TableSpec {
        name,
        source_columns,
        target_columns,
        kinds,
    }
}

const TABLES: &[TableSpec] = &[
    table(
        "users",
        &[
            "realm_id",
            "id",
            "email",
            "normalized_email",
            "email_verified",
            "password_hash",
            "created_at",
            "updated_at",
        ],
        &[
            "realm_id",
            "id",
            "email",
            "normalized_email",
            "email_verified",
            "password_hash",
            "created_at",
            "updated_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::Text,
            Kind::Bool,
            Kind::OptionalText,
            Kind::Timestamp,
            Kind::Timestamp,
        ],
    ),
    table(
        "federated_identities",
        &[
            "realm_id",
            "id",
            "user_id",
            "provider_id",
            "issuer",
            "subject",
            "verified_email",
            "normalized_verified_email",
            "created_at",
            "last_used_at",
            "revoked_at",
        ],
        &[
            "realm_id",
            "id",
            "user_id",
            "provider_id",
            "issuer",
            "subject",
            "verified_email",
            "normalized_verified_email",
            "created_at",
            "last_used_at",
            "revoked_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::Text,
            Kind::Text,
            Kind::Text,
            Kind::Text,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "federated_link_challenges",
        &[
            "realm_id",
            "digest",
            "user_id",
            "identity_id",
            "provider_id",
            "issuer",
            "subject",
            "verified_email",
            "normalized_verified_email",
            "expires_at",
            "created_at",
            "consumed_at",
        ],
        &[
            "realm_id",
            "digest",
            "user_id",
            "identity_id",
            "provider_id",
            "issuer",
            "subject",
            "verified_email",
            "normalized_verified_email",
            "expires_at",
            "created_at",
            "consumed_at",
        ],
        &[
            Kind::Uuid,
            Kind::Bytes,
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::Text,
            Kind::Text,
            Kind::Text,
            Kind::Text,
            Kind::Timestamp,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "sessions",
        &[
            "realm_id",
            "id",
            "user_id",
            "family_id",
            "device_name",
            "network_hash",
            "user_agent",
            "authentication_method",
            "second_factor_verified_at",
            "created_at",
            "last_seen_at",
            "expires_at",
            "revoked_at",
        ],
        &[
            "realm_id",
            "id",
            "user_id",
            "family_id",
            "device_name",
            "network_hash",
            "user_agent",
            "authentication_method",
            "second_factor_verified_at",
            "created_at",
            "last_seen_at",
            "expires_at",
            "revoked_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Uuid,
            Kind::Uuid,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::Text,
            Kind::OptionalTimestamp,
            Kind::Timestamp,
            Kind::Timestamp,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "access_tokens",
        &["realm_id", "digest", "session_id", "expires_at"],
        &["realm_id", "digest", "session_id", "expires_at"],
        &[Kind::Uuid, Kind::Bytes, Kind::Uuid, Kind::Timestamp],
    ),
    table(
        "refresh_tokens",
        &[
            "realm_id",
            "digest",
            "session_id",
            "family_id",
            "expires_at",
            "consumed_at",
        ],
        &[
            "realm_id",
            "digest",
            "session_id",
            "family_id",
            "expires_at",
            "consumed_at",
        ],
        &[
            Kind::Uuid,
            Kind::Bytes,
            Kind::Uuid,
            Kind::Uuid,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "challenges",
        &[
            "realm_id",
            "digest",
            "kind",
            "user_id",
            "expires_at",
            "consumed_at",
        ],
        &[
            "realm_id",
            "digest",
            "kind",
            "user_id",
            "expires_at",
            "consumed_at",
        ],
        &[
            Kind::Uuid,
            Kind::Bytes,
            Kind::Text,
            Kind::Uuid,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "login_attempts",
        &[
            "realm_id",
            "subject",
            "scope",
            "attempts_json",
            "blocked_until",
        ],
        &["realm_id", "subject", "scope", "attempts", "blocked_until"],
        &[
            Kind::Uuid,
            Kind::Text,
            Kind::Text,
            Kind::TimestampArray,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "mfa_totp_factors",
        &[
            "realm_id",
            "user_id",
            "id",
            "key_id",
            "format_version",
            "algorithm",
            "nonce",
            "ciphertext",
            "last_accepted_counter",
            "created_at",
            "updated_at",
        ],
        &[
            "realm_id",
            "user_id",
            "id",
            "key_id",
            "format_version",
            "algorithm",
            "nonce",
            "ciphertext",
            "last_accepted_counter",
            "created_at",
            "updated_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::I16,
            Kind::Text,
            Kind::Bytes,
            Kind::Bytes,
            Kind::OptionalI64,
            Kind::Timestamp,
            Kind::Timestamp,
        ],
    ),
    table(
        "mfa_enrollments",
        &[
            "realm_id",
            "user_id",
            "id",
            "key_id",
            "format_version",
            "algorithm",
            "nonce",
            "ciphertext",
            "replacing",
            "attempts",
            "max_attempts",
            "expires_at",
            "created_at",
        ],
        &[
            "realm_id",
            "user_id",
            "id",
            "key_id",
            "format_version",
            "algorithm",
            "nonce",
            "ciphertext",
            "replacing",
            "attempts",
            "max_attempts",
            "expires_at",
            "created_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::I16,
            Kind::Text,
            Kind::Bytes,
            Kind::Bytes,
            Kind::Bool,
            Kind::I32,
            Kind::I32,
            Kind::Timestamp,
            Kind::Timestamp,
        ],
    ),
    table(
        "mfa_login_challenges",
        &[
            "realm_id",
            "digest",
            "user_id",
            "device_name",
            "network_hash",
            "user_agent",
            "remember_me",
            "attempts",
            "max_attempts",
            "expires_at",
            "created_at",
            "consumed_at",
        ],
        &[
            "realm_id",
            "digest",
            "user_id",
            "device_name",
            "network_hash",
            "user_agent",
            "remember_me",
            "attempts",
            "max_attempts",
            "expires_at",
            "created_at",
            "consumed_at",
        ],
        &[
            Kind::Uuid,
            Kind::Bytes,
            Kind::Uuid,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::Bool,
            Kind::I32,
            Kind::I32,
            Kind::Timestamp,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "mfa_recovery_codes",
        &["realm_id", "user_id", "digest", "consumed_at", "created_at"],
        &["realm_id", "user_id", "digest", "consumed_at", "created_at"],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Bytes,
            Kind::OptionalTimestamp,
            Kind::Timestamp,
        ],
    ),
    table(
        "trusted_devices",
        &[
            "realm_id",
            "id",
            "user_id",
            "device_name",
            "network_hash",
            "user_agent",
            "created_at",
            "last_used_at",
            "expires_at",
            "revoked_at",
        ],
        &[
            "realm_id",
            "id",
            "user_id",
            "device_name",
            "network_hash",
            "user_agent",
            "created_at",
            "last_used_at",
            "expires_at",
            "revoked_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Uuid,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::Timestamp,
            Kind::Timestamp,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "trusted_device_tokens",
        &[
            "realm_id",
            "digest",
            "device_id",
            "expires_at",
            "consumed_at",
        ],
        &[
            "realm_id",
            "digest",
            "device_id",
            "expires_at",
            "consumed_at",
        ],
        &[
            Kind::Uuid,
            Kind::Bytes,
            Kind::Uuid,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "passkey_credentials",
        &[
            "realm_id",
            "id",
            "user_id",
            "label",
            "credential_id",
            "provider_id",
            "credential_format",
            "credential_blob",
            "signature_counter",
            "backup_eligible",
            "backed_up",
            "created_at",
            "last_used_at",
            "revoked_at",
        ],
        &[
            "realm_id",
            "id",
            "user_id",
            "label",
            "credential_id",
            "provider_id",
            "credential_format",
            "credential_blob",
            "signature_counter",
            "backup_eligible",
            "backed_up",
            "created_at",
            "last_used_at",
            "revoked_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::Bytes,
            Kind::Text,
            Kind::I16,
            Kind::Bytes,
            Kind::I64,
            Kind::Bool,
            Kind::Bool,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "passkey_ceremonies",
        &[
            "realm_id",
            "digest",
            "user_id",
            "session_id",
            "kind",
            "label",
            "login_subject",
            "device_name",
            "network_hash",
            "user_agent",
            "remember_me",
            "provider_id",
            "state_format",
            "state_blob",
            "attempts",
            "max_attempts",
            "expires_at",
            "created_at",
            "consumed_at",
        ],
        &[
            "realm_id",
            "digest",
            "user_id",
            "session_id",
            "kind",
            "label",
            "login_subject",
            "device_name",
            "network_hash",
            "user_agent",
            "remember_me",
            "provider_id",
            "state_format",
            "state_blob",
            "attempts",
            "max_attempts",
            "expires_at",
            "created_at",
            "consumed_at",
        ],
        &[
            Kind::Uuid,
            Kind::Bytes,
            Kind::Uuid,
            Kind::OptionalUuid,
            Kind::Text,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::OptionalText,
            Kind::Bool,
            Kind::Text,
            Kind::I16,
            Kind::Bytes,
            Kind::I32,
            Kind::I32,
            Kind::Timestamp,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "iam_realms",
        &["realm_id", "initialized_at"],
        &["realm_id", "initialized_at"],
        &[Kind::Uuid, Kind::Timestamp],
    ),
    table(
        "iam_permissions",
        &[
            "realm_id",
            "id",
            "key",
            "description",
            "enabled",
            "created_at",
            "updated_at",
        ],
        &[
            "realm_id",
            "id",
            "key",
            "description",
            "enabled",
            "created_at",
            "updated_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::Text,
            Kind::Bool,
            Kind::Timestamp,
            Kind::Timestamp,
        ],
    ),
    table(
        "iam_roles",
        &[
            "realm_id",
            "id",
            "key",
            "name",
            "description",
            "reserved",
            "enabled",
            "created_at",
            "updated_at",
        ],
        &[
            "realm_id",
            "id",
            "key",
            "name",
            "description",
            "reserved",
            "enabled",
            "created_at",
            "updated_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::Text,
            Kind::Text,
            Kind::Bool,
            Kind::Bool,
            Kind::Timestamp,
            Kind::Timestamp,
        ],
    ),
    table(
        "iam_role_permissions",
        &["realm_id", "role_id", "permission_id"],
        &["realm_id", "role_id", "permission_id"],
        &[Kind::Uuid, Kind::Uuid, Kind::Uuid],
    ),
    table(
        "iam_service_accounts",
        &[
            "realm_id",
            "id",
            "name",
            "description",
            "enabled",
            "created_at",
            "updated_at",
        ],
        &[
            "realm_id",
            "id",
            "name",
            "description",
            "enabled",
            "created_at",
            "updated_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::Text,
            Kind::Bool,
            Kind::Timestamp,
            Kind::Timestamp,
        ],
    ),
    table(
        "iam_principal_roles",
        &[
            "realm_id",
            "principal_kind",
            "principal_id",
            "role_id",
            "created_at",
        ],
        &[
            "realm_id",
            "principal_kind",
            "principal_id",
            "role_id",
            "created_at",
        ],
        &[
            Kind::Uuid,
            Kind::Text,
            Kind::Uuid,
            Kind::Uuid,
            Kind::Timestamp,
        ],
    ),
    table(
        "iam_api_keys",
        &[
            "realm_id",
            "id",
            "principal_kind",
            "principal_id",
            "name",
            "digest",
            "created_at",
            "expires_at",
            "grace_expires_at",
            "revoked_at",
        ],
        &[
            "realm_id",
            "id",
            "principal_kind",
            "principal_id",
            "name",
            "digest",
            "created_at",
            "expires_at",
            "grace_expires_at",
            "revoked_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::Uuid,
            Kind::Text,
            Kind::Bytes,
            Kind::Timestamp,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "iam_api_key_scopes",
        &["realm_id", "api_key_id", "permission_id"],
        &["realm_id", "api_key_id", "permission_id"],
        &[Kind::Uuid, Kind::Uuid, Kind::Uuid],
    ),
    table(
        "outbox",
        &[
            "id",
            "realm_id",
            "user_id",
            "kind",
            "payload",
            "created_at",
            "delivered_at",
            "claim_id",
            "consumer_id",
            "lease_expires_at",
        ],
        &[
            "id",
            "realm_id",
            "user_id",
            "kind",
            "payload",
            "created_at",
            "delivered_at",
            "claim_id",
            "consumer_id",
            "lease_expires_at",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::Json,
            Kind::Timestamp,
            Kind::OptionalTimestamp,
            Kind::OptionalUuid,
            Kind::OptionalText,
            Kind::OptionalTimestamp,
        ],
    ),
    table(
        "audit_log",
        &[
            "id",
            "realm_id",
            "actor_kind",
            "actor_user_id",
            "subject_user_id",
            "kind",
            "outcome",
            "metadata_json",
            "occurred_at",
            "outbox_event_id",
        ],
        &[
            "id",
            "realm_id",
            "actor_kind",
            "actor_user_id",
            "subject_user_id",
            "kind",
            "outcome",
            "metadata",
            "occurred_at",
            "outbox_event_id",
        ],
        &[
            Kind::Uuid,
            Kind::Uuid,
            Kind::Text,
            Kind::OptionalUuid,
            Kind::OptionalUuid,
            Kind::Text,
            Kind::Text,
            Kind::Json,
            Kind::Timestamp,
            Kind::OptionalUuid,
        ],
    ),
];

struct Arguments {
    sqlite_path: PathBuf,
    postgres_url_env: String,
    allow_insecure_localhost: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    if env::args().any(|value| value == "--help" || value == "-h") {
        print_usage();
        return ExitCode::SUCCESS;
    }
    match run().await {
        Ok(rows) => {
            println!("migration complete: {rows} rows copied and verified");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("migration failed: {}", error.code().as_str());
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<u64, AuthError> {
    let arguments = parse_arguments()?;
    let database_url = env::var(&arguments.postgres_url_env).map_err(|_| {
        AuthError::new(
            ErrorCode::Misconfigured,
            "PostgreSQL URL environment variable is missing",
            false,
        )
    })?;
    let source = open_locked_source(&arguments.sqlite_path)?;
    verify_source(&source)?;

    let mut migration_config = PostgresConfig::new(SecretString::new(database_url.clone()));
    migration_config.allow_insecure_localhost = arguments.allow_insecure_localhost;
    PostgresMigrator::migrate(&migration_config).await?;
    let pool = connect_target(&database_url, arguments.allow_insecure_localhost).await?;
    ensure_target_empty(&pool).await?;
    set_import_status(&pool, "in_progress", None).await?;

    let imported = import_all(&source, &pool).await;
    if imported.is_err() {
        let _ignored = set_import_status(&pool, "failed", None).await;
    }
    let rows = imported?;
    pool.close().await;
    source
        .execute_batch("ROLLBACK")
        .map_err(|_| AuthError::storage_unavailable())?;
    Ok(rows)
}

fn parse_arguments() -> Result<Arguments, AuthError> {
    let values = env::args().skip(1).collect::<Vec<_>>();
    if values.first().map(String::as_str) != Some("sqlite-to-postgres") {
        return Err(AuthError::invalid_input());
    }
    let mut sqlite_path = None;
    let mut postgres_url_env = "SDK_AUTH_POSTGRES_URL".to_owned();
    let mut allow_insecure_localhost = false;
    let mut index = 1;
    while index < values.len() {
        match values[index].as_str() {
            "--sqlite" => {
                index += 1;
                sqlite_path = values.get(index).map(PathBuf::from);
            }
            "--postgres-url-env" => {
                index += 1;
                postgres_url_env = values
                    .get(index)
                    .filter(|value| valid_env_name(value))
                    .cloned()
                    .ok_or_else(AuthError::invalid_input)?;
            }
            "--allow-insecure-localhost" => allow_insecure_localhost = true,
            _ => return Err(AuthError::invalid_input()),
        }
        index += 1;
    }
    Ok(Arguments {
        sqlite_path: sqlite_path.ok_or_else(AuthError::invalid_input)?,
        postgres_url_env,
        allow_insecure_localhost,
    })
}

fn print_usage() {
    println!(
        "Usage: sdk-auth-migrate sqlite-to-postgres --sqlite <path> [--postgres-url-env <name>] [--allow-insecure-localhost]"
    );
}

fn valid_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn open_locked_source(path: &PathBuf) -> Result<Connection, AuthError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| AuthError::storage_unavailable())?;
    connection
        .busy_timeout(Duration::from_secs(2))
        .map_err(|_| AuthError::storage_unavailable())?;
    connection
        .execute_batch("PRAGMA foreign_keys=ON; BEGIN IMMEDIATE; PRAGMA query_only=ON;")
        .map_err(|_| AuthError::storage_unavailable())?;
    Ok(connection)
}

fn verify_source(source: &Connection) -> Result<(), AuthError> {
    let version: u32 = source
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| AuthError::schema_incompatible())?;
    if version != LATEST_SCHEMA_VERSION {
        return Err(AuthError::schema_incompatible());
    }
    let integrity: String = source
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| AuthError::storage_unavailable())?;
    let foreign_key_violation: bool = source
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AuthError::storage_unavailable())?;
    if integrity != "ok" || foreign_key_violation {
        return Err(AuthError::new(
            ErrorCode::Conflict,
            "SQLite source failed integrity validation",
            false,
        ));
    }
    Ok(())
}

async fn connect_target(database_url: &str, allow_insecure: bool) -> Result<PgPool, AuthError> {
    let parsed = Url::parse(database_url).map_err(|_| AuthError::invalid_input())?;
    let loopback = parsed
        .host_str()
        .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if allow_insecure && !loopback {
        return Err(AuthError::new(
            ErrorCode::Misconfigured,
            "insecure PostgreSQL transport is restricted to loopback",
            false,
        ));
    }
    let ssl_mode = if allow_insecure {
        PgSslMode::Disable
    } else {
        PgSslMode::VerifyFull
    };
    let options = PgConnectOptions::from_str(database_url)
        .map_err(|_| AuthError::invalid_input())?
        .ssl_mode(ssl_mode)
        .application_name("sdk-auth-migrate")
        .disable_statement_logging();
    tokio::time::timeout(
        Duration::from_secs(5),
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect_with(options),
    )
    .await
    .map_err(|_| AuthError::dependency_unavailable())?
    .map_err(|_| AuthError::dependency_unavailable())
}

async fn ensure_target_empty(pool: &PgPool) -> Result<(), AuthError> {
    for spec in TABLES {
        let mut builder = QueryBuilder::<Postgres>::new("SELECT EXISTS(SELECT 1 FROM ");
        builder.push(spec.name).push(" LIMIT 1)");
        let occupied: bool = builder
            .build_query_scalar()
            .fetch_one(pool)
            .await
            .map_err(|_| AuthError::storage_unavailable())?;
        if occupied {
            return Err(AuthError::new(
                ErrorCode::Conflict,
                "PostgreSQL import target is not empty",
                false,
            ));
        }
    }
    Ok(())
}

async fn set_import_status(
    pool: &PgPool,
    status: &str,
    completed_at: Option<DateTime<Utc>>,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO sdk_import_status(singleton,status,source_schema_version,started_at,completed_at) VALUES(TRUE,$1,$2,$3,$4) ON CONFLICT(singleton) DO UPDATE SET status=EXCLUDED.status,source_schema_version=EXCLUDED.source_schema_version,started_at=EXCLUDED.started_at,completed_at=EXCLUDED.completed_at",
    )
    .bind(status)
    .bind(i32::try_from(LATEST_SCHEMA_VERSION).map_err(|_| AuthError::invalid_input())?)
    .bind(Utc::now())
    .bind(completed_at)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|_| AuthError::storage_unavailable())
}

async fn import_all(source: &Connection, pool: &PgPool) -> Result<u64, AuthError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| AuthError::storage_unavailable())?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(IMPORT_LOCK_ID)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::storage_unavailable())?;
    let mut total = 0_u64;
    for spec in TABLES {
        total = total
            .checked_add(import_table(source, &mut transaction, spec).await?)
            .ok_or_else(AuthError::storage_unavailable)?;
    }
    sqlx::query(
        "UPDATE sdk_import_status SET status='complete',completed_at=$1 WHERE singleton=TRUE AND status='in_progress'",
    )
    .bind(Utc::now())
    .execute(&mut *transaction)
    .await
    .map_err(|_| AuthError::storage_unavailable())?;
    transaction
        .commit()
        .await
        .map_err(|_| AuthError::storage_unavailable())?;
    Ok(total)
}

async fn import_table(
    source: &Connection,
    target: &mut sqlx::PgConnection,
    spec: &TableSpec,
) -> Result<u64, AuthError> {
    if spec.source_columns.len() != spec.target_columns.len()
        || spec.source_columns.len() != spec.kinds.len()
    {
        return Err(AuthError::schema_incompatible());
    }
    let source_query = format!(
        "SELECT {} FROM {}",
        spec.source_columns.join(","),
        spec.name
    );
    let mut statement = source
        .prepare(&source_query)
        .map_err(|_| AuthError::schema_incompatible())?;
    let mut rows = statement
        .query([])
        .map_err(|_| AuthError::storage_unavailable())?;
    let prefix = format!(
        "INSERT INTO {}({}) VALUES",
        spec.name,
        spec.target_columns.join(",")
    );
    let mut builder = QueryBuilder::<Postgres>::new(prefix);
    let mut batch_rows = 0_u16;
    let mut copied = 0_u64;
    while let Some(row) = rows.next().map_err(|_| AuthError::storage_unavailable())? {
        if batch_rows != 0 {
            builder.push(",");
        }
        builder.push("(");
        for (index, kind) in spec.kinds.iter().enumerate() {
            if index != 0 {
                builder.push(",");
            }
            let value: Value = row
                .get(index)
                .map_err(|_| AuthError::storage_unavailable())?;
            bind_value(&mut builder, *kind, value)?;
        }
        builder.push(")");
        batch_rows += 1;
        copied = copied
            .checked_add(1)
            .ok_or_else(AuthError::storage_unavailable)?;
        if batch_rows == 256 {
            builder
                .build()
                .execute(&mut *target)
                .await
                .map_err(|_| AuthError::storage_unavailable())?;
            builder.reset();
            batch_rows = 0;
        }
    }
    if batch_rows != 0 {
        builder
            .build()
            .execute(&mut *target)
            .await
            .map_err(|_| AuthError::storage_unavailable())?;
    }
    Ok(copied)
}

fn bind_value(
    builder: &mut QueryBuilder<Postgres>,
    kind: Kind,
    value: Value,
) -> Result<(), AuthError> {
    match kind {
        Kind::Uuid => {
            builder.push_bind(parse_uuid(required_text(value)?)?);
        }
        Kind::OptionalUuid => {
            builder.push_bind(optional_text(value)?.map(parse_uuid).transpose()?);
        }
        Kind::Text => {
            builder.push_bind(required_text(value)?);
        }
        Kind::OptionalText => {
            builder.push_bind(optional_text(value)?);
        }
        Kind::Bool => {
            builder.push_bind(match required_integer(value)? {
                0 => false,
                1 => true,
                _ => return Err(AuthError::schema_incompatible()),
            });
        }
        Kind::I16 => {
            builder.push_bind(
                i16::try_from(required_integer(value)?)
                    .map_err(|_| AuthError::schema_incompatible())?,
            );
        }
        Kind::I32 => {
            builder.push_bind(
                i32::try_from(required_integer(value)?)
                    .map_err(|_| AuthError::schema_incompatible())?,
            );
        }
        Kind::I64 => {
            builder.push_bind(required_integer(value)?);
        }
        Kind::OptionalI64 => {
            builder.push_bind(optional_integer(value)?);
        }
        Kind::Bytes => {
            builder.push_bind(required_bytes(value)?);
        }
        Kind::Timestamp => {
            builder.push_bind(parse_timestamp(&required_text(value)?)?);
        }
        Kind::OptionalTimestamp => {
            builder.push_bind(
                optional_text(value)?
                    .map(|value| parse_timestamp(&value))
                    .transpose()?,
            );
        }
        Kind::Json => {
            builder.push_bind(
                serde_json::from_str::<serde_json::Value>(&required_text(value)?)
                    .map_err(|_| AuthError::schema_incompatible())?,
            );
        }
        Kind::TimestampArray => {
            let values = serde_json::from_str::<Vec<String>>(&required_text(value)?)
                .map_err(|_| AuthError::schema_incompatible())?;
            builder.push_bind(
                values
                    .iter()
                    .map(|value| parse_timestamp(value))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
    }
    Ok(())
}

fn required_text(value: Value) -> Result<String, AuthError> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(AuthError::schema_incompatible()),
    }
}

fn optional_text(value: Value) -> Result<Option<String>, AuthError> {
    match value {
        Value::Null => Ok(None),
        Value::Text(value) => Ok(Some(value)),
        _ => Err(AuthError::schema_incompatible()),
    }
}

fn required_integer(value: Value) -> Result<i64, AuthError> {
    match value {
        Value::Integer(value) => Ok(value),
        _ => Err(AuthError::schema_incompatible()),
    }
}

fn optional_integer(value: Value) -> Result<Option<i64>, AuthError> {
    match value {
        Value::Null => Ok(None),
        Value::Integer(value) => Ok(Some(value)),
        _ => Err(AuthError::schema_incompatible()),
    }
}

fn required_bytes(value: Value) -> Result<Vec<u8>, AuthError> {
    match value {
        Value::Blob(value) => Ok(value),
        _ => Err(AuthError::schema_incompatible()),
    }
}

fn parse_uuid(value: String) -> Result<Uuid, AuthError> {
    Uuid::parse_str(&value).map_err(|_| AuthError::schema_incompatible())
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| AuthError::schema_incompatible())
}

#[cfg(test)]
mod tests {
    use rusqlite::params;
    use sdk_auth_postgres::PostgresAuthStore;
    use sdk_auth_sqlite::SqliteMigrator;
    use tempfile::NamedTempFile;

    use super::*;

    #[tokio::test]
    async fn copies_real_rows_and_unlocks_postgres_startup() -> Result<(), AuthError> {
        let Ok(database_url) = env::var("SDK_AUTH_TEST_POSTGRES_URL") else {
            return Ok(());
        };
        let file = NamedTempFile::new().map_err(|_| AuthError::storage_unavailable())?;
        SqliteMigrator::migrate(file.path())?;
        let connection =
            Connection::open(file.path()).map_err(|_| AuthError::storage_unavailable())?;
        let realm_id = Uuid::now_v7().to_string();
        let user_id = Uuid::now_v7().to_string();
        let identity_id = Uuid::now_v7().to_string();
        let event_id = Uuid::now_v7().to_string();
        let audit_id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        connection
            .execute(
                "INSERT INTO users(realm_id,id,email,normalized_email,email_verified,password_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                params![realm_id, user_id, "migration@example.com", "migration@example.com", 1_i64, "$argon2id$test", now, now],
            )
            .map_err(|_| AuthError::storage_unavailable())?;
        connection
            .execute(
                "INSERT INTO federated_identities(realm_id,id,user_id,provider_id,issuer,subject,verified_email,normalized_verified_email,created_at,last_used_at,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                params![realm_id, identity_id, user_id, "google", "https://accounts.google.com", "provider-subject", "migration@example.com", "migration@example.com", now, now, Option::<String>::None],
            )
            .map_err(|_| AuthError::storage_unavailable())?;
        connection
            .execute(
                "INSERT INTO federated_link_challenges(realm_id,digest,user_id,identity_id,provider_id,issuer,subject,verified_email,normalized_verified_email,expires_at,created_at,consumed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                params![realm_id, vec![7_u8; 32], user_id, Uuid::now_v7().to_string(), "github", "https://github.com", "123456", "migration@example.com", "migration@example.com", now, now, now],
            )
            .map_err(|_| AuthError::storage_unavailable())?;
        connection
            .execute(
                "INSERT INTO outbox(id,realm_id,user_id,kind,payload,created_at,delivered_at) VALUES(?,?,?,?,?,?,?)",
                params![event_id, realm_id, user_id, "email_verified", "{}", now, now],
            )
            .map_err(|_| AuthError::storage_unavailable())?;
        connection
            .execute(
                "INSERT INTO audit_log(id,realm_id,actor_kind,actor_user_id,subject_user_id,kind,outcome,metadata_json,occurred_at,outbox_event_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                params![audit_id, realm_id, "user", user_id, user_id, "email_verified", "succeeded", "{}", now, event_id],
            )
            .map_err(|_| AuthError::storage_unavailable())?;
        drop(connection);

        let mut config = PostgresConfig::new(SecretString::new(database_url.clone()));
        config.allow_insecure_localhost = true;
        PostgresMigrator::migrate(&config).await?;
        let source = open_locked_source(&file.path().to_path_buf())?;
        verify_source(&source)?;
        let pool = connect_target(&database_url, true).await?;
        ensure_target_empty(&pool).await?;
        set_import_status(&pool, "in_progress", None).await?;
        assert_eq!(import_all(&source, &pool).await?, 5);
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .map_err(|_| AuthError::storage_unavailable())?;
        assert_eq!(users, 1);
        let federated_identities: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM federated_identities")
                .fetch_one(&pool)
                .await
                .map_err(|_| AuthError::storage_unavailable())?;
        assert_eq!(federated_identities, 1);
        let federated_link_challenges: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM federated_link_challenges")
                .fetch_one(&pool)
                .await
                .map_err(|_| AuthError::storage_unavailable())?;
        assert_eq!(federated_link_challenges, 1);
        pool.close().await;
        source
            .execute_batch("ROLLBACK")
            .map_err(|_| AuthError::storage_unavailable())?;

        let store = PostgresAuthStore::connect(config).await?;
        store.health_check().await?;
        store.close().await;
        Ok(())
    }
}
