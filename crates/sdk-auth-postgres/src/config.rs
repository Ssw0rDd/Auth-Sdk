use std::{fmt, str::FromStr as _, time::Duration};

use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::SecretString;
use sqlx::{
    ConnectOptions as _, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use url::Url;

/// Bounded PostgreSQL pool and session timeout policy.
#[derive(Debug, Clone)]
pub struct PostgresPoolConfig {
    /// Maximum concurrent connections owned by this SDK instance.
    pub max_connections: u32,
    /// Connections established eagerly.
    pub min_connections: u32,
    /// Maximum wait for a checked-out connection.
    pub acquire_timeout: Duration,
    /// Maximum time allowed for initial pool connection.
    pub connect_timeout: Duration,
    /// Idle connection retirement threshold.
    pub idle_timeout: Duration,
    /// Maximum connection lifetime.
    pub max_lifetime: Duration,
    /// Per-session PostgreSQL statement timeout.
    pub statement_timeout: Duration,
    /// Per-session PostgreSQL lock wait timeout.
    pub lock_timeout: Duration,
    /// Maximum idle duration inside a transaction.
    pub idle_in_transaction_session_timeout: Duration,
}

impl Default for PostgresPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 16,
            min_connections: 0,
            acquire_timeout: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(10 * 60),
            max_lifetime: Duration::from_secs(30 * 60),
            statement_timeout: Duration::from_secs(5),
            lock_timeout: Duration::from_secs(2),
            idle_in_transaction_session_timeout: Duration::from_secs(10),
        }
    }
}

/// Secret-redacting PostgreSQL connection policy.
pub struct PostgresConfig {
    /// Database URL. Its password and host never appear in `Debug` or SDK errors.
    pub database_url: SecretString,
    /// Pool and database-session bounds.
    pub pool: PostgresPoolConfig,
    /// Non-sensitive server-side application label.
    pub application_name: String,
    /// Allows plaintext only for loopback development databases.
    pub allow_insecure_localhost: bool,
}

impl PostgresConfig {
    /// Creates a secure-by-default PostgreSQL configuration.
    #[must_use]
    pub fn new(database_url: SecretString) -> Self {
        Self {
            database_url,
            pool: PostgresPoolConfig::default(),
            application_name: "sdk-auth".to_owned(),
            allow_insecure_localhost: false,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), AuthError> {
        let parsed = Url::parse(self.database_url.expose_secret())
            .map_err(|_| AuthError::invalid_input())?;
        if !matches!(parsed.scheme(), "postgres" | "postgresql")
            || self.pool.max_connections == 0
            || self.pool.min_connections > self.pool.max_connections
            || self.pool.max_connections > 1_024
            || self.application_name.is_empty()
            || self.application_name.len() > 64
            || !self
                .application_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || [
                self.pool.acquire_timeout,
                self.pool.connect_timeout,
                self.pool.statement_timeout,
                self.pool.lock_timeout,
                self.pool.idle_in_transaction_session_timeout,
            ]
            .into_iter()
            .any(|duration| duration.is_zero())
        {
            return Err(AuthError::invalid_input());
        }
        if self.allow_insecure_localhost && !is_loopback_host(parsed.host_str()) {
            return Err(AuthError::new(
                ErrorCode::Misconfigured,
                "insecure PostgreSQL transport is restricted to loopback",
                false,
            ));
        }
        Ok(())
    }

    fn connect_options(&self) -> Result<PgConnectOptions, AuthError> {
        self.validate()?;
        let parsed = Url::parse(self.database_url.expose_secret())
            .map_err(|_| AuthError::invalid_input())?;
        let ssl_mode = if self.allow_insecure_localhost && is_loopback_host(parsed.host_str()) {
            PgSslMode::Disable
        } else {
            PgSslMode::VerifyFull
        };
        PgConnectOptions::from_str(self.database_url.expose_secret())
            .map(|options| {
                options
                    .ssl_mode(ssl_mode)
                    .application_name(&self.application_name)
                    .disable_statement_logging()
            })
            .map_err(|_| AuthError::invalid_input())
    }
}

impl fmt::Debug for PostgresConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresConfig")
            .field("database_url", &"[REDACTED]")
            .field("pool", &self.pool)
            .field("application_name", &self.application_name)
            .field("allow_insecure_localhost", &self.allow_insecure_localhost)
            .finish()
    }
}

pub(crate) async fn connect_pool(config: &PostgresConfig) -> Result<PgPool, AuthError> {
    let options = config.connect_options()?;
    let statement_timeout = duration_setting(config.pool.statement_timeout)?;
    let lock_timeout = duration_setting(config.pool.lock_timeout)?;
    let idle_transaction_timeout =
        duration_setting(config.pool.idle_in_transaction_session_timeout)?;
    let pool = PgPoolOptions::new()
        .max_connections(config.pool.max_connections)
        .min_connections(config.pool.min_connections)
        .acquire_timeout(config.pool.acquire_timeout)
        .idle_timeout(Some(config.pool.idle_timeout))
        .max_lifetime(Some(config.pool.max_lifetime))
        .after_connect(move |connection, _metadata| {
            let statement_timeout = statement_timeout.clone();
            let lock_timeout = lock_timeout.clone();
            let idle_transaction_timeout = idle_transaction_timeout.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('statement_timeout',$1,FALSE)")
                    .bind(statement_timeout)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SELECT set_config('lock_timeout',$1,FALSE)")
                    .bind(lock_timeout)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SELECT set_config('idle_in_transaction_session_timeout',$1,FALSE)")
                    .bind(idle_transaction_timeout)
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect_lazy_with(options);
    tokio::time::timeout(config.pool.connect_timeout, pool.acquire())
        .await
        .map_err(|_| AuthError::dependency_unavailable())?
        .map_err(super::mapping::storage)?;
    Ok(pool)
}

fn duration_setting(duration: Duration) -> Result<String, AuthError> {
    u64::try_from(duration.as_millis())
        .map(|milliseconds| format!("{milliseconds}ms"))
        .map_err(|_| AuthError::invalid_input())
}

fn is_loopback_host(host: Option<&str>) -> bool {
    host.is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"))
}
