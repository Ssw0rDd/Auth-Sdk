//! Redis-backed distributed login throttling for SDK-Auth.
//!
//! This adapter deliberately implements only [`sdk_auth_core::RateLimitStore`].
//! Identity, sessions and authorization remain in the primary transactional
//! store. Redis failures are fail-closed and never silently fall back to a
//! process-local counter.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, TimeZone as _, Utc};
use redis::{Script, aio::ConnectionManagerConfig};
use sdk_auth_core::{AttemptDecision, LoginAttemptPolicy, RateLimitStore};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::{RealmId, SecretBytes, SecretString};
use url::Url;
use uuid::Uuid;

const RECORD_SCRIPT: &str = r#"
local function record(attempts_key, block_key)
    local blocked = tonumber(redis.call('GET', block_key))
    if blocked and blocked > tonumber(ARGV[1]) then
        return blocked
    end
    if blocked then
        redis.call('DEL', block_key)
        redis.call('DEL', attempts_key)
    end

    redis.call('ZREMRANGEBYSCORE', attempts_key, '-inf', '(' .. ARGV[2])
    redis.call('ZADD', attempts_key, ARGV[1], ARGV[6])
    local count = redis.call('ZCARD', attempts_key)
    if count > tonumber(ARGV[3]) then
        local until_ms = tonumber(ARGV[1]) + tonumber(ARGV[4])
        redis.call('SET', block_key, until_ms, 'PX', ARGV[4])
        redis.call('DEL', attempts_key)
        return until_ms
    end
    redis.call('PEXPIRE', attempts_key, ARGV[5])
    return 0
end

local account = record(KEYS[1], KEYS[2])
local network = 0
if ARGV[7] == '1' then
    network = record(KEYS[3], KEYS[4])
end
if account > network then
    return account
end
return network
"#;

/// Timeouts and key-space settings for the Redis adapter.
pub struct RedisRateLimitConfig {
    /// Redis URL. Credentials are always redacted from debug output and errors.
    pub redis_url: SecretString,
    /// Secret 32-byte BLAKE3 key used to hide account and network subjects.
    pub privacy_key: SecretBytes,
    /// Non-secret prefix used to isolate an environment or application.
    pub namespace: String,
    /// Maximum time allowed to establish or re-establish a connection.
    pub connect_timeout: Duration,
    /// Maximum time allowed for one Redis response.
    pub response_timeout: Duration,
    /// Allows plaintext Redis only on a loopback development endpoint.
    pub allow_insecure_localhost: bool,
}

impl RedisRateLimitConfig {
    /// Creates a secure-by-default configuration.
    #[must_use]
    pub fn new(redis_url: SecretString, privacy_key: SecretBytes) -> Self {
        Self {
            redis_url,
            privacy_key,
            namespace: "sdk-auth".to_owned(),
            connect_timeout: Duration::from_secs(3),
            response_timeout: Duration::from_secs(2),
            allow_insecure_localhost: false,
        }
    }

    fn validate(&self) -> Result<(), AuthError> {
        let parsed =
            Url::parse(self.redis_url.expose_secret()).map_err(|_| AuthError::invalid_input())?;
        let secure = parsed.scheme() == "rediss";
        let insecure_loopback = parsed.scheme() == "redis"
            && self.allow_insecure_localhost
            && is_loopback(parsed.host_str());
        if (!secure && !insecure_loopback)
            || self.privacy_key.len() != 32
            || self.namespace.is_empty()
            || self.namespace.len() > 64
            || !self
                .namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || self.connect_timeout.is_zero()
            || self.response_timeout.is_zero()
        {
            return Err(AuthError::new(
                ErrorCode::Misconfigured,
                "Redis rate-limit configuration is invalid",
                false,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for RedisRateLimitConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisRateLimitConfig")
            .field("redis_url", &"[REDACTED]")
            .field("privacy_key", &"[REDACTED]")
            .field("namespace", &self.namespace)
            .field("connect_timeout", &self.connect_timeout)
            .field("response_timeout", &self.response_timeout)
            .field("allow_insecure_localhost", &self.allow_insecure_localhost)
            .finish()
    }
}

struct Inner {
    connection: redis::aio::ConnectionManager,
    privacy_key: SecretBytes,
    namespace: String,
    instance_id: String,
    sequence: AtomicU64,
}

/// Exact sliding-window rate limiter backed by a primary Redis instance.
#[derive(Clone)]
pub struct RedisRateLimitStore {
    inner: Arc<Inner>,
}

impl RedisRateLimitStore {
    /// Connects to Redis and verifies liveness before returning the adapter.
    pub async fn connect(config: RedisRateLimitConfig) -> Result<Self, AuthError> {
        config.validate()?;
        let client = redis::Client::open(config.redis_url.expose_secret())
            .map_err(|_| AuthError::invalid_input())?;
        let manager_config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(config.connect_timeout))
            .set_response_timeout(Some(config.response_timeout));
        let mut connection = tokio::time::timeout(
            config.connect_timeout,
            client.get_connection_manager_with_config(manager_config),
        )
        .await
        .map_err(|_| AuthError::dependency_unavailable())?
        .map_err(|_| AuthError::dependency_unavailable())?;
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .map_err(|_| AuthError::dependency_unavailable())?;
        Ok(Self {
            inner: Arc::new(Inner {
                connection,
                privacy_key: config.privacy_key,
                namespace: config.namespace,
                instance_id: Uuid::now_v7().simple().to_string(),
                sequence: AtomicU64::new(0),
            }),
        })
    }

    /// Executes a bounded primary-node liveness check.
    pub async fn health_check(&self) -> Result<(), AuthError> {
        let mut connection = self.inner.connection.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .map(|_| ())
            .map_err(|_| AuthError::dependency_unavailable())
    }

    fn bucket_keys(
        &self,
        realm_id: RealmId,
        scope: &str,
        subject: &str,
    ) -> Result<(String, String), AuthError> {
        let privacy_key: &[u8; 32] = self
            .inner
            .privacy_key
            .expose_secret()
            .try_into()
            .map_err(|_| AuthError::crypto_failure())?;
        let mut input = Vec::with_capacity(16 + scope.len() + subject.len() + 2);
        input.extend_from_slice(realm_id.as_uuid().as_bytes());
        input.push(0);
        input.extend_from_slice(scope.as_bytes());
        input.push(0);
        input.extend_from_slice(subject.as_bytes());
        let digest = blake3::keyed_hash(privacy_key, &input).to_hex();
        let tag = format!("{}:{{{digest}}}", self.inner.namespace);
        Ok((format!("{tag}:attempts"), format!("{tag}:block")))
    }
}

#[async_trait]
impl RateLimitStore for RedisRateLimitStore {
    async fn record_login_attempt(
        &self,
        realm_id: RealmId,
        subject: &str,
        network_hash: Option<&str>,
        now: DateTime<Utc>,
        policy: LoginAttemptPolicy,
    ) -> Result<AttemptDecision, AuthError> {
        let window_ms = positive_milliseconds(policy.window)?;
        let lockout_ms = positive_milliseconds(policy.lockout)?;
        if policy.max_failures == 0 || subject.is_empty() || subject.len() > 1_024 {
            return Err(AuthError::invalid_input());
        }
        let now_ms = now.timestamp_millis();
        let cutoff_ms = now_ms
            .checked_sub(window_ms)
            .ok_or_else(AuthError::invalid_input)?;
        let ttl_ms = window_ms
            .checked_add(lockout_ms)
            .ok_or_else(AuthError::invalid_input)?;
        let (account_attempts, account_block) = self.bucket_keys(realm_id, "account", subject)?;
        let (network_attempts, network_block) = if let Some(network_hash) = network_hash {
            if network_hash.is_empty() || network_hash.len() > 1_024 {
                return Err(AuthError::invalid_input());
            }
            self.bucket_keys(realm_id, "network", network_hash)?
        } else {
            (account_attempts.clone(), account_block.clone())
        };
        let sequence = self.inner.sequence.fetch_add(1, Ordering::Relaxed);
        let member = format!("{}:{sequence}", self.inner.instance_id);
        let mut connection = self.inner.connection.clone();
        let blocked_until_ms: i64 = Script::new(RECORD_SCRIPT)
            .key(account_attempts)
            .key(account_block)
            .key(network_attempts)
            .key(network_block)
            .arg(now_ms)
            .arg(cutoff_ms)
            .arg(policy.max_failures)
            .arg(lockout_ms)
            .arg(ttl_ms)
            .arg(member)
            .arg(i64::from(network_hash.is_some()))
            .invoke_async(&mut connection)
            .await
            .map_err(|_| AuthError::dependency_unavailable())?;
        if blocked_until_ms == 0 {
            Ok(AttemptDecision::Allowed)
        } else {
            Utc.timestamp_millis_opt(blocked_until_ms)
                .single()
                .map(AttemptDecision::BlockedUntil)
                .ok_or_else(AuthError::dependency_unavailable)
        }
    }

    async fn clear_login_attempts(
        &self,
        realm_id: RealmId,
        subject: &str,
    ) -> Result<(), AuthError> {
        if subject.is_empty() || subject.len() > 1_024 {
            return Err(AuthError::invalid_input());
        }
        let (attempts, block) = self.bucket_keys(realm_id, "account", subject)?;
        let mut connection = self.inner.connection.clone();
        redis::cmd("DEL")
            .arg(attempts)
            .arg(block)
            .query_async::<u64>(&mut connection)
            .await
            .map(|_| ())
            .map_err(|_| AuthError::dependency_unavailable())
    }
}

fn positive_milliseconds(duration: chrono::Duration) -> Result<i64, AuthError> {
    let milliseconds = duration.num_milliseconds();
    if milliseconds > 0 {
        Ok(milliseconds)
    } else {
        Err(AuthError::invalid_input())
    }
}

fn is_loopback(host: Option<&str>) -> bool {
    host.is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_debug_redacts_secrets() {
        let config = RedisRateLimitConfig::new(
            SecretString::new("rediss://user:password@example.test/0"),
            SecretBytes::new(vec![7_u8; 32]),
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("password"));
        assert!(!debug.contains("777"));
    }

    #[test]
    fn plaintext_is_restricted_to_explicit_loopback_development() {
        let remote = RedisRateLimitConfig::new(
            SecretString::new("redis://cache.example.test/0"),
            SecretBytes::new(vec![1_u8; 32]),
        );
        assert!(remote.validate().is_err());

        let mut local = RedisRateLimitConfig::new(
            SecretString::new("redis://127.0.0.1/0"),
            SecretBytes::new(vec![1_u8; 32]),
        );
        local.allow_insecure_localhost = true;
        assert!(local.validate().is_ok());
    }

    #[test]
    fn rate_window_requires_at_least_one_millisecond() {
        assert!(positive_milliseconds(chrono::Duration::nanoseconds(1)).is_err());
        assert_eq!(
            positive_milliseconds(chrono::Duration::milliseconds(1)).ok(),
            Some(1)
        );
    }
}
