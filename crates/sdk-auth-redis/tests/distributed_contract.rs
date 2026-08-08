//! Redis adapter contract executed when its test service URL is configured.

use sdk_auth_error::AuthError;
use sdk_auth_redis::{RedisRateLimitConfig, RedisRateLimitStore};
use sdk_auth_testing::verify_rate_limit_contract;
use sdk_auth_types::{SecretBytes, SecretString};

#[tokio::test]
async fn redis_distributed_contract() -> Result<(), AuthError> {
    let Ok(redis_url) = std::env::var("SDK_AUTH_TEST_REDIS_URL") else {
        return Ok(());
    };
    let mut config = RedisRateLimitConfig::new(
        SecretString::new(redis_url),
        SecretBytes::new(vec![0xA5; 32]),
    );
    config.allow_insecure_localhost = true;
    let store = RedisRateLimitStore::connect(config).await?;
    verify_rate_limit_contract(&store).await
}
