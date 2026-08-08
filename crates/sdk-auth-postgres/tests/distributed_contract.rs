//! PostgreSQL adapter contract executed when its test database URL is configured.

use sdk_auth_error::AuthError;
use sdk_auth_postgres::{PostgresAuthStore, PostgresConfig, PostgresMigrator};
use sdk_auth_testing::{verify_outbox_contract, verify_rate_limit_contract};
use sdk_auth_types::SecretString;

#[tokio::test]
async fn postgres_distributed_contract() -> Result<(), AuthError> {
    let Ok(database_url) = std::env::var("SDK_AUTH_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let mut config = PostgresConfig::new(SecretString::new(database_url));
    config.allow_insecure_localhost = true;
    PostgresMigrator::migrate(&config).await?;
    let store = PostgresAuthStore::connect(config).await?;
    verify_rate_limit_contract(&store).await?;
    verify_outbox_contract(&store).await?;
    store.close().await;
    Ok(())
}
