//! Full authentication, IAM and passkey contracts for PostgreSQL.

#[path = "../../sdk-auth-testing/tests/auth_contract.rs"]
mod auth_contract;
#[path = "../../sdk-auth-testing/tests/federation_contract.rs"]
mod federation_contract;
#[path = "../../sdk-auth-testing/tests/iam_contract.rs"]
mod iam_contract;
#[path = "../../sdk-auth-testing/tests/passkey_contract.rs"]
mod passkey_contract;

use std::sync::Arc;

use sdk_auth_core::AuthStore;
use sdk_auth_error::AuthError;
use sdk_auth_postgres::{PostgresAuthStore, PostgresConfig, PostgresMigrator};
use sdk_auth_types::SecretString;

#[tokio::test]
async fn postgres_satisfies_full_contract() -> Result<(), AuthError> {
    let Ok(database_url) = std::env::var("SDK_AUTH_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let mut config = PostgresConfig::new(SecretString::new(database_url));
    config.allow_insecure_localhost = true;
    PostgresMigrator::migrate(&config).await?;
    let store = Arc::new(PostgresAuthStore::connect(config).await?);

    let auth_store: Arc<dyn AuthStore> = store.clone();
    auth_contract::exercise_contract(auth_contract::service(Arc::clone(&auth_store))?).await?;
    auth_contract::exercise_mfa_contract(Arc::clone(&auth_store)).await?;
    auth_contract::exercise_vault_rewrap(Arc::clone(&auth_store)).await?;
    auth_contract::exercise_mfa_management(auth_store).await?;
    federation_contract::federation_contract(Arc::clone(&store)).await?;
    iam_contract::exercise(Arc::clone(&store)).await?;
    iam_contract::bootstrap_race(Arc::clone(&store)).await?;
    passkey_contract::exercise(Arc::clone(&store)).await?;

    store.close().await;
    Ok(())
}
