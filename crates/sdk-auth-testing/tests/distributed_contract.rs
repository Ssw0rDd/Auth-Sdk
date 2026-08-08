//! Cross-adapter contracts for distributed rate limiting and outbox leasing.

use sdk_auth_error::AuthError;
use sdk_auth_memory::MemoryAuthStore;
use sdk_auth_sqlite::SqliteAuthStore;
use sdk_auth_testing::{verify_outbox_contract, verify_rate_limit_contract};

#[tokio::test]
async fn memory_distributed_contract() -> Result<(), AuthError> {
    let store = MemoryAuthStore::new();
    verify_rate_limit_contract(&store).await?;
    verify_outbox_contract(&store).await
}

#[tokio::test]
async fn sqlite_distributed_contract() -> Result<(), AuthError> {
    let store = SqliteAuthStore::in_memory()?;
    verify_rate_limit_contract(&store).await?;
    verify_outbox_contract(&store).await
}
