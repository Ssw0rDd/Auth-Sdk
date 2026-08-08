//! Stable error codes shared by the SDK-Auth crates and bindings.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable machine-readable error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ErrorCode {
    /// One or more inputs failed validation.
    InvalidInput,
    /// Authentication failed without revealing whether an account exists.
    InvalidCredentials,
    /// The account cannot perform the operation until its email is verified.
    AccountUnverified,
    /// A supplied MFA proof is invalid without exposing factor state.
    SecondFactorInvalid,
    /// The requested account has no active MFA factor.
    MfaNotEnrolled,
    /// The requested resource conflicts with existing state.
    Conflict,
    /// The caller exceeded an authentication attempt policy.
    RateLimited,
    /// A token is malformed, unknown, or does not belong to the realm.
    TokenInvalid,
    /// A token is valid but expired.
    TokenExpired,
    /// A single-use token was presented after it had already been consumed.
    TokenReused,
    /// A passkey signature counter indicates a potentially cloned authenticator.
    AuthenticatorCompromised,
    /// The referenced session is revoked or no longer active.
    SessionRevoked,
    /// Authentication succeeded but the principal lacks the requested permission.
    PermissionDenied,
    /// The realm has not completed its one-time IAM bootstrap.
    RealmNotInitialized,
    /// Persistent storage is temporarily unavailable.
    StorageUnavailable,
    /// A required external dependency is temporarily unavailable.
    DependencyUnavailable,
    /// A bounded connection pool could not supply a connection in time.
    PoolExhausted,
    /// The persistent schema cannot be read or written by this SDK version.
    SchemaIncompatible,
    /// An offline import did not complete validation and cannot be opened.
    MigrationIncomplete,
    /// An outbox acknowledgement or release used an invalid or expired claim.
    OutboxClaimInvalid,
    /// A cryptographic operation failed safely.
    CryptoFailure,
    /// SDK configuration is incomplete or unsafe.
    Misconfigured,
    /// An unexpected internal failure occurred.
    Internal,
}

impl ErrorCode {
    /// Returns the stable external representation of this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::AccountUnverified => "ACCOUNT_UNVERIFIED",
            Self::SecondFactorInvalid => "SECOND_FACTOR_INVALID",
            Self::MfaNotEnrolled => "MFA_NOT_ENROLLED",
            Self::Conflict => "CONFLICT",
            Self::RateLimited => "RATE_LIMITED",
            Self::TokenInvalid => "TOKEN_INVALID",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::TokenReused => "TOKEN_REUSED",
            Self::AuthenticatorCompromised => "AUTHENTICATOR_COMPROMISED",
            Self::SessionRevoked => "SESSION_REVOKED",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::RealmNotInitialized => "REALM_NOT_INITIALIZED",
            Self::StorageUnavailable => "STORAGE_UNAVAILABLE",
            Self::DependencyUnavailable => "DEPENDENCY_UNAVAILABLE",
            Self::PoolExhausted => "POOL_EXHAUSTED",
            Self::SchemaIncompatible => "SCHEMA_INCOMPATIBLE",
            Self::MigrationIncomplete => "MIGRATION_INCOMPLETE",
            Self::OutboxClaimInvalid => "OUTBOX_CLAIM_INVALID",
            Self::CryptoFailure => "CRYPTO_FAILURE",
            Self::Misconfigured => "MISCONFIGURED",
            Self::Internal => "INTERNAL",
        }
    }
}

/// Error exposed by SDK public APIs.
///
/// Messages are deliberately generic. Infrastructure-specific causes belong in
/// structured logs owned by the host and are never embedded here.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("{message}")]
pub struct AuthError {
    code: ErrorCode,
    message: &'static str,
    retryable: bool,
}

impl AuthError {
    /// Creates a new sanitized SDK error.
    #[must_use]
    pub const fn new(code: ErrorCode, message: &'static str, retryable: bool) -> Self {
        Self {
            code,
            message,
            retryable,
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns a sanitized human-readable message.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Indicates whether retrying later can reasonably succeed.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// Creates a generic validation failure.
    #[must_use]
    pub const fn invalid_input() -> Self {
        Self::new(ErrorCode::InvalidInput, "invalid input", false)
    }

    /// Creates an enumeration-resistant credential failure.
    #[must_use]
    pub const fn invalid_credentials() -> Self {
        Self::new(
            ErrorCode::InvalidCredentials,
            "authentication failed",
            false,
        )
    }

    /// Creates a sanitized storage failure.
    #[must_use]
    pub const fn storage_unavailable() -> Self {
        Self::new(
            ErrorCode::StorageUnavailable,
            "authentication storage is unavailable",
            true,
        )
    }

    /// Creates a sanitized external-dependency failure.
    #[must_use]
    pub const fn dependency_unavailable() -> Self {
        Self::new(
            ErrorCode::DependencyUnavailable,
            "authentication dependency is unavailable",
            true,
        )
    }

    /// Creates a sanitized pool-acquisition timeout.
    #[must_use]
    pub const fn pool_exhausted() -> Self {
        Self::new(
            ErrorCode::PoolExhausted,
            "authentication storage pool is exhausted",
            true,
        )
    }

    /// Creates a sanitized schema compatibility failure.
    #[must_use]
    pub const fn schema_incompatible() -> Self {
        Self::new(
            ErrorCode::SchemaIncompatible,
            "authentication storage schema is incompatible",
            false,
        )
    }

    /// Creates a sanitized incomplete-migration failure.
    #[must_use]
    pub const fn migration_incomplete() -> Self {
        Self::new(
            ErrorCode::MigrationIncomplete,
            "authentication storage migration is incomplete",
            false,
        )
    }

    /// Creates a sanitized invalid outbox-claim failure.
    #[must_use]
    pub const fn outbox_claim_invalid() -> Self {
        Self::new(
            ErrorCode::OutboxClaimInvalid,
            "outbox claim is invalid or expired",
            false,
        )
    }

    /// Creates a sanitized cryptographic failure.
    #[must_use]
    pub const fn crypto_failure() -> Self {
        Self::new(
            ErrorCode::CryptoFailure,
            "cryptographic operation failed",
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_error_shape_is_stable() {
        insta::assert_json_snapshot!(AuthError::invalid_credentials(), @r###"
        {
          "code": "INVALID_CREDENTIALS",
          "message": "authentication failed",
          "retryable": false
        }
        "###);
        assert_eq!(
            ErrorCode::InvalidCredentials.as_str(),
            "INVALID_CREDENTIALS"
        );
        assert!(!AuthError::invalid_input().retryable());
        assert_eq!(AuthError::crypto_failure().code(), ErrorCode::CryptoFailure);

        let codes = [
            ErrorCode::InvalidInput,
            ErrorCode::InvalidCredentials,
            ErrorCode::AccountUnverified,
            ErrorCode::SecondFactorInvalid,
            ErrorCode::MfaNotEnrolled,
            ErrorCode::Conflict,
            ErrorCode::RateLimited,
            ErrorCode::TokenInvalid,
            ErrorCode::TokenExpired,
            ErrorCode::TokenReused,
            ErrorCode::AuthenticatorCompromised,
            ErrorCode::SessionRevoked,
            ErrorCode::PermissionDenied,
            ErrorCode::RealmNotInitialized,
            ErrorCode::StorageUnavailable,
            ErrorCode::DependencyUnavailable,
            ErrorCode::PoolExhausted,
            ErrorCode::SchemaIncompatible,
            ErrorCode::MigrationIncomplete,
            ErrorCode::OutboxClaimInvalid,
            ErrorCode::CryptoFailure,
            ErrorCode::Misconfigured,
            ErrorCode::Internal,
        ];
        assert!(codes.into_iter().all(|code| !code.as_str().is_empty()));
        assert!(AuthError::storage_unavailable().retryable());
        assert!(!AuthError::new(ErrorCode::Internal, "internal", false).retryable());
    }
}
