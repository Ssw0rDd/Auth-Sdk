//! Server-side OAuth 2.0 and OpenID Connect provider adapters.

use async_trait::async_trait;
use sdk_auth_core::VerifiedFederatedClaims;
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::SecretString;
use serde::Deserialize;
use url::Url;

mod github;
mod oidc;

pub use github::{GitHubProvider, GitHubProviderConfig};
pub use oidc::{OidcProvider, OidcProviderConfig};

/// Secrets retained by a trusted BFF while constructing an authorization request.
#[derive(Debug)]
pub struct ProviderAuthorizationRequest {
    /// Opaque CSRF state persisted server-side only as a digest.
    pub state: SecretString,
    /// OIDC replay-binding nonce. Non-OIDC providers ignore this value.
    pub nonce: SecretString,
    /// RFC 7636 verifier retained server-side; only its S256 challenge is sent.
    pub pkce_verifier: SecretString,
}

/// Secrets presented to a provider adapter after the BFF consumes callback state.
#[derive(Debug)]
pub struct ProviderCodeExchange {
    /// Temporary authorization code returned by the provider.
    pub code: SecretString,
    /// Original OIDC nonce loaded from trusted server-side state.
    pub nonce: SecretString,
    /// Original RFC 7636 verifier loaded from trusted server-side state.
    pub pkce_verifier: SecretString,
}

/// Verified provider protocol boundary used by the BFF orchestration layer.
#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    /// Stable provider configuration key.
    fn provider_id(&self) -> &str;

    /// Constructs the provider authorization URL with state, nonce and PKCE S256.
    fn authorization_url(&self, request: ProviderAuthorizationRequest) -> Result<Url, AuthError>;

    /// Exchanges a code and returns claims only after protocol verification succeeds.
    async fn exchange_code(
        &self,
        request: ProviderCodeExchange,
    ) -> Result<VerifiedFederatedClaims, AuthError>;
}

#[derive(Debug)]
pub(crate) struct OidcClaims {
    provider_id: String,
    issuer: String,
    subject: String,
    email: Option<String>,
    email_verified: bool,
}

pub(crate) fn map_oidc_claims(claims: OidcClaims) -> Result<VerifiedFederatedClaims, AuthError> {
    if claims.provider_id.is_empty() || claims.issuer.is_empty() || claims.subject.is_empty() {
        return Err(AuthError::invalid_input());
    }
    Ok(VerifiedFederatedClaims {
        provider_id: claims.provider_id,
        issuer: claims.issuer,
        subject: claims.subject,
        email: claims.email,
        email_verified: claims.email_verified,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct GitHubIdentity {
    id: u64,
    login: String,
    #[serde(skip)]
    emails: Vec<GitHubEmail>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

pub(crate) fn map_github_identity(
    identity: GitHubIdentity,
) -> Result<VerifiedFederatedClaims, AuthError> {
    if identity.id == 0
        || identity.login.is_empty()
        || identity.login.len() > 255
        || identity.login.chars().any(char::is_control)
    {
        return Err(AuthError::new(
            ErrorCode::TokenInvalid,
            "provider identity response is invalid",
            false,
        ));
    }
    let email = identity
        .emails
        .into_iter()
        .find(|candidate| candidate.primary && candidate.verified)
        .map(|candidate| candidate.email);
    Ok(VerifiedFederatedClaims {
        provider_id: "github".to_owned(),
        issuer: "https://github.com".to_owned(),
        subject: identity.id.to_string(),
        email_verified: email.is_some(),
        email,
    })
}

pub(crate) fn invalid_provider_response() -> AuthError {
    AuthError::new(
        ErrorCode::TokenInvalid,
        "provider authentication response is invalid",
        false,
    )
}

pub(crate) fn dependency_unavailable() -> AuthError {
    AuthError::new(
        ErrorCode::DependencyUnavailable,
        "identity provider is temporarily unavailable",
        true,
    )
}

pub(crate) fn validate_redirect_uri(value: &str) -> Result<Url, AuthError> {
    let url = Url::parse(value).map_err(|_| AuthError::invalid_input())?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
    {
        return Err(AuthError::invalid_input());
    }
    Ok(url)
}

pub(crate) fn validate_pkce_verifier(value: &SecretString) -> Result<(), AuthError> {
    let value = value.expose_secret();
    if !(43..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(AuthError::invalid_input());
    }
    Ok(())
}

pub(crate) fn validate_opaque_flow_value(value: &SecretString) -> Result<(), AuthError> {
    let value = value.expose_secret();
    if !(32..=512).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(AuthError::invalid_input());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_profiles_use_durable_subjects_instead_of_human_identifiers() -> Result<(), AuthError>
    {
        let google = map_oidc_claims(OidcClaims {
            provider_id: "google".to_owned(),
            issuer: "https://accounts.google.com".to_owned(),
            subject: "109876543210987654321".to_owned(),
            email: Some("old@example.com".to_owned()),
            email_verified: true,
        })?;
        assert_eq!(google.subject, "109876543210987654321");

        let github = map_github_identity(GitHubIdentity {
            id: 42,
            login: "renameable-login".to_owned(),
            emails: vec![GitHubEmail {
                email: "owner@example.com".to_owned(),
                primary: true,
                verified: true,
            }],
        })?;
        assert_eq!(github.subject, "42");
        assert_ne!(github.subject, "renameable-login");
        assert!(github.email_verified);
        Ok(())
    }

    #[test]
    fn github_ignores_unverified_and_non_primary_emails() -> Result<(), AuthError> {
        let claims = map_github_identity(GitHubIdentity {
            id: 7,
            login: "octo".to_owned(),
            emails: vec![
                GitHubEmail {
                    email: "unverified@example.com".to_owned(),
                    primary: true,
                    verified: false,
                },
                GitHubEmail {
                    email: "secondary@example.com".to_owned(),
                    primary: false,
                    verified: true,
                },
            ],
        })?;
        assert_eq!(claims.email, None);
        assert!(!claims.email_verified);
        Ok(())
    }

    #[test]
    fn malformed_pkce_verifiers_fail_without_panicking() -> Result<(), AuthError> {
        let provider = GitHubProvider::new(GitHubProviderConfig::new(
            "client-id",
            SecretString::new("client-secret"),
            "https://app.example.com/auth/github/callback",
            "sdk-auth-tests",
        )?)?;
        let error = provider
            .authorization_url(ProviderAuthorizationRequest {
                state: SecretString::new("state-state-state-state-state-state-state-state"),
                nonce: SecretString::new("nonce"),
                pkce_verifier: SecretString::new("short"),
            })
            .err()
            .ok_or_else(AuthError::storage_unavailable)?;
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        Ok(())
    }

    #[test]
    fn github_authorization_uses_state_and_pkce_s256_without_leaking_verifier()
    -> Result<(), AuthError> {
        let provider = GitHubProvider::new(GitHubProviderConfig::new(
            "client-id",
            SecretString::new("client-secret"),
            "https://app.example.com/auth/github/callback",
            "sdk-auth-tests",
        )?)?;
        let state = "state-state-state-state-state-state-state-state";
        let verifier = "verifier-verifier-verifier-verifier-verifier-1234";
        let url = provider.authorization_url(ProviderAuthorizationRequest {
            state: SecretString::new(state),
            nonce: SecretString::new("nonce-nonce-nonce-nonce-nonce-nonce-12"),
            pkce_verifier: SecretString::new(verifier),
        })?;
        let parameters = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            parameters.get("state").map(|value| value.as_ref()),
            Some(state)
        );
        assert_eq!(
            parameters
                .get("code_challenge_method")
                .map(|value| value.as_ref()),
            Some("S256")
        );
        assert!(parameters.contains_key("code_challenge"));
        assert!(!url.as_str().contains(verifier));
        assert!(!url.as_str().contains("client-secret"));
        Ok(())
    }
}
