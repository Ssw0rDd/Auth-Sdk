//! Portable native OAuth/OIDC providers for trusted Node.js servers.
//!
//! This binding deliberately excludes WebAuthn and native OpenSSL. Provider
//! HTTP uses Rustls through `sdk-auth-oauth`.

use std::sync::Arc;

use napi::{Error, Result, Status};
use napi_derive::napi;
use sdk_auth_core::VerifiedFederatedClaims;
use sdk_auth_error::AuthError;
use sdk_auth_oauth::{
    GitHubProvider, GitHubProviderConfig, OidcProvider, OidcProviderConfig,
    ProviderAuthorizationRequest, ProviderCodeExchange,
};
use sdk_auth_types::SecretString;

/// Claims returned only after the native provider adapter verifies its protocol.
#[napi(object)]
pub struct NodeVerifiedFederatedClaims {
    /// Stable provider configuration key.
    pub provider_id: String,
    /// Exact verified issuer.
    pub issuer: String,
    /// Durable provider subject; never an email or username.
    pub subject: String,
    /// Optional provider email attribute.
    pub email: Option<String>,
    /// Whether the provider verified ownership of the email attribute.
    pub email_verified: bool,
}

/// Native OpenID Connect adapter for a trusted Node.js server.
#[napi]
pub struct NodeOidcProvider {
    inner: Arc<OidcProvider>,
}

#[napi]
impl NodeOidcProvider {
    /// Discovers Google's metadata and JWKS with strict issuer validation.
    #[napi(factory)]
    pub async fn google(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> Result<Self> {
        discover_oidc(
            OidcProviderConfig::google(client_id, SecretString::new(client_secret), redirect_uri)
                .map_err(node_error)?,
        )
        .await
    }

    /// Discovers the canonical Microsoft personal-account (Hotmail) issuer.
    #[napi(factory)]
    pub async fn microsoft_consumers(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> Result<Self> {
        discover_oidc(
            OidcProviderConfig::microsoft_consumers(
                client_id,
                SecretString::new(client_secret),
                redirect_uri,
            )
            .map_err(node_error)?,
        )
        .await
    }

    /// Discovers one tenant-pinned Microsoft Entra issuer.
    #[napi(factory)]
    pub async fn microsoft_tenant(
        tenant_id: String,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> Result<Self> {
        discover_oidc(
            OidcProviderConfig::microsoft_tenant(
                &tenant_id,
                client_id,
                SecretString::new(client_secret),
                redirect_uri,
            )
            .map_err(node_error)?,
        )
        .await
    }

    /// Discovers a host-approved custom HTTPS OIDC issuer.
    #[napi(factory)]
    pub async fn custom(
        provider_id: String,
        issuer: String,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        scopes: Vec<String>,
    ) -> Result<Self> {
        discover_oidc(
            OidcProviderConfig::new(
                provider_id,
                issuer,
                client_id,
                SecretString::new(client_secret),
                redirect_uri,
                scopes,
            )
            .map_err(node_error)?,
        )
        .await
    }

    /// Builds an authorization URL without exposing the PKCE verifier in it.
    #[napi]
    pub fn authorization_url(
        &self,
        state: String,
        nonce: String,
        pkce_verifier: String,
    ) -> Result<String> {
        authorization_url(self.inner.as_ref(), state, nonce, pkce_verifier)
    }

    /// Exchanges a code and verifies the ID token before returning claims.
    #[napi]
    pub async fn exchange_code(
        &self,
        code: String,
        nonce: String,
        pkce_verifier: String,
    ) -> Result<NodeVerifiedFederatedClaims> {
        exchange_code(self.inner.as_ref(), code, nonce, pkce_verifier).await
    }
}

/// Native GitHub OAuth adapter for a trusted Node.js server.
#[napi]
pub struct NodeGitHubProvider {
    inner: Arc<GitHubProvider>,
}

#[napi]
impl NodeGitHubProvider {
    /// Creates the redirect-disabled GitHub adapter.
    #[napi(constructor)]
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        user_agent: String,
    ) -> Result<Self> {
        let config = GitHubProviderConfig::new(
            client_id,
            SecretString::new(client_secret),
            redirect_uri,
            user_agent,
        )
        .map_err(node_error)?;
        GitHubProvider::new(config)
            .map(|inner| Self {
                inner: Arc::new(inner),
            })
            .map_err(node_error)
    }

    /// Builds a GitHub authorization URL with PKCE S256.
    #[napi]
    pub fn authorization_url(
        &self,
        state: String,
        nonce: String,
        pkce_verifier: String,
    ) -> Result<String> {
        authorization_url(self.inner.as_ref(), state, nonce, pkce_verifier)
    }

    /// Exchanges a code, calls GitHub `/user`, and returns the numeric subject.
    #[napi]
    pub async fn exchange_code(
        &self,
        code: String,
        nonce: String,
        pkce_verifier: String,
    ) -> Result<NodeVerifiedFederatedClaims> {
        exchange_code(self.inner.as_ref(), code, nonce, pkce_verifier).await
    }
}

async fn discover_oidc(config: OidcProviderConfig) -> Result<NodeOidcProvider> {
    OidcProvider::discover(config)
        .await
        .map(|inner| NodeOidcProvider {
            inner: Arc::new(inner),
        })
        .map_err(node_error)
}

fn authorization_url<P>(
    provider: &P,
    state: String,
    nonce: String,
    pkce_verifier: String,
) -> Result<String>
where
    P: sdk_auth_oauth::ProviderAdapter,
{
    provider
        .authorization_url(ProviderAuthorizationRequest {
            state: SecretString::new(state),
            nonce: SecretString::new(nonce),
            pkce_verifier: SecretString::new(pkce_verifier),
        })
        .map(|url| url.to_string())
        .map_err(node_error)
}

async fn exchange_code<P>(
    provider: &P,
    code: String,
    nonce: String,
    pkce_verifier: String,
) -> Result<NodeVerifiedFederatedClaims>
where
    P: sdk_auth_oauth::ProviderAdapter,
{
    provider
        .exchange_code(ProviderCodeExchange {
            code: SecretString::new(code),
            nonce: SecretString::new(nonce),
            pkce_verifier: SecretString::new(pkce_verifier),
        })
        .await
        .map(verified_claims_result)
        .map_err(node_error)
}

fn verified_claims_result(claims: VerifiedFederatedClaims) -> NodeVerifiedFederatedClaims {
    NodeVerifiedFederatedClaims {
        provider_id: claims.provider_id,
        issuer: claims.issuer,
        subject: claims.subject,
        email: claims.email,
        email_verified: claims.email_verified,
    }
}

fn node_error(error: AuthError) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("{}:{}", error.code().as_str(), error.message()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_projection_preserves_durable_identity_fields() {
        let projected = verified_claims_result(VerifiedFederatedClaims {
            provider_id: "github".to_owned(),
            issuer: "https://github.com".to_owned(),
            subject: "42".to_owned(),
            email: None,
            email_verified: false,
        });
        assert_eq!(projected.subject, "42");
        assert_eq!(projected.email, None);
    }
}
