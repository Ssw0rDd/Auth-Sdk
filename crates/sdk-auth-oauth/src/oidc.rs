use std::time::Duration;

use async_trait::async_trait;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse as _, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse as _,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest,
};
use sdk_auth_core::VerifiedFederatedClaims;
use sdk_auth_error::AuthError;
use sdk_auth_types::SecretString;
use url::Url;

use crate::{
    OidcClaims, ProviderAdapter, ProviderAuthorizationRequest, ProviderCodeExchange,
    dependency_unavailable, invalid_provider_response, map_oidc_claims, validate_opaque_flow_value,
    validate_pkce_verifier, validate_redirect_uri,
};

/// Validated OIDC relying-party configuration for one provider and redirect URI.
#[derive(Debug)]
pub struct OidcProviderConfig {
    provider_id: String,
    issuer: String,
    client_id: String,
    client_secret: SecretString,
    redirect_uri: String,
    scopes: Vec<String>,
}

impl OidcProviderConfig {
    /// Creates a provider-specific OIDC configuration.
    pub fn new(
        provider_id: impl Into<String>,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: impl Into<String>,
        scopes: Vec<String>,
    ) -> Result<Self, AuthError> {
        let provider_id = provider_id.into();
        let issuer = issuer.into();
        let client_id = client_id.into();
        let redirect_uri = redirect_uri.into();
        validate_identifier(&provider_id, 64)?;
        validate_identifier(&client_id, 512)?;
        if client_secret.is_empty() {
            return Err(AuthError::invalid_input());
        }
        validate_issuer(&issuer)?;
        validate_redirect_uri(&redirect_uri)?;
        if scopes.len() > 32
            || scopes.iter().any(|scope| {
                scope.is_empty() || scope.len() > 128 || scope.chars().any(char::is_control)
            })
        {
            return Err(AuthError::invalid_input());
        }
        Ok(Self {
            provider_id,
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            scopes,
        })
    }

    /// Creates the canonical Google OpenID Connect profile.
    pub fn google(
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: impl Into<String>,
    ) -> Result<Self, AuthError> {
        Self::new(
            "google",
            "https://accounts.google.com",
            client_id,
            client_secret,
            redirect_uri,
            vec!["email".to_owned(), "profile".to_owned()],
        )
    }

    /// Creates the Microsoft consumer profile used for personal/Hotmail accounts.
    ///
    /// Microsoft publishes the fixed consumer-tenant UUID as the canonical
    /// issuer, so strict discovery must use that value instead of its
    /// human-friendly `consumers` authority alias.
    pub fn microsoft_consumers(
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: impl Into<String>,
    ) -> Result<Self, AuthError> {
        Self::new(
            "microsoft",
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
            client_id,
            client_secret,
            redirect_uri,
            vec!["email".to_owned(), "profile".to_owned()],
        )
    }

    /// Creates a Microsoft profile pinned to one Entra tenant identifier.
    pub fn microsoft_tenant(
        tenant_id: &str,
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: impl Into<String>,
    ) -> Result<Self, AuthError> {
        if tenant_id.len() != 36
            || !tenant_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err(AuthError::invalid_input());
        }
        Self::new(
            "microsoft",
            format!("https://login.microsoftonline.com/{tenant_id}/v2.0"),
            client_id,
            client_secret,
            redirect_uri,
            vec!["email".to_owned(), "profile".to_owned()],
        )
    }
}

/// OIDC adapter backed by discovered metadata and a redirect-disabled Rustls client.
pub struct OidcProvider {
    config: OidcProviderConfig,
    metadata: CoreProviderMetadata,
    http: reqwest::Client,
}

impl OidcProvider {
    /// Discovers and validates provider metadata before accepting login traffic.
    pub async fn discover(config: OidcProviderConfig) -> Result<Self, AuthError> {
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| dependency_unavailable())?;
        let issuer =
            IssuerUrl::new(config.issuer.clone()).map_err(|_| AuthError::invalid_input())?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|_| dependency_unavailable())?;
        Ok(Self {
            config,
            metadata,
            http,
        })
    }
}

#[async_trait]
impl ProviderAdapter for OidcProvider {
    fn provider_id(&self) -> &str {
        &self.config.provider_id
    }

    fn authorization_url(&self, request: ProviderAuthorizationRequest) -> Result<Url, AuthError> {
        validate_opaque_flow_value(&request.state)?;
        validate_opaque_flow_value(&request.nonce)?;
        validate_pkce_verifier(&request.pkce_verifier)?;
        let client = CoreClient::from_provider_metadata(
            self.metadata.clone(),
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(
                self.config.client_secret.expose_secret().to_owned(),
            )),
        )
        .set_redirect_uri(
            RedirectUrl::new(self.config.redirect_uri.clone())
                .map_err(|_| AuthError::invalid_input())?,
        );
        let verifier = PkceCodeVerifier::new(request.pkce_verifier.expose_secret().to_owned());
        let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
        let state = request.state.expose_secret().to_owned();
        let nonce = request.nonce.expose_secret().to_owned();
        let mut authorization = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || CsrfToken::new(state),
                move || Nonce::new(nonce),
            )
            .set_pkce_challenge(challenge);
        for scope in &self.config.scopes {
            authorization = authorization.add_scope(Scope::new(scope.clone()));
        }
        let (url, _, _) = authorization.url();
        Ok(url)
    }

    async fn exchange_code(
        &self,
        request: ProviderCodeExchange,
    ) -> Result<VerifiedFederatedClaims, AuthError> {
        if request.code.is_empty() {
            return Err(invalid_provider_response());
        }
        validate_opaque_flow_value(&request.nonce).map_err(|_| invalid_provider_response())?;
        validate_pkce_verifier(&request.pkce_verifier).map_err(|_| invalid_provider_response())?;
        let client = CoreClient::from_provider_metadata(
            self.metadata.clone(),
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(
                self.config.client_secret.expose_secret().to_owned(),
            )),
        )
        .set_redirect_uri(
            RedirectUrl::new(self.config.redirect_uri.clone())
                .map_err(|_| AuthError::invalid_input())?,
        );
        let response = client
            .exchange_code(AuthorizationCode::new(
                request.code.expose_secret().to_owned(),
            ))
            .map_err(|_| dependency_unavailable())?
            .set_pkce_verifier(PkceCodeVerifier::new(
                request.pkce_verifier.expose_secret().to_owned(),
            ))
            .request_async(&self.http)
            .await
            .map_err(|_| dependency_unavailable())?;
        let id_token = response.id_token().ok_or_else(invalid_provider_response)?;
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(
                &verifier,
                &Nonce::new(request.nonce.expose_secret().to_owned()),
            )
            .map_err(|_| invalid_provider_response())?;
        if let Some(expected_hash) = claims.access_token_hash() {
            let actual_hash = AccessTokenHash::from_token(
                response.access_token(),
                id_token
                    .signing_alg()
                    .map_err(|_| invalid_provider_response())?,
                id_token
                    .signing_key(&verifier)
                    .map_err(|_| invalid_provider_response())?,
            )
            .map_err(|_| invalid_provider_response())?;
            if actual_hash != *expected_hash {
                return Err(invalid_provider_response());
            }
        }
        map_oidc_claims(OidcClaims {
            provider_id: self.config.provider_id.clone(),
            issuer: claims.issuer().as_str().to_owned(),
            subject: claims.subject().as_str().to_owned(),
            email: claims.email().map(|email| email.as_str().to_owned()),
            email_verified: claims.email_verified().unwrap_or(false),
        })
    }
}

fn validate_identifier(value: &str, max: usize) -> Result<(), AuthError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(AuthError::invalid_input());
    }
    Ok(())
}

fn validate_issuer(value: &str) -> Result<(), AuthError> {
    let issuer = Url::parse(value).map_err(|_| AuthError::invalid_input())?;
    if issuer.scheme() != "https"
        || issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err(AuthError::invalid_input());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsoft_consumers_uses_the_canonical_personal_accounts_issuer() -> Result<(), AuthError> {
        let config = OidcProviderConfig::microsoft_consumers(
            "client-id",
            SecretString::new("client-secret"),
            "https://app.example.com/auth/microsoft/callback",
        )?;
        assert_eq!(
            config.issuer,
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
        );
        Ok(())
    }
}
