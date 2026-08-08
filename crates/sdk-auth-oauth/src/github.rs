use std::time::Duration;

use async_trait::async_trait;
use openidconnect::{PkceCodeChallenge, PkceCodeVerifier, reqwest};
use sdk_auth_core::VerifiedFederatedClaims;
use sdk_auth_error::AuthError;
use sdk_auth_types::SecretString;
use serde::Deserialize;
use url::Url;

use crate::{
    GitHubIdentity, ProviderAdapter, ProviderAuthorizationRequest, ProviderCodeExchange,
    dependency_unavailable, invalid_provider_response, map_github_identity,
    validate_opaque_flow_value, validate_pkce_verifier, validate_redirect_uri,
};

const AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const EMAILS_URL: &str = "https://api.github.com/user/emails";
const MAX_PROVIDER_BODY_BYTES: usize = 256 * 1024;

/// GitHub OAuth application configuration with a fixed callback.
#[derive(Debug)]
pub struct GitHubProviderConfig {
    client_id: String,
    client_secret: SecretString,
    redirect_uri: String,
    user_agent: String,
}

impl GitHubProviderConfig {
    /// Creates a GitHub sign-in configuration.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: impl Into<String>,
        user_agent: impl Into<String>,
    ) -> Result<Self, AuthError> {
        let client_id = client_id.into();
        let redirect_uri = redirect_uri.into();
        let user_agent = user_agent.into();
        if client_id.is_empty()
            || client_id.len() > 512
            || client_secret.is_empty()
            || user_agent.is_empty()
            || user_agent.len() > 256
            || user_agent.chars().any(char::is_control)
        {
            return Err(AuthError::invalid_input());
        }
        validate_redirect_uri(&redirect_uri)?;
        Ok(Self {
            client_id,
            client_secret,
            redirect_uri,
            user_agent,
        })
    }
}

/// GitHub OAuth adapter that revalidates `/user` after every code exchange.
pub struct GitHubProvider {
    config: GitHubProviderConfig,
    http: reqwest::Client,
}

impl GitHubProvider {
    /// Builds a redirect-disabled Rustls HTTP client.
    pub fn new(config: GitHubProviderConfig) -> Result<Self, AuthError> {
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| dependency_unavailable())?;
        Ok(Self { config, http })
    }
}

#[async_trait]
impl ProviderAdapter for GitHubProvider {
    fn provider_id(&self) -> &str {
        "github"
    }

    fn authorization_url(&self, request: ProviderAuthorizationRequest) -> Result<Url, AuthError> {
        validate_opaque_flow_value(&request.state)?;
        validate_pkce_verifier(&request.pkce_verifier)?;
        let verifier = PkceCodeVerifier::new(request.pkce_verifier.expose_secret().to_owned());
        let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
        let mut url = Url::parse(AUTHORIZE_URL).map_err(|_| AuthError::invalid_input())?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", "read:user user:email")
            .append_pair("state", request.state.expose_secret())
            .append_pair("code_challenge", challenge.as_str())
            .append_pair("code_challenge_method", "S256");
        Ok(url)
    }

    async fn exchange_code(
        &self,
        request: ProviderCodeExchange,
    ) -> Result<VerifiedFederatedClaims, AuthError> {
        if request.code.is_empty() {
            return Err(invalid_provider_response());
        }
        validate_pkce_verifier(&request.pkce_verifier).map_err(|_| invalid_provider_response())?;
        let mut token_response = self
            .http
            .post(TOKEN_URL)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.expose_secret()),
                ("code", request.code.expose_secret()),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("code_verifier", request.pkce_verifier.expose_secret()),
            ])
            .send()
            .await
            .map_err(|_| dependency_unavailable())?;
        if !token_response.status().is_success() {
            return Err(invalid_provider_response());
        }
        let token: GitHubTokenResponse = read_json_limited(&mut token_response).await?;
        if !token.token_type.eq_ignore_ascii_case("bearer") || token.access_token.is_empty() {
            return Err(invalid_provider_response());
        }
        let access_token = SecretString::new(token.access_token);
        let mut user_response = self
            .http
            .get(USER_URL)
            .bearer_auth(access_token.expose_secret())
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::USER_AGENT, &self.config.user_agent)
            .header("X-GitHub-Api-Version", "2026-03-10")
            .send()
            .await
            .map_err(|_| dependency_unavailable())?;
        if !user_response.status().is_success() {
            return Err(invalid_provider_response());
        }
        let mut identity: GitHubIdentity = read_json_limited(&mut user_response).await?;
        let mut email_response = self
            .http
            .get(EMAILS_URL)
            .bearer_auth(access_token.expose_secret())
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::USER_AGENT, &self.config.user_agent)
            .header("X-GitHub-Api-Version", "2026-03-10")
            .send()
            .await
            .map_err(|_| dependency_unavailable())?;
        if email_response.status().is_success() {
            identity.emails = read_json_limited(&mut email_response).await?;
        }
        map_github_identity(identity)
    }
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
}

async fn read_json_limited<T>(response: &mut reqwest::Response) -> Result<T, AuthError>
where
    T: for<'de> Deserialize<'de>,
{
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_BODY_BYTES as u64)
    {
        return Err(invalid_provider_response());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| dependency_unavailable())?
    {
        if body.len().saturating_add(chunk.len()) > MAX_PROVIDER_BODY_BYTES {
            return Err(invalid_provider_response());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| invalid_provider_response())
}
