//! Cross-adapter federation and account-linking regression contract.

use std::sync::Arc;

use sdk_auth_core::{
    AuthConfig, AuthService, AuthStore, BeginFederatedLoginRequest, CompleteFederatedLinkRequest,
    FederatedLinkProof, FederatedLoginOutcome, FederationConfig, FederationService,
    FederationStore, LoginOutcome, LoginRequest, RegisterRequest, VerifiedFederatedClaims,
};
use sdk_auth_crypto::{Argon2PasswordEngine, OsTokenGenerator, VaultKey, XChaCha20Vault};
use sdk_auth_error::AuthError;
use sdk_auth_memory::MemoryAuthStore;
use sdk_auth_sqlite::{SqliteAuthStore, SqliteMigrator};
use sdk_auth_types::{DeviceContext, RealmId, SecretBytes, SecretString};
use tempfile::tempdir;

#[tokio::test]
async fn memory_federation_contract() -> Result<(), AuthError> {
    federation_contract(Arc::new(MemoryAuthStore::default())).await
}

#[tokio::test]
async fn sqlite_federation_contract() -> Result<(), AuthError> {
    let directory = tempdir().map_err(|_| AuthError::storage_unavailable())?;
    let path = directory.path().join("federation.sqlite3");
    SqliteMigrator::migrate(&path)?;
    federation_contract(Arc::new(SqliteAuthStore::open(path)?)).await
}

pub(crate) async fn federation_contract<S>(store: Arc<S>) -> Result<(), AuthError>
where
    S: AuthStore + FederationStore + 'static,
{
    let vault = Arc::new(XChaCha20Vault::new(
        "test-v1",
        vec![VaultKey::new("test-v1", SecretBytes::new(vec![0x5A; 32]))?],
    )?);
    let auth = Arc::new(
        AuthService::builder()
            .store(store.clone())
            .password_engine(Arc::new(Argon2PasswordEngine::recommended()?))
            .token_generator(Arc::new(OsTokenGenerator))
            .secret_vault(vault)
            .config(AuthConfig::default())
            .build()?,
    );
    let federation = FederationService::new(
        auth.clone(),
        store.clone(),
        Arc::new(OsTokenGenerator),
        FederationConfig::default(),
    )?;
    let realm_id = RealmId::new();
    let local = auth
        .register(RegisterRequest {
            realm_id,
            email: "owner@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
        })
        .await?;

    let outcome = federation
        .begin_verified_login(BeginFederatedLoginRequest {
            realm_id,
            device: DeviceContext::default(),
            remember_me: false,
            claims: VerifiedFederatedClaims {
                provider_id: "google".to_owned(),
                issuer: "https://accounts.google.com".to_owned(),
                subject: "109876543210987654321".to_owned(),
                email: Some("owner@example.com".to_owned()),
                email_verified: true,
            },
        })
        .await?;

    let link_token = match outcome {
        FederatedLoginOutcome::LinkRequired(link) => {
            assert_eq!(link.user_id, local.user.id);
            assert!(!link.token.expose_secret().is_empty());
            link.token
        }
        FederatedLoginOutcome::Authenticated(_) | FederatedLoginOutcome::RegistrationRequired => {
            return Err(AuthError::storage_unavailable());
        }
        _ => return Err(AuthError::storage_unavailable()),
    };
    auth.verify_email(
        realm_id,
        &SecretString::new(local.verification.token.expose_secret()),
    )
    .await?;
    let session = match auth
        .login(LoginRequest {
            realm_id,
            email: "owner@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
            device: DeviceContext::default(),
            remember_me: false,
            trusted_device_token: None,
        })
        .await?
    {
        LoginOutcome::Authenticated(authentication) => *authentication,
        _ => return Err(AuthError::storage_unavailable()),
    };
    let linked = federation
        .complete_link(CompleteFederatedLinkRequest {
            realm_id,
            access_token: SecretString::new(session.tokens.access_token.expose_secret()),
            link_token: SecretString::new(link_token.expose_secret()),
            proof: FederatedLinkProof::Password {
                password: SecretString::new("correct horse battery staple"),
                second_factor: None,
            },
        })
        .await?;
    assert_eq!(linked.user_id, local.user.id);

    let repeat = federation
        .begin_verified_login(BeginFederatedLoginRequest {
            realm_id,
            device: DeviceContext::default(),
            remember_me: false,
            claims: VerifiedFederatedClaims {
                provider_id: "google".to_owned(),
                issuer: "https://accounts.google.com".to_owned(),
                subject: "109876543210987654321".to_owned(),
                email: Some("renamed-by-provider@example.com".to_owned()),
                email_verified: true,
            },
        })
        .await?;
    match repeat {
        FederatedLoginOutcome::Authenticated(authentication) => {
            assert_eq!(authentication.user.id, local.user.id);
            auth.validate_access(
                realm_id,
                &SecretString::new(authentication.tokens.access_token.expose_secret()),
            )
            .await?;
        }
        _ => return Err(AuthError::storage_unavailable()),
    }

    let social = federation
        .begin_verified_login(BeginFederatedLoginRequest {
            realm_id,
            device: DeviceContext::default(),
            remember_me: true,
            claims: VerifiedFederatedClaims {
                provider_id: "github".to_owned(),
                issuer: "https://github.com".to_owned(),
                subject: "42424242".to_owned(),
                email: Some("social@example.com".to_owned()),
                email_verified: true,
            },
        })
        .await?;
    let social = match social {
        FederatedLoginOutcome::Authenticated(authentication) => *authentication,
        _ => return Err(AuthError::storage_unavailable()),
    };
    assert!(social.user.email_verified);
    assert_eq!(social.user.email.as_str(), "social@example.com");

    let social_repeat = federation
        .begin_verified_login(BeginFederatedLoginRequest {
            realm_id,
            device: DeviceContext::default(),
            remember_me: false,
            claims: VerifiedFederatedClaims {
                provider_id: "github".to_owned(),
                issuer: "https://github.com".to_owned(),
                subject: "42424242".to_owned(),
                email: Some("provider-renamed@example.com".to_owned()),
                email_verified: true,
            },
        })
        .await?;
    match social_repeat {
        FederatedLoginOutcome::Authenticated(authentication) => {
            assert_eq!(authentication.user.id, social.user.id);
        }
        _ => return Err(AuthError::storage_unavailable()),
    }
    assert!(
        store
            .find_user_by_email(realm_id, "provider-renamed@example.com")
            .await?
            .is_none()
    );
    Ok(())
}
