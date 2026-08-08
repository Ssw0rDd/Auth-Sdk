//! Cross-adapter passkey orchestration and replay/clone regression contract.

use std::sync::Arc;

use sdk_auth_core::{
    AuthConfig, AuthenticatorManagementProof, BeginPasskeyLoginRequest,
    BeginPasskeyRegistrationRequest, FinishPasskeyLoginRequest, FinishPasskeyRegistrationRequest,
    LoginOutcome, LoginRequest, PasskeyStore, RegisterRequest, RenamePasskeyRequest,
    RevokePasskeyRequest, SdkAuth, SdkStore, VersionedPasskeyCredential,
    WebAuthnAuthenticationResult, WebAuthnCeremony, WebAuthnEngine, WebAuthnProviderMetadata,
    WebAuthnRegistrationResult,
};
use sdk_auth_crypto::{Argon2PasswordEngine, OsTokenGenerator, VaultKey, XChaCha20Vault};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_memory::MemoryAuthStore;
use sdk_auth_sqlite::SqliteAuthStore;
use sdk_auth_types::{DeviceContext, RealmId, SecretBytes, SecretString, UserId};

const PROVIDER: &str = "contract-passkey-provider";

struct ContractWebAuthn;

impl WebAuthnEngine for ContractWebAuthn {
    fn metadata(&self) -> WebAuthnProviderMetadata {
        WebAuthnProviderMetadata {
            provider_id: PROVIDER.to_owned(),
            state_format: 1,
            credential_format: 1,
        }
    }

    fn start_registration(
        &self,
        _realm_id: RealmId,
        _user_id: UserId,
        _user_name: &str,
        _display_name: &str,
        _existing: &[VersionedPasskeyCredential],
    ) -> Result<WebAuthnCeremony, AuthError> {
        Ok(ceremony(b"registration-state"))
    }

    fn finish_registration(
        &self,
        _realm_id: RealmId,
        response_json: &str,
        state: &[u8],
        state_format: u16,
    ) -> Result<WebAuthnRegistrationResult, AuthError> {
        if state != b"registration-state" || state_format != 1 {
            return Err(AuthError::invalid_credentials());
        }
        let id = if response_json.contains("\"id\":2") {
            2
        } else {
            1
        };
        Ok(WebAuthnRegistrationResult {
            credential_id: vec![id; 32],
            provider_id: PROVIDER.to_owned(),
            credential_format: 1,
            credential_blob: vec![id, 0],
        })
    }

    fn start_authentication(
        &self,
        _realm_id: RealmId,
        credentials: &[VersionedPasskeyCredential],
    ) -> Result<WebAuthnCeremony, AuthError> {
        if credentials.is_empty() {
            return Err(AuthError::invalid_credentials());
        }
        Ok(ceremony(b"authentication-state"))
    }

    fn finish_authentication(
        &self,
        _realm_id: RealmId,
        response_json: &str,
        state: &[u8],
        state_format: u16,
        credentials: &[VersionedPasskeyCredential],
    ) -> Result<WebAuthnAuthenticationResult, AuthError> {
        if state != b"authentication-state" || state_format != 1 {
            return Err(AuthError::invalid_credentials());
        }
        let selected = if response_json.contains("\"credential\":2") {
            2
        } else {
            1
        };
        let credential = credentials
            .iter()
            .find(|value| value.credential_id == vec![selected; 32])
            .ok_or_else(AuthError::invalid_credentials)?;
        let counter = if response_json.contains("\"counter\":2") {
            2
        } else {
            1
        };
        Ok(WebAuthnAuthenticationResult {
            credential_id: credential.credential_id.clone(),
            provider_id: PROVIDER.to_owned(),
            credential_format: 1,
            credential_blob: vec![selected, counter],
            signature_counter: u32::from(counter),
            user_verified: true,
            backup_eligible: true,
            backed_up: true,
        })
    }
}

fn ceremony(state: &[u8]) -> WebAuthnCeremony {
    WebAuthnCeremony {
        public_options_json: "{\"publicKey\":{}}".to_owned(),
        provider_id: PROVIDER.to_owned(),
        state_format: 1,
        state: state.to_vec(),
    }
}

fn sdk<T>(store: Arc<T>) -> Result<SdkAuth, AuthError>
where
    T: SdkStore + PasskeyStore + 'static,
{
    SdkAuth::builder()
        .store(Arc::clone(&store))
        .passkey_store(store)
        .webauthn_engine(Arc::new(ContractWebAuthn))
        .password_engine(Arc::new(Argon2PasswordEngine::recommended()?))
        .token_generator(Arc::new(OsTokenGenerator))
        .secret_vault(Arc::new(XChaCha20Vault::new(
            "test-v1",
            vec![VaultKey::new("test-v1", SecretBytes::new(vec![0xA5; 32]))?],
        )?))
        .auth_config(AuthConfig::default())
        .build()
}

async fn verified_password_session(
    sdk: &SdkAuth,
    realm_id: RealmId,
) -> Result<sdk_auth_core::Authentication, AuthError> {
    let registration = sdk
        .identity()
        .register(RegisterRequest {
            realm_id,
            email: "passkey@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
        })
        .await?;
    sdk.identity()
        .verify_email(
            realm_id,
            &SecretString::new(registration.verification.token.expose_secret()),
        )
        .await?;
    let outcome = sdk
        .authentication()
        .login(LoginRequest {
            realm_id,
            email: "passkey@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
            remember_me: false,
            device: DeviceContext::default(),
            trusted_device_token: None,
        })
        .await?;
    match outcome {
        LoginOutcome::Authenticated(value) => Ok(*value),
        LoginOutcome::SecondFactorRequired(_) => Err(AuthError::storage_unavailable()),
        _ => Err(AuthError::storage_unavailable()),
    }
}

pub(crate) async fn exercise<T>(store: Arc<T>) -> Result<(), AuthError>
where
    T: SdkStore + PasskeyStore + 'static,
{
    let sdk = sdk(store)?;
    let passkeys = sdk.passkeys().ok_or_else(AuthError::storage_unavailable)?;
    let realm_id = RealmId::new();
    let password_authentication = verified_password_session(&sdk, realm_id).await?;
    let password_access = password_authentication
        .tokens
        .access_token
        .expose_secret()
        .to_owned();

    let registration = passkeys
        .begin_registration(BeginPasskeyRegistrationRequest {
            realm_id,
            access_token: SecretString::new(password_access.clone()),
            label: "Main passkey".to_owned(),
            proof: AuthenticatorManagementProof::Password {
                password: SecretString::new("correct horse battery staple"),
                second_factor: None,
            },
        })
        .await?;
    let passkey = passkeys
        .finish_registration(FinishPasskeyRegistrationRequest {
            realm_id,
            access_token: SecretString::new(password_access.clone()),
            ceremony_token: SecretString::new(
                registration.ceremony_token.expose_secret().to_owned(),
            ),
            response_json: "{\"id\":1}".to_owned(),
        })
        .await?;
    assert_eq!(passkey.label, "Main passkey");

    let login = passkeys
        .begin_login(BeginPasskeyLoginRequest {
            realm_id,
            email: "passkey@example.com".to_owned(),
            remember_me: false,
            device: DeviceContext::default(),
        })
        .await?;
    let login_token = login.ceremony_token.expose_secret().to_owned();
    let passkey_authentication = passkeys
        .finish_login(FinishPasskeyLoginRequest {
            realm_id,
            ceremony_token: SecretString::new(login_token.clone()),
            response_json: "{\"credential\":1,\"counter\":1}".to_owned(),
        })
        .await?;
    let assurance = passkey_authentication.session.assurance();
    assert!(assurance.phishing_resistant);
    assert!(assurance.user_verified);

    let replay = passkeys
        .finish_login(FinishPasskeyLoginRequest {
            realm_id,
            ceremony_token: SecretString::new(login_token),
            response_json: "{\"credential\":1,\"counter\":2}".to_owned(),
        })
        .await;
    assert_eq!(
        replay.err().map(|error| error.code()),
        Some(ErrorCode::TokenReused)
    );

    let passkey_access = passkey_authentication
        .tokens
        .access_token
        .expose_secret()
        .to_owned();
    let second_registration = passkeys
        .begin_registration(BeginPasskeyRegistrationRequest {
            realm_id,
            access_token: SecretString::new(passkey_access.clone()),
            label: "Backup passkey".to_owned(),
            proof: AuthenticatorManagementProof::CurrentPasskeySession,
        })
        .await?;
    let backup = passkeys
        .finish_registration(FinishPasskeyRegistrationRequest {
            realm_id,
            access_token: SecretString::new(passkey_access.clone()),
            ceremony_token: SecretString::new(
                second_registration
                    .ceremony_token
                    .expose_secret()
                    .to_owned(),
            ),
            response_json: "{\"id\":2}".to_owned(),
        })
        .await?;
    assert!(
        passkeys
            .rename(RenamePasskeyRequest {
                realm_id,
                access_token: SecretString::new(passkey_access.clone()),
                passkey_id: backup.id,
                label: "Renamed backup".to_owned(),
            })
            .await?
    );
    assert!(
        passkeys
            .revoke(RevokePasskeyRequest {
                realm_id,
                access_token: SecretString::new(passkey_access),
                passkey_id: backup.id,
                proof: AuthenticatorManagementProof::CurrentPasskeySession,
            })
            .await?
    );

    let clone_challenge = passkeys
        .begin_login(BeginPasskeyLoginRequest {
            realm_id,
            email: "passkey@example.com".to_owned(),
            remember_me: false,
            device: DeviceContext::default(),
        })
        .await?;
    let clone_result = passkeys
        .finish_login(FinishPasskeyLoginRequest {
            realm_id,
            ceremony_token: SecretString::new(
                clone_challenge.ceremony_token.expose_secret().to_owned(),
            ),
            response_json: "{\"credential\":1,\"counter\":1}".to_owned(),
        })
        .await;
    assert_eq!(
        clone_result.err().map(|error| error.code()),
        Some(ErrorCode::AuthenticatorCompromised)
    );
    let listed = passkeys
        .list(realm_id, &SecretString::new(password_access))
        .await?;
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|value| value.revoked_at.is_some()));
    Ok(())
}

#[tokio::test]
async fn memory_passkey_contract() -> Result<(), AuthError> {
    exercise(Arc::new(MemoryAuthStore::new())).await
}

#[tokio::test]
async fn sqlite_passkey_contract() -> Result<(), AuthError> {
    exercise(Arc::new(SqliteAuthStore::in_memory()?)).await
}
