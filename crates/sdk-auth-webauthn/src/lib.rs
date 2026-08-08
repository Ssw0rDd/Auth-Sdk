//! `webauthn-rs` adapter isolated behind the SDK Core WebAuthn port.
//!
//! The dangerous-sounding upstream state-serialization feature is enabled only
//! so opaque ceremony state can be persisted server-side. Raw state must never
//! be placed in a browser cookie, URL, or client-controlled session.

use std::collections::HashMap;

use sdk_auth_core::{
    VersionedPasskeyCredential, WebAuthnAuthenticationResult, WebAuthnCeremony, WebAuthnEngine,
    WebAuthnProviderMetadata, WebAuthnRegistrationResult,
};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::{RealmId, UserId};
use url::Url;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

const PROVIDER_ID: &str = "webauthn-rs-passkey";
const STATE_FORMAT: u16 = 1;
const CREDENTIAL_FORMAT: u16 = 1;
const MAX_ORIGINS_PER_REALM: usize = 16;

/// Immutable WebAuthn relying-party configuration for one SDK realm.
#[derive(Debug, Clone)]
pub struct WebAuthnRealmConfig {
    /// SDK realm mapped to this relying party.
    pub realm_id: RealmId,
    /// Immutable WebAuthn relying-party identifier.
    pub rp_id: String,
    /// Human-readable relying-party name.
    pub rp_name: String,
    /// Exact HTTPS or Android application origins accepted for ceremonies.
    pub origins: Vec<Url>,
}

impl WebAuthnRealmConfig {
    /// Validates an exact-origin realm configuration.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.rp_id.is_empty()
            || self.rp_id.len() > 253
            || self.rp_name.trim().is_empty()
            || self.rp_name.chars().count() > 100
            || self.origins.is_empty()
            || self.origins.len() > MAX_ORIGINS_PER_REALM
        {
            return Err(misconfigured());
        }
        if !self.origins.iter().any(is_exact_https_origin) {
            return Err(misconfigured());
        }
        for origin in &self.origins {
            if !is_exact_https_origin(origin) && !is_android_app_origin(origin) {
                return Err(misconfigured());
            }
        }
        Ok(())
    }
}

/// Immutable multi-realm `webauthn-rs` provider registry.
pub struct WebAuthnRegistry {
    realms: HashMap<RealmId, Webauthn>,
}

impl WebAuthnRegistry {
    /// Builds exact-origin relying parties. Duplicate realms are rejected.
    pub fn new(configs: Vec<WebAuthnRealmConfig>) -> Result<Self, AuthError> {
        if configs.is_empty() {
            return Err(misconfigured());
        }
        let mut realms = HashMap::with_capacity(configs.len());
        for config in configs {
            config.validate()?;
            let primary = config
                .origins
                .iter()
                .find(|origin| is_exact_https_origin(origin))
                .ok_or_else(misconfigured)?;
            let mut builder = WebauthnBuilder::new(&config.rp_id, primary)
                .map_err(|_| misconfigured())?
                .rp_name(config.rp_name.trim());
            for origin in &config.origins {
                if origin != primary {
                    builder = builder.append_allowed_origin(origin);
                }
            }
            let webauthn = builder.build().map_err(|_| misconfigured())?;
            if realms.insert(config.realm_id, webauthn).is_some() {
                return Err(misconfigured());
            }
        }
        Ok(Self { realms })
    }

    fn realm(&self, realm_id: RealmId) -> Result<&Webauthn, AuthError> {
        self.realms.get(&realm_id).ok_or_else(misconfigured)
    }

    fn decode_credentials(
        credentials: &[VersionedPasskeyCredential],
    ) -> Result<Vec<Passkey>, AuthError> {
        credentials
            .iter()
            .map(|credential| {
                if credential.provider_id != PROVIDER_ID
                    || credential.format_version != CREDENTIAL_FORMAT
                {
                    return Err(incompatible());
                }
                serde_json::from_slice(&credential.blob).map_err(|_| incompatible())
            })
            .collect()
    }
}

fn is_exact_https_origin(origin: &Url) -> bool {
    origin.scheme() == "https"
        && origin.host_str().is_some()
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none()
}

fn is_android_app_origin(origin: &Url) -> bool {
    let Some(fingerprint) = origin.as_str().strip_prefix("android:apk-key-hash:") else {
        return false;
    };
    fingerprint.len() == 43
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

impl WebAuthnEngine for WebAuthnRegistry {
    fn metadata(&self) -> WebAuthnProviderMetadata {
        WebAuthnProviderMetadata {
            provider_id: PROVIDER_ID.to_owned(),
            state_format: STATE_FORMAT,
            credential_format: CREDENTIAL_FORMAT,
        }
    }

    fn start_registration(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        user_name: &str,
        display_name: &str,
        existing: &[VersionedPasskeyCredential],
    ) -> Result<WebAuthnCeremony, AuthError> {
        let existing = Self::decode_credentials(existing)?;
        let exclude = if existing.is_empty() {
            None
        } else {
            Some(
                existing
                    .iter()
                    .map(|credential| credential.cred_id().clone())
                    .collect(),
            )
        };
        let (options, state) = self
            .realm(realm_id)?
            .start_passkey_registration(user_id.as_uuid(), user_name, display_name, exclude)
            .map_err(|_| verification_failed())?;
        Ok(WebAuthnCeremony {
            public_options_json: serde_json::to_string(&options).map_err(|_| internal())?,
            provider_id: PROVIDER_ID.to_owned(),
            state_format: STATE_FORMAT,
            state: serde_json::to_vec(&state).map_err(|_| internal())?,
        })
    }

    fn finish_registration(
        &self,
        realm_id: RealmId,
        response_json: &str,
        state: &[u8],
        state_format: u16,
    ) -> Result<WebAuthnRegistrationResult, AuthError> {
        if state_format != STATE_FORMAT {
            return Err(incompatible());
        }
        let response: RegisterPublicKeyCredential =
            serde_json::from_str(response_json).map_err(|_| verification_failed())?;
        let state: PasskeyRegistration =
            serde_json::from_slice(state).map_err(|_| incompatible())?;
        let passkey = self
            .realm(realm_id)?
            .finish_passkey_registration(&response, &state)
            .map_err(|_| verification_failed())?;
        let credential_id = passkey.cred_id().as_ref().to_vec();
        Ok(WebAuthnRegistrationResult {
            credential_id,
            provider_id: PROVIDER_ID.to_owned(),
            credential_format: CREDENTIAL_FORMAT,
            credential_blob: serde_json::to_vec(&passkey).map_err(|_| internal())?,
        })
    }

    fn start_authentication(
        &self,
        realm_id: RealmId,
        credentials: &[VersionedPasskeyCredential],
    ) -> Result<WebAuthnCeremony, AuthError> {
        let credentials = Self::decode_credentials(credentials)?;
        if credentials.is_empty() {
            return Err(verification_failed());
        }
        let (options, state) = self
            .realm(realm_id)?
            .start_passkey_authentication(&credentials)
            .map_err(|_| verification_failed())?;
        Ok(WebAuthnCeremony {
            public_options_json: serde_json::to_string(&options).map_err(|_| internal())?,
            provider_id: PROVIDER_ID.to_owned(),
            state_format: STATE_FORMAT,
            state: serde_json::to_vec(&state).map_err(|_| internal())?,
        })
    }

    fn finish_authentication(
        &self,
        realm_id: RealmId,
        response_json: &str,
        state: &[u8],
        state_format: u16,
        credentials: &[VersionedPasskeyCredential],
    ) -> Result<WebAuthnAuthenticationResult, AuthError> {
        if state_format != STATE_FORMAT {
            return Err(incompatible());
        }
        let response: PublicKeyCredential =
            serde_json::from_str(response_json).map_err(|_| verification_failed())?;
        let state: PasskeyAuthentication =
            serde_json::from_slice(state).map_err(|_| incompatible())?;
        let result = self
            .realm(realm_id)?
            .finish_passkey_authentication(&response, &state)
            .map_err(|_| verification_failed())?;
        let mut decoded = Self::decode_credentials(credentials)?;
        let Some(passkey) = decoded
            .iter_mut()
            .find(|credential| credential.cred_id() == result.cred_id())
        else {
            return Err(verification_failed());
        };
        if passkey.update_credential(&result).is_none() {
            return Err(verification_failed());
        }
        Ok(WebAuthnAuthenticationResult {
            credential_id: result.cred_id().as_ref().to_vec(),
            provider_id: PROVIDER_ID.to_owned(),
            credential_format: CREDENTIAL_FORMAT,
            credential_blob: serde_json::to_vec(passkey).map_err(|_| internal())?,
            signature_counter: result.counter(),
            user_verified: result.user_verified(),
            backup_eligible: result.backup_eligible(),
            backed_up: result.backup_state(),
        })
    }
}

fn misconfigured() -> AuthError {
    AuthError::new(
        ErrorCode::Misconfigured,
        "WebAuthn relying-party configuration is invalid",
        false,
    )
}

fn incompatible() -> AuthError {
    AuthError::new(
        ErrorCode::Misconfigured,
        "persisted WebAuthn state is incompatible with this provider",
        false,
    )
}

fn verification_failed() -> AuthError {
    AuthError::invalid_credentials()
}

fn internal() -> AuthError {
    AuthError::new(
        ErrorCode::Internal,
        "WebAuthn provider serialization failed",
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_exact_origins_and_starts_registration() -> Result<(), Box<dyn std::error::Error>> {
        let realm_id = RealmId::new();
        let insecure = WebAuthnRealmConfig {
            realm_id,
            rp_id: "example.com".to_owned(),
            rp_name: "Example".to_owned(),
            origins: vec![Url::parse("http://example.com")?],
        };
        assert_eq!(
            insecure.validate().err().map(|error| error.code()),
            Some(ErrorCode::Misconfigured)
        );

        let secure = WebAuthnRealmConfig {
            realm_id,
            rp_id: "example.com".to_owned(),
            rp_name: "Example".to_owned(),
            origins: vec![
                Url::parse("https://login.example.com")?,
                Url::parse(&format!("android:apk-key-hash:{}", "A".repeat(43)))?,
            ],
        };
        let registry = WebAuthnRegistry::new(vec![secure.clone()])?;
        let challenge = registry.start_registration(
            realm_id,
            UserId::new(),
            "user@example.com",
            "User",
            &[],
        )?;
        assert!(!challenge.public_options_json.is_empty());
        assert!(!challenge.state.is_empty());
        assert!(WebAuthnRegistry::new(vec![secure.clone(), secure]).is_err());
        Ok(())
    }
}
