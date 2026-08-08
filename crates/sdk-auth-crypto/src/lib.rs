//! Cryptographic primitives with opinionated safe defaults.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString},
};
use std::{collections::HashMap, fmt, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, Payload},
};
use rand_core::{OsRng, RngCore};
use sdk_auth_error::AuthError;
use sdk_auth_types::{ApiKeyId, OpaqueToken, SecretBytes, SecretString};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Persistable digest of a high-entropy opaque token.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    /// Reconstructs a digest read from trusted storage.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AuthError> {
        let value: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AuthError::storage_unavailable())?;
        Ok(Self(value))
    }

    /// Returns the fixed-width digest for persistence.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compares digests without early exit.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl std::fmt::Debug for TokenDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TokenDigest([REDACTED])")
    }
}

/// Password hashing and verification boundary used by the core.
pub trait PasswordEngine: Send + Sync {
    /// Hashes a validated plaintext password into a PHC string.
    fn hash(&self, password: &SecretString) -> Result<String, AuthError>;

    /// Verifies a plaintext password against a stored PHC string.
    fn verify(&self, password: &SecretString, encoded: &str) -> Result<bool, AuthError>;

    /// Performs equivalent work when no account exists.
    fn fake_verify(&self, password: &SecretString) -> Result<(), AuthError>;

    /// Indicates whether a stored PHC string should be upgraded.
    fn needs_rehash(&self, encoded: &str) -> bool;
}

/// Cryptographically secure opaque-token generator.
pub trait TokenGenerator: Send + Sync {
    /// Generates a 256-bit bearer token.
    fn generate(&self) -> Result<OpaqueToken, AuthError>;
}

/// Authenticated-encryption algorithm recorded with every sealed secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// XChaCha20-Poly1305 with a 192-bit nonce.
    XChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// Stable persistence representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "xchacha20_poly1305",
        }
    }

    /// Parses an algorithm identifier read from trusted storage.
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        match value {
            "xchacha20_poly1305" => Ok(Self::XChaCha20Poly1305),
            _ => Err(AuthError::storage_unavailable()),
        }
    }
}

/// Immutable metadata describing one composed cryptographic provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoProviderMetadata {
    /// Stable provider identifier for diagnostics and policy checks.
    pub provider_id: &'static str,
    /// Highest sealed-secret format emitted by this provider.
    pub sealed_secret_format: u16,
    /// Whether this exact provider and environment have a validated FIPS claim.
    pub fips_validated: bool,
}

/// Versioned composition boundary for cryptographic capabilities used by the core.
pub trait CryptoProvider: Send + Sync {
    /// Returns immutable provider metadata.
    fn metadata(&self) -> CryptoProviderMetadata;

    /// Returns the password-hashing capability.
    fn password_engine(&self) -> Arc<dyn PasswordEngine>;

    /// Returns the CSPRNG-backed token capability.
    fn token_generator(&self) -> Arc<dyn TokenGenerator>;

    /// Returns the authenticated secret-vault capability.
    fn secret_vault(&self) -> Arc<dyn SecretVault>;
}

/// Software provider that composes independently testable capabilities.
pub struct SoftwareCryptoProvider {
    password_engine: Arc<dyn PasswordEngine>,
    token_generator: Arc<dyn TokenGenerator>,
    secret_vault: Arc<dyn SecretVault>,
}

impl SoftwareCryptoProvider {
    /// Creates the default non-FIPS software provider.
    #[must_use]
    pub fn new(
        password_engine: Arc<dyn PasswordEngine>,
        token_generator: Arc<dyn TokenGenerator>,
        secret_vault: Arc<dyn SecretVault>,
    ) -> Self {
        Self {
            password_engine,
            token_generator,
            secret_vault,
        }
    }
}

impl CryptoProvider for SoftwareCryptoProvider {
    fn metadata(&self) -> CryptoProviderMetadata {
        CryptoProviderMetadata {
            provider_id: "sdk-auth-software-v1",
            sealed_secret_format: 1,
            fips_validated: false,
        }
    }

    fn password_engine(&self) -> Arc<dyn PasswordEngine> {
        Arc::clone(&self.password_engine)
    }

    fn token_generator(&self) -> Arc<dyn TokenGenerator> {
        Arc::clone(&self.token_generator)
    }

    fn secret_vault(&self) -> Arc<dyn SecretVault> {
        Arc::clone(&self.secret_vault)
    }
}

/// Versioned authenticated ciphertext suitable for persistence.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedSecret {
    format_version: u16,
    algorithm: AeadAlgorithm,
    key_id: String,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl SealedSecret {
    /// Reconstructs a sealed value read from trusted storage.
    pub fn from_parts(
        key_id: String,
        nonce: &[u8],
        ciphertext: Vec<u8>,
    ) -> Result<Self, AuthError> {
        Self::from_versioned_parts(
            1,
            AeadAlgorithm::XChaCha20Poly1305,
            key_id,
            nonce,
            ciphertext,
        )
    }

    /// Reconstructs a versioned sealed value read from trusted storage.
    pub fn from_versioned_parts(
        format_version: u16,
        algorithm: AeadAlgorithm,
        key_id: String,
        nonce: &[u8],
        ciphertext: Vec<u8>,
    ) -> Result<Self, AuthError> {
        if format_version != 1 {
            return Err(AuthError::storage_unavailable());
        }
        validate_key_id(&key_id)?;
        let nonce = nonce
            .try_into()
            .map_err(|_| AuthError::storage_unavailable())?;
        if ciphertext.len() < 16 {
            return Err(AuthError::storage_unavailable());
        }
        Ok(Self {
            format_version,
            algorithm,
            key_id,
            nonce,
            ciphertext,
        })
    }

    /// Returns the stable sealed-secret format version.
    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    /// Returns the authenticated-encryption algorithm identifier.
    #[must_use]
    pub const fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// Returns the key identifier required to open the value.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the extended nonce for persistence.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Returns the authenticated ciphertext for persistence.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedSecret")
            .field("format_version", &self.format_version)
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

/// One host-provided versioned vault key.
pub struct VaultKey {
    id: String,
    material: SecretBytes,
}

impl VaultKey {
    /// Validates a key identifier and 256-bit key.
    pub fn new(id: impl Into<String>, material: SecretBytes) -> Result<Self, AuthError> {
        let id = id.into();
        validate_key_id(&id)?;
        if material.len() != 32 {
            return Err(AuthError::new(
                sdk_auth_error::ErrorCode::Misconfigured,
                "vault keys must contain exactly 32 bytes",
                false,
            ));
        }
        Ok(Self { id, material })
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultKey")
            .field("id", &self.id)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

/// Authenticated secret-protection boundary injected into the core.
pub trait SecretVault: Send + Sync {
    /// Encrypts bytes with the active key and supplied associated data.
    fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<SealedSecret, AuthError>;

    /// Authenticates and decrypts a persisted secret.
    fn open(&self, sealed: &SealedSecret, associated_data: &[u8])
    -> Result<SecretBytes, AuthError>;

    /// Returns the identifier used for new ciphertexts.
    fn active_key_id(&self) -> &str;
}

/// XChaCha20-Poly1305 keyring with one active encryption key.
pub struct XChaCha20Vault {
    active_key_id: String,
    keys: HashMap<String, SecretBytes>,
}

impl XChaCha20Vault {
    /// Builds a vault, rejecting duplicates and missing active keys.
    pub fn new(active_key_id: impl Into<String>, keys: Vec<VaultKey>) -> Result<Self, AuthError> {
        let active_key_id = active_key_id.into();
        validate_key_id(&active_key_id)?;
        let mut keyring = HashMap::with_capacity(keys.len());
        for key in keys {
            if keyring.insert(key.id, key.material).is_some() {
                return Err(AuthError::new(
                    sdk_auth_error::ErrorCode::Misconfigured,
                    "vault key identifiers must be unique",
                    false,
                ));
            }
        }
        if !keyring.contains_key(&active_key_id) {
            return Err(AuthError::new(
                sdk_auth_error::ErrorCode::Misconfigured,
                "the active vault key is missing",
                false,
            ));
        }
        Ok(Self {
            active_key_id,
            keys: keyring,
        })
    }
}

impl SecretVault for XChaCha20Vault {
    fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<SealedSecret, AuthError> {
        if plaintext.is_empty() {
            return Err(AuthError::crypto_failure());
        }
        let material = self
            .keys
            .get(&self.active_key_id)
            .ok_or_else(AuthError::crypto_failure)?;
        let cipher = XChaCha20Poly1305::new_from_slice(material.expose_secret())
            .map_err(|_| AuthError::crypto_failure())?;
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let nonce_value =
            XNonce::try_from(nonce.as_slice()).map_err(|_| AuthError::crypto_failure())?;
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| AuthError::crypto_failure())?;
        Ok(SealedSecret {
            format_version: 1,
            algorithm: AeadAlgorithm::XChaCha20Poly1305,
            key_id: self.active_key_id.clone(),
            nonce,
            ciphertext,
        })
    }

    fn open(
        &self,
        sealed: &SealedSecret,
        associated_data: &[u8],
    ) -> Result<SecretBytes, AuthError> {
        if sealed.format_version != 1 || sealed.algorithm != AeadAlgorithm::XChaCha20Poly1305 {
            return Err(AuthError::crypto_failure());
        }
        let material = self
            .keys
            .get(sealed.key_id())
            .ok_or_else(AuthError::crypto_failure)?;
        let cipher = XChaCha20Poly1305::new_from_slice(material.expose_secret())
            .map_err(|_| AuthError::crypto_failure())?;
        let nonce =
            XNonce::try_from(sealed.nonce().as_slice()).map_err(|_| AuthError::crypto_failure())?;
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: sealed.ciphertext(),
                    aad: associated_data,
                },
            )
            .map(SecretBytes::new)
            .map_err(|_| AuthError::crypto_failure())
    }

    fn active_key_id(&self) -> &str {
        &self.active_key_id
    }
}

fn validate_key_id(value: &str) -> Result<(), AuthError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AuthError::new(
            sdk_auth_error::ErrorCode::Misconfigured,
            "vault key identifier is invalid",
            false,
        ));
    }
    Ok(())
}

/// Argon2id parameters controlled by configuration and recorded in PHC output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Settings {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of iterations.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl Default for Argon2Settings {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

/// Argon2id password engine with a precomputed dummy credential.
pub struct Argon2PasswordEngine {
    settings: Argon2Settings,
    dummy_hash: String,
}

impl Argon2PasswordEngine {
    /// Creates the recommended engine and prepares an enumeration-resistant hash.
    pub fn recommended() -> Result<Self, AuthError> {
        Self::new(Argon2Settings::default())
    }

    /// Creates an engine after enforcing minimum safe parameters.
    pub fn new(settings: Argon2Settings) -> Result<Self, AuthError> {
        if settings.memory_kib < 19_456 || settings.iterations < 2 || settings.parallelism == 0 {
            return Err(AuthError::new(
                sdk_auth_error::ErrorCode::Misconfigured,
                "argon2id parameters are below the supported security floor",
                false,
            ));
        }
        let mut engine = Self {
            settings,
            dummy_hash: String::new(),
        };
        let dummy = SecretString::new("sdk-auth-dummy-password-material");
        engine.dummy_hash = engine.hash_internal(&dummy)?;
        Ok(engine)
    }

    fn argon2(&self) -> Result<Argon2<'static>, AuthError> {
        let params = Params::new(
            self.settings.memory_kib,
            self.settings.iterations,
            self.settings.parallelism,
            None,
        )
        .map_err(|_| AuthError::crypto_failure())?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    fn hash_internal(&self, password: &SecretString) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        self.argon2()?
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| AuthError::crypto_failure())
    }
}

impl PasswordEngine for Argon2PasswordEngine {
    fn hash(&self, password: &SecretString) -> Result<String, AuthError> {
        self.hash_internal(password)
    }

    fn verify(&self, password: &SecretString, encoded: &str) -> Result<bool, AuthError> {
        let parsed = PasswordHash::new(encoded).map_err(|_| AuthError::crypto_failure())?;
        Ok(self
            .argon2()?
            .verify_password(password.expose_secret().as_bytes(), &parsed)
            .is_ok())
    }

    fn fake_verify(&self, password: &SecretString) -> Result<(), AuthError> {
        let _verified = self.verify(password, &self.dummy_hash)?;
        Ok(())
    }

    fn needs_rehash(&self, encoded: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(encoded) else {
            return true;
        };
        let memory = parsed.params.get_decimal("m");
        let iterations = parsed.params.get_decimal("t");
        let parallelism = parsed.params.get_decimal("p");
        memory != Some(self.settings.memory_kib)
            || iterations != Some(self.settings.iterations)
            || parallelism != Some(self.settings.parallelism)
    }
}

/// Operating-system-backed token generator.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsTokenGenerator;

impl TokenGenerator for OsTokenGenerator {
    fn generate(&self) -> Result<OpaqueToken, AuthError> {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        Ok(OpaqueToken::new(encoded))
    }
}

/// Computes a fixed-width BLAKE3 digest of an opaque token.
#[must_use]
pub fn digest_token(token: &OpaqueToken) -> TokenDigest {
    TokenDigest(*blake3::hash(token.expose_secret().as_bytes()).as_bytes())
}

/// Computes a digest directly from trusted token text crossing an FFI boundary.
#[must_use]
pub fn digest_token_text(token: &SecretString) -> TokenDigest {
    TokenDigest(*blake3::hash(token.expose_secret().as_bytes()).as_bytes())
}

/// Newly generated API-key credential and its public identifier.
pub struct GeneratedApiKey {
    /// Public identifier embedded in the credential for indexed lookup.
    pub id: ApiKeyId,
    /// Bearer credential returned exactly once.
    pub credential: OpaqueToken,
    /// Persistable digest of the complete credential.
    pub digest: TokenDigest,
}

impl fmt::Debug for GeneratedApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedApiKey")
            .field("id", &self.id)
            .field("credential", &"[REDACTED]")
            .field("digest", &self.digest)
            .finish()
    }
}

/// Validated API-key lookup material parsed from an untrusted credential.
#[derive(Debug, Clone, Copy)]
pub struct ParsedApiKey {
    /// Public key identifier.
    pub id: ApiKeyId,
    /// Digest compared with the stored digest in constant time.
    pub digest: TokenDigest,
}

/// Generates a secret-scanning-friendly, versioned 256-bit API key.
pub fn generate_api_key(generator: &dyn TokenGenerator) -> Result<GeneratedApiKey, AuthError> {
    let id = ApiKeyId::new();
    let entropy = generator.generate()?;
    let body = format!("ska_v1_{id}_{}", entropy.expose_secret());
    let checksum = checksum(&body);
    let credential = OpaqueToken::new(format!("{body}_{checksum}"));
    let digest = digest_token(&credential);
    Ok(GeneratedApiKey {
        id,
        credential,
        digest,
    })
}

/// Parses an API key without exposing whether its public identifier exists.
pub fn parse_api_key(credential: &SecretString) -> Result<ParsedApiKey, AuthError> {
    let raw = credential.expose_secret();
    let remainder = raw
        .strip_prefix("ska_v1_")
        .ok_or_else(AuthError::invalid_credentials)?;
    let (id, secret_and_checksum) = remainder
        .split_once('_')
        .ok_or_else(AuthError::invalid_credentials)?;
    let (secret, supplied_checksum) = secret_and_checksum
        .rsplit_once('_')
        .ok_or_else(AuthError::invalid_credentials)?;
    if secret.len() != 43
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || supplied_checksum.len() != 8
    {
        return Err(AuthError::invalid_credentials());
    }
    let body = format!("ska_v1_{id}_{secret}");
    if !bool::from(
        checksum(&body)
            .as_bytes()
            .ct_eq(supplied_checksum.as_bytes()),
    ) {
        return Err(AuthError::invalid_credentials());
    }
    Ok(ParsedApiKey {
        id: ApiKeyId::parse(id).map_err(|_| AuthError::invalid_credentials())?,
        digest: digest_token_text(credential),
    })
}

fn checksum(value: &str) -> String {
    let digest = blake3::hash(value.as_bytes());
    let mut encoded = String::with_capacity(8);
    for byte in &digest.as_bytes()[..4] {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip_and_rehash_policy() -> Result<(), AuthError> {
        let engine = Argon2PasswordEngine::recommended()?;
        let password = SecretString::new("a sufficiently long password");
        let encoded = engine.hash(&password)?;
        assert!(engine.verify(&password, &encoded)?);
        assert!(!engine.verify(&SecretString::new("a different long password"), &encoded)?);
        assert!(!engine.needs_rehash(&encoded));
        Ok(())
    }

    #[test]
    fn generated_tokens_are_unique_and_redacted() -> Result<(), AuthError> {
        let first = OsTokenGenerator.generate()?;
        let second = OsTokenGenerator.generate()?;
        assert_ne!(first.expose_secret(), second.expose_secret());
        assert_eq!(
            format!("{first:?}"),
            "OpaqueToken(SecretString([REDACTED]))"
        );
        assert!(!digest_token(&first).constant_time_eq(&digest_token(&second)));
        Ok(())
    }

    #[test]
    fn api_key_format_round_trips_and_rejects_tampering() -> Result<(), AuthError> {
        let generated = generate_api_key(&OsTokenGenerator)?;
        let supplied = SecretString::new(generated.credential.expose_secret());
        let parsed = parse_api_key(&supplied)?;
        assert_eq!(parsed.id, generated.id);
        assert!(parsed.digest.constant_time_eq(&generated.digest));
        let mut tampered = generated.credential.expose_secret().to_owned();
        tampered.push('0');
        assert!(parse_api_key(&SecretString::new(tampered)).is_err());
        assert!(!format!("{generated:?}").contains(generated.credential.expose_secret()));
        Ok(())
    }

    #[test]
    fn rejects_weak_parameters_and_invalid_persisted_data() {
        let weak = Argon2PasswordEngine::new(Argon2Settings {
            memory_kib: 1_024,
            iterations: 1,
            parallelism: 0,
        });
        assert!(weak.is_err());
        assert!(TokenDigest::from_slice(&[0_u8; 31]).is_err());
        let digest = TokenDigest::from_slice(&[7_u8; 32]);
        assert!(digest.is_ok());
        assert!(
            digest
                .as_ref()
                .is_ok_and(|value| value.constant_time_eq(value))
        );
        assert_eq!(
            digest.as_ref().map(|value| format!("{value:?}")).ok(),
            Some("TokenDigest([REDACTED])".to_owned())
        );
    }

    #[test]
    fn fake_verification_and_rehash_detection_are_safe() -> Result<(), AuthError> {
        let engine = Argon2PasswordEngine::recommended()?;
        let password = SecretString::new("a sufficiently long password");
        engine.fake_verify(&password)?;
        assert!(engine.needs_rehash("not-a-phc-string"));
        let weaker = Argon2PasswordEngine::new(Argon2Settings {
            memory_kib: 19_456,
            iterations: 3,
            parallelism: 1,
        })?;
        let encoded = weaker.hash(&password)?;
        assert!(engine.needs_rehash(&encoded));
        assert!(engine.verify(&password, "broken").is_err());
        assert_eq!(
            digest_token_text(&password).as_bytes(),
            blake3::hash(password.expose_secret().as_bytes()).as_bytes()
        );
        Ok(())
    }

    #[test]
    fn vault_authenticates_aad_ciphertext_and_key_version() -> Result<(), AuthError> {
        let old = VaultKey::new("old-v1", SecretBytes::new(vec![0x11; 32]))?;
        let old_vault = XChaCha20Vault::new("old-v1", vec![old])?;
        let sealed = old_vault.seal(b"totp seed material", b"realm|user|factor")?;
        assert_eq!(sealed.format_version(), 1);
        assert_eq!(sealed.algorithm(), AeadAlgorithm::XChaCha20Poly1305);
        assert_eq!(sealed.key_id(), "old-v1");
        assert_eq!(
            old_vault
                .open(&sealed, b"realm|user|factor")?
                .expose_secret(),
            b"totp seed material"
        );
        assert!(old_vault.open(&sealed, b"other realm").is_err());

        let mut ciphertext = sealed.ciphertext().to_vec();
        ciphertext[0] ^= 1;
        let tampered =
            SealedSecret::from_parts(sealed.key_id().to_owned(), sealed.nonce(), ciphertext)?;
        assert!(old_vault.open(&tampered, b"realm|user|factor").is_err());

        let rotated = XChaCha20Vault::new(
            "new-v2",
            vec![
                VaultKey::new("old-v1", SecretBytes::new(vec![0x11; 32]))?,
                VaultKey::new("new-v2", SecretBytes::new(vec![0x22; 32]))?,
            ],
        )?;
        assert_eq!(
            rotated.open(&sealed, b"realm|user|factor")?.expose_secret(),
            b"totp seed material"
        );
        assert_eq!(
            rotated.seal(b"next", b"realm|user|factor")?.key_id(),
            "new-v2"
        );
        let new_only = XChaCha20Vault::new(
            "new-v2",
            vec![VaultKey::new("new-v2", SecretBytes::new(vec![0x22; 32]))?],
        )?;
        assert!(new_only.open(&sealed, b"realm|user|factor").is_err());
        Ok(())
    }

    #[test]
    fn software_provider_is_explicitly_non_fips_and_versioned() -> Result<(), AuthError> {
        let provider = SoftwareCryptoProvider::new(
            Arc::new(Argon2PasswordEngine::recommended()?),
            Arc::new(OsTokenGenerator),
            Arc::new(XChaCha20Vault::new(
                "active-v1",
                vec![VaultKey::new(
                    "active-v1",
                    SecretBytes::new(vec![0x42; 32]),
                )?],
            )?),
        );
        let metadata = provider.metadata();
        assert_eq!(metadata.provider_id, "sdk-auth-software-v1");
        assert_eq!(metadata.sealed_secret_format, 1);
        assert!(!metadata.fips_validated);
        assert_eq!(provider.secret_vault().active_key_id(), "active-v1");
        assert_eq!(
            AeadAlgorithm::XChaCha20Poly1305.as_str(),
            "xchacha20_poly1305"
        );
        assert_eq!(
            AeadAlgorithm::parse("xchacha20_poly1305")?,
            AeadAlgorithm::XChaCha20Poly1305
        );
        assert!(AeadAlgorithm::parse("unknown").is_err());
        assert!(
            SealedSecret::from_versioned_parts(
                2,
                AeadAlgorithm::XChaCha20Poly1305,
                "active-v1".to_owned(),
                &[0; 24],
                vec![0; 16],
            )
            .is_err()
        );
        assert!(provider.password_engine().needs_rehash("invalid"));
        assert!(
            !provider
                .token_generator()
                .generate()?
                .expose_secret()
                .is_empty()
        );
        Ok(())
    }
}
