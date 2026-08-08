//! RFC 6238 TOTP and high-entropy recovery-code primitives.
//!
//! SHA-1 is used only inside HMAC for the interoperable TOTP profile. The
//! collision attacks against standalone SHA-1 do not apply to this use.

use hmac::{Hmac, KeyInit as _, Mac as _};
use rand_core::{OsRng, RngCore as _};
use sdk_auth_error::AuthError;
use sdk_auth_types::{SecretBytes, SecretString};
use sha1::Sha1;
use subtle::ConstantTimeEq as _;
use url::Url;
use zeroize::Zeroize as _;

const PERIOD_SECONDS: u64 = 30;
const DIGITS: u32 = 6;
const SEED_BYTES: usize = 20;
const RECOVERY_BYTES: usize = 10;
const RECOVERY_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generated enrollment material returned exactly once to a trusted host.
#[derive(Debug)]
pub struct TotpEnrollmentMaterial {
    /// Raw seed that must be sealed before persistence.
    pub seed: SecretBytes,
    /// Base32 seed for manual entry in an authenticator.
    pub base32_secret: SecretString,
    /// Secret-bearing provisioning URI for QR generation by the host.
    pub provisioning_uri: SecretString,
}

/// One high-entropy recovery code returned exactly once.
#[derive(Debug)]
pub struct RecoveryCode(SecretString);

impl RecoveryCode {
    /// Exposes the printable code to the trusted enrollment boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

/// Generates a 160-bit TOTP seed and interoperable provisioning URI.
pub fn generate_totp_enrollment(
    issuer: &str,
    account_name: &str,
) -> Result<TotpEnrollmentMaterial, AuthError> {
    validate_label(issuer, 80)?;
    validate_label(account_name, 254)?;
    let mut seed = [0_u8; SEED_BYTES];
    OsRng.fill_bytes(&mut seed);
    let encoded = base32_encode(&seed);
    let uri = provisioning_uri(issuer, account_name, &encoded)?;
    let material = TotpEnrollmentMaterial {
        seed: SecretBytes::new(seed.to_vec()),
        base32_secret: SecretString::new(encoded),
        provisioning_uri: SecretString::new(uri),
    };
    seed.zeroize();
    Ok(material)
}

/// Returns the matching RFC 6238 counter within a fixed ±1-step window.
///
/// Counters at or below `last_accepted_counter` are rejected to prevent replay.
pub fn matching_totp_counter(
    seed: &[u8],
    code: &str,
    unix_seconds: u64,
    last_accepted_counter: Option<u64>,
) -> Result<Option<u64>, AuthError> {
    if seed.len() < SEED_BYTES || !valid_totp_code(code) {
        return Ok(None);
    }
    let current = unix_seconds / PERIOD_SECONDS;
    let counters = [
        current.saturating_sub(1),
        current,
        current.saturating_add(1),
    ];
    let mut matched = None;
    for counter in counters {
        let candidate = generate_code(seed, counter, DIGITS)?;
        let equal = bool::from(candidate.as_bytes().ct_eq(code.as_bytes()));
        let fresh = last_accepted_counter.is_none_or(|last| counter > last);
        if equal && fresh {
            matched = Some(counter);
        }
    }
    Ok(matched)
}

/// Generates recovery codes with 80 bits of entropy each.
pub fn generate_recovery_codes(count: usize) -> Result<Vec<RecoveryCode>, AuthError> {
    if !(1..=20).contains(&count) {
        return Err(AuthError::invalid_input());
    }
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0_u8; RECOVERY_BYTES];
        OsRng.fill_bytes(&mut bytes);
        let compact = crockford_encode(&bytes);
        let printable = format!(
            "{}-{}-{}-{}",
            &compact[0..4],
            &compact[4..8],
            &compact[8..12],
            &compact[12..16]
        );
        bytes.zeroize();
        result.push(RecoveryCode(SecretString::new(printable)));
    }
    Ok(result)
}

/// Normalizes a user-supplied recovery code to its 16-character digest input.
pub fn normalize_recovery_code(value: &str) -> Result<SecretString, AuthError> {
    let mut normalized = String::with_capacity(16);
    for character in value.chars() {
        if character == '-' {
            continue;
        }
        if !character.is_ascii() {
            return Err(AuthError::invalid_input());
        }
        let upper = character.to_ascii_uppercase();
        if !RECOVERY_ALPHABET.contains(&(upper as u8)) {
            return Err(AuthError::invalid_input());
        }
        normalized.push(upper);
    }
    if normalized.len() != 16 {
        return Err(AuthError::invalid_input());
    }
    Ok(SecretString::new(normalized))
}

fn valid_totp_code(code: &str) -> bool {
    code.len() == DIGITS as usize && code.bytes().all(|byte| byte.is_ascii_digit())
}

fn generate_code(seed: &[u8], counter: u64, digits: u32) -> Result<String, AuthError> {
    let mut mac = Hmac::<Sha1>::new_from_slice(seed).map_err(|_| AuthError::crypto_failure())?;
    mac.update(&counter.to_be_bytes());
    let mut digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32
        .checked_pow(digits)
        .ok_or_else(AuthError::crypto_failure)?;
    let result = format!("{:0width$}", binary % modulus, width = digits as usize);
    digest.zeroize();
    Ok(result)
}

fn provisioning_uri(issuer: &str, account: &str, secret: &str) -> Result<String, AuthError> {
    let mut url = Url::parse("otpauth://totp/").map_err(|_| AuthError::invalid_input())?;
    url.path_segments_mut()
        .map_err(|_| AuthError::invalid_input())?
        .push(&format!("{issuer}:{account}"));
    url.query_pairs_mut()
        .append_pair("secret", secret)
        .append_pair("issuer", issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", "6")
        .append_pair("period", "30");
    Ok(url.into())
}

fn validate_label(value: &str, maximum: usize) -> Result<(), AuthError> {
    if value.is_empty() || value.chars().count() > maximum || value.chars().any(char::is_control) {
        return Err(AuthError::invalid_input());
    }
    Ok(())
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    encode_five_bit(bytes, ALPHABET)
}

fn crockford_encode(bytes: &[u8]) -> String {
    encode_five_bit(bytes, RECOVERY_ALPHABET)
}

fn encode_five_bit(bytes: &[u8], alphabet: &[u8; 32]) -> String {
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            output.push(char::from(alphabet[index]));
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(char::from(alphabet[index]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_6238_sha1_vectors() -> Result<(), AuthError> {
        let secret = b"12345678901234567890";
        let vectors = [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (seconds, expected) in vectors {
            assert_eq!(generate_code(secret, seconds / 30, 8)?, expected);
        }
        Ok(())
    }

    #[test]
    fn rejects_replayed_or_malformed_totp() -> Result<(), AuthError> {
        let secret = b"12345678901234567890";
        let timestamp = 1_234_567_890;
        let counter = timestamp / PERIOD_SECONDS;
        let code = generate_code(secret, counter, DIGITS)?;
        assert_eq!(
            matching_totp_counter(secret, &code, timestamp, None)?,
            Some(counter)
        );
        assert_eq!(
            matching_totp_counter(secret, &code, timestamp, Some(counter))?,
            None
        );
        assert_eq!(
            matching_totp_counter(secret, "not-otp", timestamp, None)?,
            None
        );
        Ok(())
    }

    #[test]
    fn enrollment_and_recovery_material_are_redacted_and_valid() -> Result<(), AuthError> {
        let enrollment = generate_totp_enrollment("SDK Auth", "user@example.com")?;
        assert_eq!(enrollment.seed.len(), 20);
        assert!(
            enrollment
                .provisioning_uri
                .expose_secret()
                .starts_with("otpauth://totp/")
        );
        assert!(!format!("{enrollment:?}").contains(enrollment.base32_secret.expose_secret()));
        let codes = generate_recovery_codes(10)?;
        assert_eq!(codes.len(), 10);
        for code in &codes {
            assert_eq!(
                normalize_recovery_code(code.expose_secret())?
                    .expose_secret()
                    .len(),
                16
            );
            assert!(!format!("{code:?}").contains(code.expose_secret()));
        }
        Ok(())
    }
}
