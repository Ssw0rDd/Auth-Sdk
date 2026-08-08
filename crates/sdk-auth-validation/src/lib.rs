//! Composable validation for untrusted boundary inputs.

use std::{collections::HashSet, fmt::Display, net::IpAddr, str::FromStr};

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

/// One machine-readable validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// Stable issue code.
    pub code: String,
    /// Field or logical input that failed.
    pub field: String,
    /// Safe message intended for developers or end users.
    pub message: String,
}

impl ValidationIssue {
    /// Creates a validation issue.
    #[must_use]
    pub fn new(
        code: impl Into<String>,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Collection returned when validation fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationErrors(Vec<ValidationIssue>);

impl ValidationErrors {
    /// Creates a non-empty error collection.
    #[must_use]
    pub fn one(issue: ValidationIssue) -> Self {
        Self(vec![issue])
    }

    /// Returns all issues without exposing mutable internal state.
    #[must_use]
    pub fn issues(&self) -> &[ValidationIssue] {
        &self.0
    }

    /// Combines another collection into this one.
    pub fn extend(&mut self, other: Self) {
        self.0.extend(other.0);
    }
}

impl Display for ValidationErrors {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} validation issue(s)", self.0.len())
    }
}

impl std::error::Error for ValidationErrors {}

/// Synchronous validation strategy.
pub trait Validator<T: ?Sized>: Send + Sync {
    /// Validates a value without modifying it.
    fn validate(&self, field: &str, value: &T) -> Result<(), ValidationErrors>;
}

/// Asynchronous validation strategy for repository or network-backed checks.
#[async_trait]
pub trait AsyncValidator<T: ?Sized>: Send + Sync {
    /// Validates a value asynchronously without modifying it.
    async fn validate(&self, field: &str, value: &T) -> Result<(), ValidationErrors>;
}

/// Applies multiple validators and returns every issue.
pub fn validate_all<T: ?Sized>(
    field: &str,
    value: &T,
    validators: &[&dyn Validator<T>],
) -> Result<(), ValidationErrors> {
    let mut combined: Option<ValidationErrors> = None;
    for validator in validators {
        if let Err(errors) = validator.validate(field, value) {
            if let Some(existing) = combined.as_mut() {
                existing.extend(errors);
            } else {
                combined = Some(errors);
            }
        }
    }
    combined.map_or(Ok(()), Err)
}

/// Validates inclusive UTF-8 character length.
#[derive(Debug, Clone, Copy)]
pub struct StringLength {
    min: usize,
    max: usize,
}

impl StringLength {
    /// Creates a length validator.
    #[must_use]
    pub const fn new(min: usize, max: usize) -> Self {
        Self { min, max }
    }
}

impl Validator<str> for StringLength {
    fn validate(&self, field: &str, value: &str) -> Result<(), ValidationErrors> {
        let length = value.chars().count();
        if length < self.min || length > self.max {
            return Err(ValidationErrors::one(ValidationIssue::new(
                "length_out_of_range",
                field,
                format!(
                    "must contain between {} and {} characters",
                    self.min, self.max
                ),
            )));
        }
        Ok(())
    }
}

/// Password policy aligned with modern length and blocklist guidance.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    min_chars: usize,
    max_chars: usize,
    blocked: HashSet<String>,
}

impl PasswordPolicy {
    /// Creates a password policy and normalized local blocklist.
    #[must_use]
    pub fn new<I, S>(min_chars: usize, max_chars: usize, blocked: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            min_chars,
            max_chars,
            blocked: blocked
                .into_iter()
                .map(Into::into)
                .map(|value: String| value.to_lowercase())
                .collect(),
        }
    }

    /// Recommended single-factor password policy for the SDK.
    #[must_use]
    pub fn recommended() -> Self {
        Self::new(
            15,
            128,
            [
                "password",
                "password123",
                "123456789012345",
                "qwertyuiopasdfg",
                "letmeinletmein",
            ],
        )
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self::recommended()
    }
}

impl Validator<str> for PasswordPolicy {
    fn validate(&self, field: &str, value: &str) -> Result<(), ValidationErrors> {
        let mut issues = Vec::new();
        let length = value.chars().count();
        if length < self.min_chars {
            issues.push(ValidationIssue::new(
                "password_too_short",
                field,
                format!("must contain at least {} characters", self.min_chars),
            ));
        }
        if length > self.max_chars {
            issues.push(ValidationIssue::new(
                "password_too_long",
                field,
                format!("must contain at most {} characters", self.max_chars),
            ));
        }
        if self.blocked.contains(&value.to_lowercase()) {
            issues.push(ValidationIssue::new(
                "password_blocked",
                field,
                "password is present in the local compromised-password blocklist",
            ));
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(issues))
        }
    }
}

/// Returns whether a string is a syntactically valid UUID.
#[must_use]
pub fn is_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok()
}

/// Returns whether a string is a syntactically valid ULID.
#[must_use]
pub fn is_ulid(value: &str) -> bool {
    Ulid::from_string(value).is_ok()
}

/// Returns whether a URL is absolute HTTP or HTTPS without embedded credentials.
#[must_use]
pub fn is_safe_http_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

/// Returns whether a string is an IPv4 or IPv6 address.
#[must_use]
pub fn is_ip(value: &str) -> bool {
    IpAddr::from_str(value).is_ok()
}

/// Returns whether a string is a canonical colon- or hyphen-separated MAC.
#[must_use]
pub fn is_mac(value: &str) -> bool {
    let normalized = value.replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok())
}

/// Returns whether a phone number follows a conservative E.164 representation.
#[must_use]
pub fn is_e164_phone(value: &str) -> bool {
    let bytes = value.as_bytes();
    (8..=16).contains(&bytes.len())
        && bytes.first() == Some(&b'+')
        && bytes
            .get(1)
            .is_some_and(|digit| (b'1'..=b'9').contains(digit))
        && bytes[1..].iter().all(u8::is_ascii_digit)
}

/// Returns whether a Brazilian CPF has valid check digits.
#[must_use]
pub fn is_cpf(value: &str) -> bool {
    let digits = only_digits(value);
    if digits.len() != 11 || all_equal(&digits) {
        return false;
    }
    check_digit(&digits[..9], 10) == digits[9] && check_digit(&digits[..10], 11) == digits[10]
}

/// Returns whether a Brazilian CNPJ has valid check digits.
#[must_use]
pub fn is_cnpj(value: &str) -> bool {
    let digits = only_digits(value);
    if digits.len() != 14 || all_equal(&digits) {
        return false;
    }
    let first_weights = [5_u8, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let second_weights = [6_u8, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    weighted_digit(&digits[..12], &first_weights) == digits[12]
        && weighted_digit(&digits[..13], &second_weights) == digits[13]
}

/// Returns whether a string is valid JSON.
#[must_use]
pub fn is_json(value: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(value).is_ok()
}

/// Evaluates a bounded regular expression supplied by a trusted host.
pub fn matches_regex(value: &str, pattern: &str) -> Result<bool, ValidationErrors> {
    if pattern.len() > 4_096 || value.len() > 1_048_576 {
        return Err(ValidationErrors::one(ValidationIssue::new(
            "regex_input_too_large",
            "pattern",
            "regex pattern or input exceeds the configured bound",
        )));
    }
    Regex::new(pattern)
        .map(|regex| regex.is_match(value))
        .map_err(|_| {
            ValidationErrors::one(ValidationIssue::new(
                "invalid_regex",
                "pattern",
                "regular expression is invalid",
            ))
        })
}

fn only_digits(value: &str) -> Vec<u8> {
    value
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|digit| digit - b'0')
        .collect()
}

fn all_equal(digits: &[u8]) -> bool {
    digits
        .first()
        .is_none_or(|first| digits.iter().all(|digit| digit == first))
}

fn check_digit(digits: &[u8], initial_weight: u8) -> u8 {
    let sum: u16 = digits
        .iter()
        .enumerate()
        .map(|(index, digit)| u16::from(*digit) * u16::from(initial_weight - index as u8))
        .sum();
    let remainder = sum % 11;
    if remainder < 2 {
        0
    } else {
        (11 - remainder) as u8
    }
}

fn weighted_digit(digits: &[u8], weights: &[u8]) -> u8 {
    let sum: u16 = digits
        .iter()
        .zip(weights)
        .map(|(digit, weight)| u16::from(*digit) * u16::from(*weight))
        .sum();
    let remainder = sum % 11;
    if remainder < 2 {
        0
    } else {
        (11 - remainder) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    struct AlwaysInvalid;

    impl Validator<str> for AlwaysInvalid {
        fn validate(&self, field: &str, _value: &str) -> Result<(), ValidationErrors> {
            Err(ValidationErrors::one(ValidationIssue::new(
                "always_invalid",
                field,
                "value was rejected",
            )))
        }
    }

    #[test]
    fn validates_brazilian_documents() {
        assert!(is_cpf("529.982.247-25"));
        assert!(!is_cpf("111.111.111-11"));
        assert!(is_cnpj("04.252.011/0001-10"));
        assert!(!is_cnpj("11.111.111/1111-11"));
    }

    #[test]
    fn rejects_credentialed_or_non_http_urls() {
        assert!(is_safe_http_url("https://example.com/path"));
        assert!(!is_safe_http_url("file:///etc/passwd"));
        assert!(!is_safe_http_url("https://user:secret@example.com"));
    }

    #[test]
    fn password_policy_collects_issues() {
        let policy = PasswordPolicy::recommended();
        let result = policy.validate("password", "password");
        assert!(result.is_err());
        assert_eq!(result.err().map(|errors| errors.issues().len()), Some(2));
    }

    #[test]
    fn composite_and_length_validators_cover_boundaries() {
        let length = StringLength::new(2, 4);
        assert!(length.validate("name", "ab").is_ok());
        assert!(length.validate("name", "abcd").is_ok());
        assert!(length.validate("name", "a").is_err());
        assert!(length.validate("name", "abcde").is_err());

        let result = validate_all(
            "name",
            "a",
            &[&length as &dyn Validator<str>, &AlwaysInvalid],
        );
        let errors = result.err().map(|value| value.issues().len());
        assert_eq!(errors, Some(2));
        assert_eq!(
            ValidationErrors::one(ValidationIssue::new("x", "field", "bad")).to_string(),
            "1 validation issue(s)"
        );
    }

    #[test]
    fn validates_all_supported_boundary_formats() {
        assert!(is_uuid("018f4f5a-8f4c-7c6f-9da8-e6e6088bce25"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(is_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!is_ulid("not-a-ulid"));
        assert!(is_ip("127.0.0.1"));
        assert!(is_ip("2001:db8::1"));
        assert!(!is_ip("999.1.1.1"));
        assert!(is_mac("00:1A:2B:3C:4D:5E"));
        assert!(is_mac("00-1a-2b-3c-4d-5e"));
        assert!(!is_mac("00:11:22"));
        assert!(is_e164_phone("+5511999999999"));
        assert!(!is_e164_phone("5511999999999"));
        assert!(!is_e164_phone("+01234567"));
        assert!(is_json("{\"ok\":true}"));
        assert!(!is_json("{broken"));
    }

    #[test]
    fn regex_validation_is_bounded_and_reports_invalid_patterns() {
        assert_eq!(matches_regex("abc-123", "^[a-z0-9-]+$").ok(), Some(true));
        assert_eq!(matches_regex("ABC", "^[a-z]+$").ok(), Some(false));
        assert!(matches_regex("input", "[").is_err());
        assert!(matches_regex("input", &"a".repeat(4_097)).is_err());
        assert!(matches_regex(&"a".repeat(1_048_577), "a+").is_err());
    }

    #[test]
    fn rejects_document_edge_cases() {
        assert!(!is_cpf("123"));
        assert!(!is_cpf("00000000000"));
        assert!(!is_cnpj("123"));
        assert!(!is_cnpj("00000000000000"));
    }

    proptest! {
        #[test]
        fn boundary_validators_never_panic(input in ".{0,2048}") {
            let _uuid = is_uuid(&input);
            let _ulid = is_ulid(&input);
            let _url = is_safe_http_url(&input);
            let _ip = is_ip(&input);
            let _mac = is_mac(&input);
            let _phone = is_e164_phone(&input);
            let _cpf = is_cpf(&input);
            let _cnpj = is_cnpj(&input);
            let _json = is_json(&input);
        }
    }
}
