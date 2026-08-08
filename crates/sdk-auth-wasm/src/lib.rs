//! Client-safe WebAssembly validation facade.
//!
//! This crate intentionally exports no password hashing, tokens, session state,
//! key material, or server-side authentication capability.

use sdk_auth_authorization::PermissionKey;
use sdk_auth_validation::{
    PasswordPolicy, Validator, is_cnpj, is_cpf, is_e164_phone, is_ip, is_json, is_mac,
    is_safe_http_url, is_ulid, is_uuid,
};
use wasm_bindgen::prelude::*;

/// Returns whether a password passes the SDK's default client-side policy.
#[wasm_bindgen]
#[must_use]
pub fn validate_password(password: &str) -> bool {
    PasswordPolicy::recommended()
        .validate("password", password)
        .is_ok()
}

/// Returns whether a value is a valid CPF.
#[wasm_bindgen]
#[must_use]
pub fn validate_cpf(value: &str) -> bool {
    is_cpf(value)
}

/// Returns whether a value is a valid CNPJ.
#[wasm_bindgen]
#[must_use]
pub fn validate_cnpj(value: &str) -> bool {
    is_cnpj(value)
}

/// Returns whether a value is a valid UUID.
#[wasm_bindgen]
#[must_use]
pub fn validate_uuid(value: &str) -> bool {
    is_uuid(value)
}

/// Returns whether a value is a valid ULID.
#[wasm_bindgen]
#[must_use]
pub fn validate_ulid(value: &str) -> bool {
    is_ulid(value)
}

/// Returns whether a value is an absolute credential-free HTTP(S) URL.
#[wasm_bindgen]
#[must_use]
pub fn validate_http_url(value: &str) -> bool {
    is_safe_http_url(value)
}

/// Returns whether a value is an IPv4 or IPv6 address.
#[wasm_bindgen]
#[must_use]
pub fn validate_ip(value: &str) -> bool {
    is_ip(value)
}

/// Returns whether a value is a conventional MAC address.
#[wasm_bindgen]
#[must_use]
pub fn validate_mac(value: &str) -> bool {
    is_mac(value)
}

/// Returns whether a value follows E.164 phone syntax.
#[wasm_bindgen]
#[must_use]
pub fn validate_phone(value: &str) -> bool {
    is_e164_phone(value)
}

/// Returns whether a string is valid JSON.
#[wasm_bindgen]
#[must_use]
pub fn validate_json(value: &str) -> bool {
    is_json(value)
}

/// Returns whether a value is a canonical wildcard-free permission key.
#[wasm_bindgen]
#[must_use]
pub fn validate_permission_key(value: &str) -> bool {
    PermissionKey::parse(value).is_ok()
}
