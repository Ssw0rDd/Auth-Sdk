#![no_main]

use libfuzzer_sys::fuzz_target;
use sdk_auth_authorization::{PermissionKey, RoleKey};
use sdk_auth_crypto::parse_api_key;
use sdk_auth_types::SecretString;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        let _ = PermissionKey::parse(value);
        let _ = RoleKey::parse(value);
        let _ = parse_api_key(&SecretString::new(value));
    }
});
