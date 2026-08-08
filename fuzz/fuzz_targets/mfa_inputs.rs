#![no_main]

use libfuzzer_sys::fuzz_target;
use sdk_auth_mfa::{matching_totp_counter, normalize_recovery_code};

fuzz_target!(|input: &str| {
    let _totp = matching_totp_counter(&[0x5A; 20], input, 1_774_958_400, None);
    let _recovery = normalize_recovery_code(input);
});
