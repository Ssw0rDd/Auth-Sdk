#![no_main]

use libfuzzer_sys::fuzz_target;
use sdk_auth_core::WebAuthnEngine;
use sdk_auth_types::{RealmId, UserId};
use sdk_auth_webauthn::{WebAuthnRealmConfig, WebAuthnRegistry};
use url::Url;

fuzz_target!(|input: &[u8]| {
    let Ok(response) = std::str::from_utf8(input) else {
        return;
    };
    let Ok(origin) = Url::parse("https://login.example.com") else {
        return;
    };
    let realm_id = RealmId::new();
    let Ok(registry) = WebAuthnRegistry::new(vec![WebAuthnRealmConfig {
        realm_id,
        rp_id: "example.com".to_owned(),
        rp_name: "SDK Auth Fuzz".to_owned(),
        origins: vec![origin],
    }]) else {
        return;
    };
    let Ok(ceremony) =
        registry.start_registration(realm_id, UserId::new(), "fuzz@example.com", "Fuzz", &[])
    else {
        return;
    };
    let _result =
        registry.finish_registration(realm_id, response, &ceremony.state, ceremony.state_format);
});
