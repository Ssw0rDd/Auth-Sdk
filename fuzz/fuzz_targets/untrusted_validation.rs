#![no_main]

use libfuzzer_sys::fuzz_target;
use sdk_auth_validation::{
    is_cnpj, is_cpf, is_e164_phone, is_ip, is_json, is_mac, is_safe_http_url, is_ulid, is_uuid,
    matches_regex,
};

fuzz_target!(|input: &str| {
    let _uuid = is_uuid(input);
    let _ulid = is_ulid(input);
    let _url = is_safe_http_url(input);
    let _ip = is_ip(input);
    let _mac = is_mac(input);
    let _phone = is_e164_phone(input);
    let _cpf = is_cpf(input);
    let _cnpj = is_cnpj(input);
    let _json = is_json(input);
    let _regex = matches_regex(input, "^[[:alnum:] _-]{0,128}$");
});
