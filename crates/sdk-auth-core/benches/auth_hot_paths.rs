//! Microbenchmarks for bounded authentication hot paths.
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use sdk_auth_crypto::{
    Argon2PasswordEngine, OsTokenGenerator, PasswordEngine, SecretVault, TokenGenerator, VaultKey,
    XChaCha20Vault, digest_token, generate_api_key, parse_api_key,
};
use sdk_auth_mfa::{matching_totp_counter, normalize_recovery_code};
use sdk_auth_types::{SecretBytes, SecretString};
use sdk_auth_validation::{PasswordPolicy, Validator};

fn benchmark_token_digest(criterion: &mut Criterion) {
    let Ok(token) = OsTokenGenerator.generate() else {
        return;
    };
    criterion.bench_function("opaque_token_blake3_digest", |bencher| {
        bencher.iter(|| digest_token(&token));
    });
}

fn benchmark_api_key_parse(criterion: &mut Criterion) {
    let Ok(generated) = generate_api_key(&OsTokenGenerator) else {
        return;
    };
    let credential = SecretString::new(generated.credential.expose_secret());
    criterion.bench_function("api_key_parse_and_digest", |bencher| {
        bencher.iter(|| parse_api_key(black_box(&credential)));
    });
}

fn benchmark_password_validation(criterion: &mut Criterion) {
    let policy = PasswordPolicy::recommended();
    criterion.bench_function("password_policy", |bencher| {
        bencher.iter(|| policy.validate("password", "a strong passphrase with length"));
    });
}

fn benchmark_password_hash(criterion: &mut Criterion) {
    let Ok(engine) = Argon2PasswordEngine::recommended() else {
        return;
    };
    let password = SecretString::new("a representative secure passphrase");
    criterion.bench_function("password_hash_argon2id", |bencher| {
        bencher.iter(|| engine.hash(black_box(&password)));
    });
}

fn benchmark_totp_verification(criterion: &mut Criterion) {
    criterion.bench_function("totp_hmac_sha1_window", |bencher| {
        bencher.iter(|| {
            matching_totp_counter(
                black_box(b"12345678901234567890"),
                black_box("287082"),
                black_box(59),
                None,
            )
        });
    });
    criterion.bench_function("recovery_code_normalization", |bencher| {
        bencher.iter(|| normalize_recovery_code(black_box("0123-4567-89AB-CDEF")));
    });
}

fn benchmark_secret_vault(criterion: &mut Criterion) {
    let Ok(key) = VaultKey::new("bench-v1", SecretBytes::new(vec![0x5A; 32])) else {
        return;
    };
    let Ok(vault) = XChaCha20Vault::new("bench-v1", vec![key]) else {
        return;
    };
    let Ok(sealed) = vault.seal(b"representative totp seed", b"realm|user|factor") else {
        return;
    };
    criterion.bench_function("xchacha20poly1305_open", |bencher| {
        bencher.iter(|| vault.open(black_box(&sealed), black_box(b"realm|user|factor")));
    });
}

criterion_group!(
    benches,
    benchmark_token_digest,
    benchmark_api_key_parse,
    benchmark_password_validation,
    benchmark_password_hash,
    benchmark_totp_verification,
    benchmark_secret_vault
);
criterion_main!(benches);
