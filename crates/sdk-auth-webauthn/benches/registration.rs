//! Microbenchmark for relying-party challenge creation.
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use sdk_auth_core::WebAuthnEngine;
use sdk_auth_types::{RealmId, UserId};
use sdk_auth_webauthn::{WebAuthnRealmConfig, WebAuthnRegistry};
use url::Url;

fn benchmark_registration_start(criterion: &mut Criterion) {
    let realm_id = RealmId::new();
    let Ok(origin) = Url::parse("https://auth.example.com") else {
        return;
    };
    let Ok(registry) = WebAuthnRegistry::new(vec![WebAuthnRealmConfig {
        realm_id,
        rp_id: "example.com".to_owned(),
        rp_name: "SDK Auth benchmark".to_owned(),
        origins: vec![origin],
    }]) else {
        return;
    };
    let user_id = UserId::new();

    criterion.bench_function("webauthn_start_passkey_registration", |bencher| {
        bencher.iter(|| {
            registry.start_registration(
                black_box(realm_id),
                black_box(user_id),
                black_box("benchmark@example.com"),
                black_box("Benchmark User"),
                black_box(&[]),
            )
        });
    });
}

criterion_group!(benches, benchmark_registration_start);
criterion_main!(benches);
