#![allow(missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use sdk_auth_authorization::{PermissionKey, is_allowed};

fn rbac(c: &mut Criterion) {
    let granted: Vec<_> = (0..256)
        .map(|index| parsed(format!("documents:action{index}")))
        .collect();
    let scopes: Vec<_> = granted.iter().take(128).cloned().collect();
    let requested = parsed("documents:action127");
    c.bench_function("rbac_256_grants_128_scopes", |bench| {
        bench.iter(|| is_allowed(&granted, Some(&scopes), &requested));
    });
}

fn parsed(value: impl Into<String>) -> PermissionKey {
    match PermissionKey::parse(value) {
        Ok(permission) => permission,
        Err(_) => std::process::abort(),
    }
}

criterion_group!(benches, rbac);
criterion_main!(benches);
