# Getting started

Bootstrap SDK-Auth from a clean clone. For environment variables see
[CONFIGURATION.md](CONFIGURATION.md). For day-to-day commands see
[LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md).

## Prerequisites

| Tool | Requirement |
|------|-------------|
| Rust | MSRV **1.94+**; workspace pin in [`rust-toolchain.toml`](../rust-toolchain.toml) |
| Node.js | **≥ 22** (CI uses 24) |
| npm | Comes with Node; monorepo uses npm workspaces |
| OpenSSL 3 | Dev headers/libs for full WebAuthn / N-API builds (`libssl-dev` on Debian/Ubuntu) |
| Optional | PostgreSQL 16–18, Redis 7/8 for multi-instance and rate-limit paths |

Windows: install a recent Visual Studio Build Tools C++ workload and OpenSSL if you
build the native crates. macOS: `brew install openssl@3` and set link paths as needed.

## Clone and install

```bash
git clone https://github.com/Ssw0rDd/Auth-Sdk.git
cd Auth-Sdk
cp .env.example .env
# Edit .env — never commit real secrets
npm install
```

## Rust (portable default)

The default Cargo workspace members avoid the OpenSSL-heavy WebAuthn path so you
can validate the pure-Rust core quickly:

```bash
cargo fmt --all -- --check
cargo test
```

Full maintainer surface (includes WebAuthn, Node, etc.):

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## First in-memory compose

Use the snippet in the root [README.md](../README.md): `MemoryAuthStore` + vault key
from the host. Generate a 32-byte key:

```bash
openssl rand -base64 32
```

Put it in a secret manager or local `.env` (see `SDK_AUTH_VAULT_KEY_B64` in
[CONFIGURATION.md](CONFIGURATION.md)). Do **not** store the vault key in SQLite,
PostgreSQL, or Redis.

## SQLite path (single process)

1. Migrate explicitly (`SqliteMigrator::migrate` or Node `migrateSqlite`).
2. Open the store only after migrate — open refuses missing/incompatible schema.
3. Pass the same vault key material into crypto composition.

## Node + BFF + browser (0.7 alpha)

Recommended composition is documented in
[integrations/node-typescript.md](integrations/node-typescript.md):

1. Native `NodeAuthService` (SQLite or Postgres).
2. `@sdk-auth/bff` with encrypted stores and OAuth adapters.
3. `@sdk-auth/browser` + `@sdk-auth/ui` same-origin over HTTPS.

```bash
npm run bff:build && npm run browser:build && npm run ui:build
npm run bff:test && npm run browser:test && npm run ui:test
```

Native bindings (`@sdk-auth/internal-node`, `@sdk-auth/oauth-node`) stay **private**
during alpha. Use the workspace / verified prebuilds — do not treat a local
`*.node` binary as an official release artifact.

## Next steps

- Wire production secrets and OAuth callbacks → [CONFIGURATION.md](CONFIGURATION.md)
- Multi-instance Postgres/Redis and migration ops → [MIGRATION-0.7.md](MIGRATION-0.7.md)
- Threat model and security policy → [THREAT_MODEL.md](THREAT_MODEL.md), [SECURITY.md](../SECURITY.md)
- Contribute and run quality gates → [CONTRIBUTING.md](../CONTRIBUTING.md)
