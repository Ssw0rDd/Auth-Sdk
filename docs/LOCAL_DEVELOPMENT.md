# Local development

Companion to [GETTING_STARTED.md](GETTING_STARTED.md) and
[CONFIGURATION.md](CONFIGURATION.md).

## Repository layout

| Path | Role |
|------|------|
| `crates/` | Rust workspace (core, adapters, N-API, migrate, fuzz-adjacent crates) |
| `packages/bff` | `@sdk-auth/bff` |
| `packages/browser` | `@sdk-auth/browser` |
| `packages/ui` | `@sdk-auth/ui` |
| `security/pentest` | Local adversarial harness (no Internet scanning) |
| `docs/` | Architecture, ADRs, integrations, OpenAPI |
| `fuzz/` | cargo-fuzz targets (corpus/artifacts are gitignored) |

## Environment

```bash
cp .env.example .env
```

Fill only what you need for the path under test. Leave OAuth secrets empty until
you exercise federated login.

## npm workspace scripts

From the repository root:

| Script | Action |
|--------|--------|
| `npm run bff:build` / `bff:check` / `bff:test` | BFF package |
| `npm run browser:build` / `browser:check` / `browser:test` | Browser client |
| `npm run ui:build` / `ui:check` / `ui:test` | Login UI |
| `npm run pentest` / `pentest:check` | Local security harness |

Install once after clone:

```bash
npm install
```

## Rust commands

Portable default (quick loop):

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

Full workspace (needs OpenSSL for WebAuthn/Node where linked):

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps
```

Supply chain:

```bash
cargo audit --deny warnings --ignore RUSTSEC-2023-0071
cargo deny check
```

## Postgres and Redis for local contract tests

Start services, then export:

```bash
export SDK_AUTH_TEST_POSTGRES_URL=postgres://sdk_auth:sdk_auth_test@127.0.0.1:5432/sdk_auth
export SDK_AUTH_TEST_REDIS_URL=redis://127.0.0.1:6379/0
cargo test -p sdk-auth-postgres --all-features
cargo test -p sdk-auth-redis --all-features
```

Without these variables, distributed contract tests skip cleanly.

## SQLite developer loop

```bash
# After compose in code: migrate then open (never skip migrate)
# auth.db is gitignored
```

Delete local `*.db` / `*.db-shm` / `*.db-wal` when resetting schema experiments.

## Native Node bindings

Packages under `crates/sdk-auth-node` and `crates/sdk-auth-oauth-node` are private
workspace members. Build with their N-API tooling when changing the binding surface.
Output `*.node` files are gitignored and are **not** release artifacts.

## Local pentest harness

```bash
npm run pentest
```

See [security/pentest/README.md](../security/pentest/README.md). This is for
local matrices only — no credential stuffing of third-party systems, no public
probe targets.

## Hygiene

- Do not commit `.env`, keys, or browser profile dumps under `artifacts/`
- Do not publish local `packages/*/dist` as release packages without the
  project’s release process
- Prefer redacted fixtures in tests; CI greps dist for accidental secret strings

## Useful links

- [Node + TypeScript](integrations/node-typescript.md)
- [Browser + React](integrations/browser-react.md)
- [Quality gates](QUALITY_GATES.md)
- [Contributing](../CONTRIBUTING.md)
