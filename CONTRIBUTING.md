# Contributing

Thanks for helping improve SDK-Auth. This repository ships an authentication core
and security-sensitive surface — treat secrets, threat model, and quality gates
as part of the contribution, not optional polish.

## Before you start

1. Read [GETTING_STARTED.md](docs/GETTING_STARTED.md) and [CONFIGURATION.md](docs/CONFIGURATION.md).
2. Skim [THREAT_MODEL.md](docs/THREAT_MODEL.md) and [SECURITY.md](SECURITY.md).
3. Prefer small, reviewable PRs over large mixed refactors.

## Setup

```bash
git clone https://github.com/Ssw0rDd/Auth-Sdk.git
cd Auth-Sdk
cp .env.example .env
npm install
```

Never commit `.env`, vault/BFF keys, OAuth secrets, real tokens, or production
database URLs. See `.gitignore` and `.env.example`.

## Quality gates (minimum)

Run what your change touches; full stack before large merges:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
cargo audit --deny warnings --ignore RUSTSEC-2023-0071
cargo deny check
npm run bff:test && npm run browser:test && npm run ui:test
npm run pentest && npm audit --audit-level=high
```

Detail: [docs/QUALITY_GATES.md](docs/QUALITY_GATES.md).

## Coding expectations

- Keep auth policy in Rust core; adapters stay thin.
- Do not log passwords, MFA codes, tokens, vault material, or sealed blobs.
- Browser packages stay **token-blind** — no SDK bearers in `localStorage`.
- Production BFF stores require distributed atomic semantics; do not “fix” multi-process
  refresh with only process-local mutexes.
- Prefer explicit migrate steps over silent schema mutation at startup.
- New public surface needs docs (README / integrations / OpenAPI when applicable).

## Security reports

Do **not** file public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## Pull requests

- Describe the threat or user problem, not only the patch.
- Link ADR or threat-model impact when behavior changes.
- Add/adjust tests for regression-prone auth edges.
- Keep generative UI demos and local harness artifacts out of the tree.

## License

Contributions are accepted under MIT OR Apache-2.0 (same as the project).
