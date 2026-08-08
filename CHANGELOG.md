# Changelog

Todas as mudanças relevantes são registradas neste arquivo.

## [Unreleased]

### Added

- Atomic federated identity and explicit account linking for Google, GitHub and
  Microsoft personal/tenant providers.
- Rustls-only OAuth/OIDC core and portable Node N-API binding.
- Framework-neutral BFF, token-blind browser client, Lit Web Components and
  React wrappers for password, OAuth, MFA and passkey login.
- Encrypted BFF stores with AES-256-GCM/keyring/AAD plus Redis atomic and session
  lease primitives.
- OpenAPI contract, multi-language integration guides and isolated local pentest
  harness.

### Changed

- SQLite/PostgreSQL schema v7 permits federated accounts without a local
  password and enforces unique issuer/subject identities.
- Main Node WebAuthn dependency is feature-gated; session inspection now returns
  email, assurance and rotatable backend state.
- API-key listing in SQLite/PostgreSQL uses one query instead of N+1.
- Browser builds no longer publish source or declaration maps.

### Security

- Verified email never authenticates or auto-links an external subject.
- OAuth state is bound to one browser and atomically consumed; PKCE/nonce and SDK
  tokens never cross the BFF boundary.
- MFA/link/passkey bearers remain server-side behind random HttpOnly pending IDs.
- Session inspection/logout is serialized across replicas to prevent concurrent
  refresh rotation from being misclassified as token replay.
- RUSTSEC-2023-0071 is accepted only as documented RISK-001 for public-key OIDC
  verification; every other advisory remains fatal.

## [0.6.0] - 2026-07-30

### Added

- PostgreSQL 16–18 adapter covering identity, sessions, challenges, MFA,
  passkeys, IAM, API keys, audit, outbox and rate limiting.
- Redis 7/8 exact sliding-window `RateLimitStore` with atomic Lua execution and
  keyed-BLAKE3 bucket identifiers.
- Claim/ack/release outbox leases with at-least-once worker semantics.
- Offline, all-or-nothing SQLite v6 to PostgreSQL migration command.
- Async Node `connectPostgres` factory and explicit `migratePostgres` function.
- Distributed CI contracts across PostgreSQL 16/17/18 and Redis 7/8.

### Changed

- Workspace version is 0.6.0; MSRV is Rust 1.94 and CI stable is Rust 1.97.1.
- SQLite schema v6 stores exact attempt windows and outbox lease metadata.
- `SdkAuthBuilder` accepts a dedicated `RateLimitStore` while old composition
  remains source-compatible for built-in adapters.
- Legacy single-consumer outbox facade methods are deprecated, not removed.

### Security

- Missing network context no longer collapses callers into an `unknown` bucket.
- Successful login clears only account state and cannot erase network pressure.
- Redis failure is fail-closed and never falls back to per-process memory.
- IAM mutations recheck the actor and serialize per realm in the same transaction.
- PostgreSQL startup rejects missing tables, incompatible schema and incomplete import.

## [0.5.0] - 2026-07-29

### Added

- Framework-independent `WebAuthnEngine` and `PasskeyStore` ports.
- Isolated `sdk-auth-webauthn` adapter using `webauthn-rs` 0.5.5.
- UV-required passkey registration and username-first authentication.
- Passkey listing, labeling, revocation, backup metadata and conservative AAL2
  phishing-resistant assurance.
- Server-side, single-use, bounded ceremonies with provider/version envelopes.
- Atomic signature-counter validation and passkey revocation on clone signals.
- Memory/SQLite cross-adapter passkey contract and WebAuthn response fuzz target.
- Node N-API passkey configuration and begin/finish/manage operations.
- SQLite schema v5 for passkey credentials and ceremonies.

### Changed

- `AuthEventKind` is non-exhaustive for forward-compatible audit evolution.
- OpenSSL development libraries are now a build prerequisite of the production
  WebAuthn adapter.
- Recovery policy explicitly preserves passkeys and MFA during password reset.

### Security

- Magic-link login was rejected. Email is not accepted as an authenticator and
  cannot create a session or satisfy step-up.
- RP IDs are immutable configuration; HTTPS and Android application origins are
  exact allow-list entries. Subdomain and arbitrary-port matching remain off.
- Registration completion is bound to the same user and session that began it.
- Credential identifiers are globally unique; response/state/blob sizes are
  bounded; raw ceremony state never crosses the server boundary.
- Attestation, presence-only keys, conditional UI and passkey-only account
  recovery remain disabled or deferred.

## [0.4.0] - 2026-07-29

### Added

- Capability-oriented facades for identity, authentication, authenticators,
  sessions, recovery and audit.
- Conservative NIST-style session assurance context.
- Versioned `CryptoProvider` composition and explicit sealed-secret format and
  AEAD metadata.
- Append-only structured audit storage separate from the outbox.
- Distinct `AuditId` and `EventId` types.
- Explicit `UnitOfWorkStore` atomic journal contract.
- SQLite schema v4 with audit backfill, crypto metadata and rolling-schema
  compatibility declarations.

### Changed

- `SdkAuth::authentication()` now exposes only authentication operations;
  identity, session, recovery and audit operations moved to their own facades.
- `SdkStore` now requires audit and atomic unit-of-work capabilities.
- SQLite migration 4 is required before opening an existing database.

### Security

- Journaled mutations commit state, audit and outbox together or roll back.
- Login, email verification and session revocation create audit-only records;
  operational audit does not inflate the integration outbox.
- Unknown ciphertext versions and algorithms fail closed.
- Trusted-device authentication remains conservatively classified as AAL1.
- The software crypto provider explicitly reports that it is not FIPS validated.

## [0.3.0] - 2026-07-29

### Added

- Crate pura `sdk-auth-authorization` com permission keys exatas, principals,
  roles, catálogo por realm e avaliador RBAC deny-by-default.
- Fachada `SdkAuth` com serviços de autenticação, IAM e autorização.
- Bootstrap IAM atômico e único, role reservada `realm_owner` e proteção do
  último owner humano.
- Contas de serviço e API keys de 256 bits, digests BLAKE3, scopes, validade,
  rotação com grace period e revogação.
- Migração SQLite v3, contrato Memory/SQLite, binding Node e parser client-safe
  de permission keys no WASM.
- Testes de contrato, concorrência, cross-realm, revogação imediata, rotação e
  fuzz target para entradas IAM.

### Security

- Toda mutação e leitura sensível do control plane exige usuário verificado,
  access token, senha atual, MFA fresco e permissão administrativa explícita.
- API keys nunca administram IAM; permissões e scopes são reavaliados a cada
  autorização; role revogada ou conta desabilitada nega imediatamente.
- Adapters revalidam a permissão do ator dentro do mesmo lock/transação da
  mutação para fechar TOCTOU.

## [0.2.0] - 2026-07-28

### Added

- TOTP RFC 6238 com perfil SHA-1/6 dígitos/30 segundos, janela ±1 e bloqueio de
  reutilização de counter.
- Dez recovery codes de 80 bits, uso único e armazenamento somente por digest.
- Trusted devices com token rotativo, validade absoluta, revogação e resposta a
  replay.
- Vault XChaCha20-Poly1305 com key ID, AAD por realm/usuário/fator e rewrap.
- Crate `sdk-auth-mfa` sem dependência de runtime ou storage.
- Migrações SQLite versionadas e explícitas.
- Fluxos MFA completos no binding Node e fuzz target para entradas MFA.

### Changed

- `login` retorna `LoginOutcome`; nenhuma sessão é criada antes da segunda prova.
- `AuthServiceBuilder` exige um `SecretVault`.
- `SqliteAuthStore::open` não aplica migrações implicitamente.
- Traits de storage foram segregadas por responsabilidade.

### Security

- Reset de senha preserva MFA, mas revoga sessões e trusted devices.
- Alterações de fator exigem senha atual e TOTP/recovery code.
- Rate limits independentes protegem login, reautenticação e gestão MFA.

## [0.1.0] - 2026-07-28

- Workspace inicial com autenticação essencial, tokens opacos, sessões, Memory,
  SQLite, Node.js e validação client-safe em WebAssembly.
