# Configuration

Template: [`.env.example`](../.env.example). Copy to `.env` for local use. `.env`
is gitignored; **never** commit real credentials.

```bash
cp .env.example .env
```

## Variable reference

### Public origin

| Variable | Purpose |
|----------|---------|
| `SDK_AUTH_PUBLIC_ORIGIN` | Exact public origin of the app BFF (e.g. `https://app.example.com`). Must match browser Origin for CSRF and drive `__Host-` cookie scope. No trailing path. |

Insecure HTTP is only for tightly controlled local experiments; production and
real integration tests expect HTTPS.

### Persistence

| Variable | Purpose |
|----------|---------|
| `SDK_AUTH_POSTGRES_URL` | Primary multi-instance store. Prefer secrets outside the process argv. |
| `SDK_AUTH_REDIS_URL` | Optional distributed rate limit / BFF atomic blob backend. |
| `SDK_AUTH_SQLITE_PATH` | Optional single-process SQLite file path for local development. |

PostgreSQL TLS uses **verify-full** by default. Plaintext is only for explicit
loopback scenarios. Migrate **before** app replicas open the store.

Do not put the database password on the migrate CLI when avoidable:

```powershell
$env:SDK_AUTH_POSTGRES_URL='postgres://sdk_auth:secret@127.0.0.1:5432/sdk_auth'
cargo run -p sdk-auth-migrate -- sqlite-to-postgres --sqlite auth.db --allow-insecure-localhost
```

### Integration tests

| Variable | Purpose |
|----------|---------|
| `SDK_AUTH_TEST_POSTGRES_URL` | Used by Postgres contract tests when present. |
| `SDK_AUTH_TEST_REDIS_URL` | Used by Redis contract tests when present. |

If unset, those integration tests skip. CI sets them via service containers.

### OAuth / OIDC (server only)

| Variable | Purpose |
|----------|---------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OIDC |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` | Microsoft personal or Entra |
| `MICROSOFT_TENANT_ID` | Optional tenant (`consumers`, `organizations`, or GUID) |

Rules:

- Callback URL must match the provider console **and** BFF redirect **exactly**.
- Secrets must **never** be `VITE_*`, embedded in UI packages, or logged.
- Prefer Authorization Code + PKCE S256, state, nonce (as implemented by adapters).

Example wiring: [integrations/node-typescript.md](integrations/node-typescript.md).

### Cryptographic keys

Generate 32-byte material:

```bash
openssl rand -base64 32
```

| Variable | Purpose |
|----------|---------|
| `SDK_AUTH_VAULT_KEY_B64` | MFA TOTP vault (XChaCha20-Poly1305). Host-owned. |
| `SDK_AUTH_VAULT_KEY_ID` | Active vault key id (e.g. `auth-v1`). |
| `SDK_AUTH_BFF_KEY_B64` | AES-256-GCM key for encrypted BFF stores. |
| `SDK_AUTH_BFF_KEY_ID` | Active BFF keyring id (e.g. `bff-2026-08`). |
| `SDK_AUTH_REDIS_PRIVACY_KEY_B64` | Keys BLAKE3 fingerprints so rate-limit keys are not plain PII. |

Critical constraints:

- **Vault key ≠ BFF key ≠ Redis privacy key** — rotate independently.
- Never persist raw key material in SQLite, Postgres rows, or Redis values.
- Load from a secret manager in production; prefer ephemeral env injection.
- Version key ids so you can rotate without locking existing sealed data.

## BFF runtime (non-env)

Configured in host code when calling `createAuthBff` / store factories:

- `publicOrigin` — same rules as `SDK_AUTH_PUBLIC_ORIGIN`
- Encrypted stores via `createEncryptedBffStores` + atomic KV (`putIfAbsent`,
  `getAndDelete`, `runExclusive` across replicas — use official Redis adapter)
- OAuth provider map with exact redirect URIs
- Host-owned email delivery for registration/verify (never return raw tokens to the browser)

In-memory BFF stores are for **single process / tests only**.

## WebAuthn

Configured on the native service (not typically file-based env):

- `rpId` is durable — changing it invalidates credentials
- `origins` is an exact allow-list (HTTPS or Android key-hash forms)
- OpenSSL required for the official `sdk-auth-webauthn` adapter

## What must never reach the browser

- Access/refresh tokens, API keys, OAuth `client_secret`, code verifiers
- Vault / BFF key material
- MFA seeds / `otpauth` URIs
- Passkey ceremony server state
- Database or Redis URLs with credentials

## Related docs

- [GETTING_STARTED.md](GETTING_STARTED.md)
- [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md)
- [SECURITY.md](../SECURITY.md)
- [ADR 0010 — public code vs confidential state](adr/0010-public-code-and-confidential-state.md)
