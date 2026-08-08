# SDK-Auth

SDK de autenticação modular em Rust. Regras de negócio ficam no Core; Memory,
SQLite, PostgreSQL, Redis, Node.js e WebAssembly são adapters.

## Estado

Versão privada `0.6.0`. Os pacotes continuam com `publish = false` até revisão
independente da API e da segurança.

Implementado:

- registro, verificação de email, login, logout e reset de senha;
- access token e refresh token opacos, rotação e detecção de replay;
- sessões por realm e remember-me;
- TOTP RFC 6238, recovery codes e trusted devices rotativos;
- vault XChaCha20-Poly1305 versionado para seeds TOTP;
- RBAC exato e deny-by-default, catálogo de permissões por realm e papéis sem
  herança;
- contas de serviço e API keys restritas por scopes, com rotação e revogação;
- bootstrap IAM único e operações administrativas protegidas por sessão,
  senha atual, MFA recente e permissão explícita;
- adapters Memory, SQLite e PostgreSQL com contrato comum;
- rate limit distribuído Redis, exato e fail-closed, com buckets independentes;
- outbox com lease, claim/ack/release e entrega at-least-once entre workers;
- binding Node N-API e validação client-safe em WebAssembly;
- facades por capacidade, assurance conservador, crypto provider versionado,
  audit log append-only e journal state/audit/outbox atômico;
- schema SQLite v4 com metadados criptográficos e contrato rolling-deploy;
- passkeys WebAuthn com UV obrigatória, estado server-side, origens exatas,
  revogação e detecção de possível clone por signature counter;
- schemas SQLite/PostgreSQL v6, migração offline SQLite→PostgreSQL e factory Node assíncrona.

## Requisitos

- Rust 1.94 ou superior;
- Node.js 22 ou superior para o binding N-API;
- OpenSSL 3 development libraries para `sdk-auth-webauthn`;
- chave de vault de 32 bytes fornecida pelo host. Nunca salve a chave no banco.

## Construção em Rust

```rust,no_run
use std::sync::Arc;

use sdk_auth_core::{AuthConfig, SdkAuth};
use sdk_auth_crypto::{
    Argon2PasswordEngine, OsTokenGenerator, SoftwareCryptoProvider, VaultKey,
    XChaCha20Vault,
};
use sdk_auth_memory::MemoryAuthStore;
use sdk_auth_types::SecretBytes;

# fn build(key_material: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
let vault = XChaCha20Vault::new(
    "auth-v1",
    vec![VaultKey::new("auth-v1", SecretBytes::new(key_material))?],
)?;
let crypto = SoftwareCryptoProvider::new(
    Arc::new(Argon2PasswordEngine::recommended()?),
    Arc::new(OsTokenGenerator),
    Arc::new(vault),
);
let sdk = SdkAuth::builder()
    .store(Arc::new(MemoryAuthStore::new()))
    .crypto_provider(Arc::new(crypto))
    .auth_config(AuthConfig::default())
    .build()?;
# let _ = sdk;
# Ok(())
# }
```

`LoginOutcome` é discriminado: contas sem MFA retornam `Authenticated`; contas
com MFA retornam `SecondFactorRequired`. Nenhuma sessão é criada antes da prova.

`SdkAuth` separa `identity()`, `authentication()`, `authenticators()`,
`sessions()`, `recovery()`, `audit()`, `outbox()`, `iam()` e `authorization()`.
`passkeys()` existe somente quando `PasskeyStore` e `WebAuthnEngine` são
fornecidos juntos no composition root.
Leitura de audit exige step-up e `iam.audit:read`; outbox é uma porta operacional
confiada ao host. O host ainda
deve validar o recurso/tenant solicitado para impedir IDOR; um grant genérico
não decide ownership de domínio.

## SQLite

Migração é uma ação operacional explícita:

```rust,no_run
use sdk_auth_sqlite::{SqliteAuthStore, SqliteMigrator};

# fn open() -> Result<(), Box<dyn std::error::Error>> {
let report = SqliteMigrator::migrate("auth.db")?;
let store = SqliteAuthStore::open("auth.db")?;
# let _ = (report, store);
# Ok(())
# }
```

`SqliteAuthStore::open` recusa schema atrasado ou incompatível. Um schema futuro
aditivo só é aceito quando declara explicitamente compatibilidade de reader e
writer. Execute migrações antes de iniciar réplicas da aplicação.

## PostgreSQL, Redis e migração offline

PostgreSQL 16–18 é o adapter primário para múltiplas instâncias. Migrações são
explícitas e o startup recusa schema ausente, incompatível ou importação
incompleta. TLS usa `verify-full`; plaintext só pode ser habilitado explicitamente
para loopback.

```rust,no_run
use sdk_auth_postgres::{PostgresAuthStore, PostgresConfig, PostgresMigrator};
use sdk_auth_types::SecretString;

# async fn open() -> Result<(), Box<dyn std::error::Error>> {
let config = PostgresConfig::new(SecretString::new(
    "postgres://sdk_auth:secret@db.example.com/sdk_auth",
));
PostgresMigrator::migrate(&config).await?;
let store = PostgresAuthStore::connect(config).await?;
# let _ = store;
# Ok(())
# }
```

Redis 7/8 é opcional e implementa apenas `RateLimitStore`. Email normalizado e
fingerprint de rede viram chaves BLAKE3 keyed; não são gravados em claro no Redis.
Indisponibilidade falha fechado. Não existe fallback local silencioso.

Migração offline de SQLite v6 para PostgreSQL vazio:

```powershell
$env:SDK_AUTH_POSTGRES_URL='postgres://sdk_auth:secret@127.0.0.1:5432/sdk_auth'
cargo run -p sdk-auth-migrate -- sqlite-to-postgres --sqlite auth.db --allow-insecure-localhost
```

Não passe a URL com senha na linha de comando. O utilitário bloqueia escritores
SQLite, valida integridade, marca o destino `in_progress`, copia em uma transação
e só libera o startup após `complete`.

## WebAuthn/passkeys

O Core conhece apenas `WebAuthnEngine`. O adapter concreto fica isolado em
`sdk-auth-webauthn`; tipos de `webauthn-rs` não fazem parte da API pública.

```rust,no_run
use std::sync::Arc;
use sdk_auth_core::SdkAuth;
use sdk_auth_memory::MemoryAuthStore;
use sdk_auth_types::RealmId;
use sdk_auth_webauthn::{WebAuthnRealmConfig, WebAuthnRegistry};
use url::Url;

# fn compose(existing_builder: sdk_auth_core::SdkAuthBuilder) -> Result<(), Box<dyn std::error::Error>> {
let realm_id = RealmId::new();
let store = Arc::new(MemoryAuthStore::new());
let engine = WebAuthnRegistry::new(vec![WebAuthnRealmConfig {
    realm_id,
    rp_id: "example.com".to_owned(),
    rp_name: "Example".to_owned(),
    origins: vec![Url::parse("https://login.example.com")?],
}])?;
let _builder = existing_builder
    .store(Arc::clone(&store))
    .passkey_store(store)
    .webauthn_engine(Arc::new(engine));
# Ok(())
# }
```

O RP ID não pode mudar sem invalidar credenciais. Origens são allow-list exata:
HTTPS ou `android:apk-key-hash:<SHA-256-base64url>`. Subdomínios e portas não são
aceitos implicitamente. Pelo menos uma origem HTTPS explícita é obrigatória.
Attestation, conditional UI e usernameless login foram adiados.

O JSON retornado é representação de transporte. Em browsers modernos, converta
`wire.publicKey` com `PublicKeyCredential.parseCreationOptionsFromJSON` ou
`parseRequestOptionsFromJSON` antes de chamar `navigator.credentials`; depois
serialize o `PublicKeyCredential` com `toJSON()`. Em Android, envie
`wire.publicKey` ao Credential Manager. Nunca envie o ceremony state ao cliente.

## Node.js

```javascript
const { migrateSqlite, NodeAuthService } = require("./sdk-auth-node.node");

migrateSqlite("auth.db");
const auth = new NodeAuthService({
  sqlitePath: "auth.db",
  activeKeyId: "auth-v1",
  vaultKeys: [{ keyId: "auth-v1", material: vaultKeyUint8Array }],
  webauthnRealms: [{
    realmId,
    rpId: "example.com",
    rpName: "Example",
    origins: ["https://login.example.com"],
  }],
});
```

PostgreSQL usa factory assíncrona; o construtor síncrono anterior permanece para
compatibilidade SQLite:

```javascript
const { migratePostgres, NodeAuthService } = require("./sdk-auth-node.node");

await migratePostgres(process.env.SDK_AUTH_POSTGRES_URL, false);
const auth = await NodeAuthService.connectPostgres({
  databaseUrl: process.env.SDK_AUTH_POSTGRES_URL,
  activeKeyId: "auth-v1",
  vaultKeys: [{ keyId: "auth-v1", material: vaultKeyUint8Array }],
  redisRateLimit: {
    redisUrl: process.env.SDK_AUTH_REDIS_URL,
    privacyKey: redisPrivacyKeyUint8Array,
  },
});
```

Buffers e strings JavaScript não têm zeroização garantida. Evite logs, dumps e
retenção de senha, códigos, tokens, URI `otpauth` e material de chave.

## Segurança de integração

Tokens e API keys são segredos e não aparecem em `Debug`. Aplicações web devem
usar TLS e cookies `HttpOnly`, `Secure`, `SameSite` com defesa CSRF. O host é responsável
por CORS, CSP, proxy confiável, rate limit global, armazenamento de chaves,
entrega de email, backup, SIEM e autorização HTTP.

## Quality gates

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
cargo audit --deny warnings
cargo deny check
```

## Documentação

- [Arquitetura](docs/ARCHITECTURE.md)
- [Modelo de ameaças](docs/THREAT_MODEL.md)
- [Auditoria técnica 0.4](docs/AUDIT-0.4.md)
- [Auditoria técnica 0.5](docs/AUDIT-0.5.md)
- [Auditoria técnica 0.6](docs/AUDIT-0.6.md)
- [ADR de persistência distribuída](docs/adr/0006-distributed-persistence.md)
- [ADR WebAuthn/passkeys](docs/adr/0005-webauthn-passkeys.md)
- [Quality gates](docs/QUALITY_GATES.md)
- [Política de segurança](SECURITY.md)
- [Roadmap](ROADMAP.md)

## Licença

Código próprio: MIT ou Apache-2.0, à escolha do consumidor. O adapter WebAuthn
usa dependência MPL-2.0; consulte [licenças de terceiros](THIRD_PARTY_LICENSES.md).
