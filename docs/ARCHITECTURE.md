# Arquitetura

## Portabilidade do workspace 0.7

O conjunto padrão da raiz contém os crates portáveis e é testado sem dependências
nativas em Windows, Linux e macOS. `sdk-auth-webauthn` permanece um adapter
opcional porque a API segura de `webauthn-rs` exige OpenSSL; `sdk-auth-node`
compõe esse adapter e precisa ser publicado por prebuilds, nunca exigindo que o
consumidor final compile OpenSSL. `--workspace` continua sendo o gate completo.
Veja o ADR 0007.

## Composition root 0.6

```mermaid
flowchart TB
  app[Host application] --> sdk[SdkAuth]
  sdk --> identity[IdentityService]
  sdk --> authn[AuthenticationService]
  sdk --> factors[AuthenticatorService]
  sdk --> sessions[SessionService]
  sdk --> recovery[RecoveryService]
  sdk --> audit[AuditService]
  sdk --> outbox[OutboxService]
  sdk --> iam[IamService]
  sdk --> authz[AuthorizationService]
  sdk --> passkeys[PasskeyService optional]
  identity --> usecases[Core use cases]
  authn --> usecases
  factors --> usecases
  sessions --> usecases
  recovery --> usecases
  passkeys --> webauthnPort[WebAuthnEngine port]
  passkeys --> passkeyPort[PasskeyStore port]
  webauthnPort --> webauthnAdapter[sdk-auth-webauthn]
  passkeyPort --> memory
  passkeyPort --> sqlite
  usecases --> ports[Ports]
  ports --> memory[Memory adapter]
  ports --> sqlite[SQLite adapter]
  ports --> postgres[PostgreSQL adapter]
  authn --> rateLimit[RateLimitStore]
  rateLimit --> postgres
  rateLimit --> redis[Redis adapter opcional]
```

As facades limitam a superfície descoberta por cada consumidor. Durante a janela
0.x, `AuthService` continua como implementação interna de compatibilidade para o
binding Node, mas não é a API recomendada para integrações novas.

## Unit of Work e journal

```mermaid
sequenceDiagram
  participant U as Core use case
  participant S as Store transaction
  participant D as Domain state
  participant A as Audit log
  participant O as Outbox
  U->>S: journaled mutation
  S->>D: write state
  S->>A: append audit
  opt integration event exists
    S->>O: append delivery event
  end
  alt all writes succeed
    S-->>U: commit
  else any write fails
    S-->>U: full rollback
  end
```

`SdkStore` exige `UnitOfWorkStore::REQUIRED`. Em PostgreSQL, a garantia usa uma
transação SQL e locks de linha/realm; em SQLite, transação `IMMEDIATE`; em Memory,
uma única seção crítica serializa as três gravações.
Audit é append-only e não compartilha acknowledgement ou retenção com o outbox.
Login, verificação de e-mail e revogação de sessão geram audit sem gerar evento
de integração; notificações e alterações IAM podem gravar ambos.

## Assurance e criptografia versionada

`Session::assurance()` deriva um resultado conservador da evidência persistida.
Password é AAL1; password com TOTP ou recovery code é AAL2 sem phishing
resistance; trusted-device permanece AAL1 porque o Core não controla o storage
do host. Passkey UV-required é AAL2, phishing-resistant e user-verified dentro
do modelo conservador da SDK; AAL3 nunca é inferido sem hardware e attestation
verificáveis.

`CryptoProvider` compõe password hashing, CSPRNG e vault. Ciphertexts persistem
`format_version`, `algorithm`, `key_id`, nonce e ciphertext. Formato/algoritmo
desconhecido falha fechado. O provider software declara explicitamente
`fips_validated = false`.

## Dependências

```mermaid
flowchart TD
  node[sdk-auth-node] --> core[sdk-auth-core]
  node --> sqlite[sdk-auth-sqlite]
  node --> postgres[sdk-auth-postgres]
  node --> redis[sdk-auth-redis]
  node --> webauthn[sdk-auth-webauthn]
  webauthn --> core
  sqlite --> core
  sqlite --> authorization
  postgres --> core
  postgres --> authorization
  redis --> core
  memory[sdk-auth-memory] --> core
  memory --> authorization
  testing[sdk-auth-testing] --> core
  testing --> authorization
  core --> mfa[sdk-auth-mfa]
  core --> authorization[sdk-auth-authorization]
  core --> crypto[sdk-auth-crypto]
  core --> validation[sdk-auth-validation]
  core --> types[sdk-auth-types]
  core --> errors[sdk-auth-error]
  mfa --> types
  mfa --> errors
  crypto --> types
  authorization --> types
  authorization --> errors
  wasm[sdk-auth-wasm] --> validation
  wasm --> authorization
```

O Core contém casos de uso e transições. Adapters dependem dele; o Core não
conhece SQLite, N-API, WebAssembly, HTTP ou framework. Traits de identidade,
sessão, challenge, rate limit, evento e MFA são segregadas e compostas por
`AuthStore`. `IamStore` isola catálogo, roles, assignments, service accounts e
API keys. `SdkStore` compõe ambos apenas no composition root `SdkAuth`.
`PasskeyStore` é uma capability opcional composta separadamente, preservando
adapters que implementam apenas autenticação e IAM.

## WebAuthn/passkeys

```mermaid
sequenceDiagram
  participant C as Browser/mobile
  participant H as Host/binding
  participant P as PasskeyService
  participant W as WebAuthnEngine
  participant S as PasskeyStore
  C->>H: begin registration/login
  H->>P: request transport-neutral
  P->>W: start(realm, credentials)
  W-->>P: public JSON + opaque state
  P->>S: persist state + digest(handle) + expiry
  P-->>H: public JSON + raw handle
  H-->>C: public JSON only
  C->>H: credential response + handle
  H->>P: finish(response JSON)
  P->>S: load server-side state
  P->>W: verify RP/origin/challenge/UV/signature
  P->>S: consume + credential + session/audit atomically
  P-->>H: opaque SDK tokens
```

O adapter concreto serializa estado e credencial com `provider_id` e versão. O
estado permanece exclusivamente server-side, indexado por handle aleatório de
256 bits persistido apenas como digest. Registro é ligado ao mesmo realm,
usuário e sessão do início. Credential IDs são únicos globalmente.

O RP ID é imutável por realm. A allow-list aceita origem HTTPS exata e,
opcionalmente, identidade Android exata derivada do certificado de assinatura.
Subdomínios e portas arbitrárias permanecem desativados.

Counter positivo precisa aumentar atomicamente. Regressão ou repetição positiva
consome a cerimônia, revoga a passkey, grava audit denied e não cria sessão.
Counter zero de passkeys sincronizadas não é tratado como clone.

## IAM e autorização

```mermaid
flowchart LR
  admin[Usuário + access + senha + MFA] --> iam[IamService]
  iam -->|revalida permissão na transação| policy[(IamStore)]
  user[Access token] --> authz[AuthorizationService]
  key[API key] --> authz
  authz -->|principal + roles atuais + scopes| policy
  authz -->|grant ou deny| host[Host / resource policy]
```

O bootstrap cria uma única role `realm_owner` e o catálogo IAM mínimo. Não há
wildcards, hierarquia, explicit deny ou ABAC em 0.3. A decisão é exata,
deny-by-default e reavaliada em cada chamada. API keys só chegam ao data plane;
o control plane aceita exclusivamente usuário humano com step-up fresco.

O `AuthorizationGrant` comprova apenas a permissão genérica solicitada. Ownership,
tenant do recurso e regras contra IDOR continuam no Core de domínio do host.

## Login com MFA

```mermaid
sequenceDiagram
  participant C as Cliente
  participant A as AuthService
  participant S as AuthStore
  participant V as SecretVault
  C->>A: login(email, senha, trusted token?)
  A->>S: verifica rate limit e credencial
  alt conta sem MFA
    A->>S: cria sessão atomicamente
    A-->>C: Authenticated
  else trusted token válido após senha
    A->>S: consome, rotaciona e cria sessão
    A-->>C: Authenticated + novo trusted token
  else TOTP necessário
    A->>S: persiste challenge pós-senha
    A-->>C: SecondFactorRequired
    C->>A: complete_login(challenge, TOTP/recovery)
    A->>V: abre seed com AAD
    A->>S: consome prova e cria sessão atomicamente
    A-->>C: Authenticated
  end
```

Não existe sessão parcial entre senha e MFA. Counters TOTP, recovery codes,
challenges e tokens de trusted device são consumidos na mesma transação que cria
a sessão.

## Vault e rotação de chaves

```mermaid
flowchart LR
  host[Host / secret manager] -->|key ID + 32 bytes| vault[XChaCha20Vault]
  core[Core] -->|seed + AAD| vault
  vault -->|key ID + nonce + ciphertext| db[(Storage)]
  db -->|ciphertext antigo| rewrap[Rewrap batch]
  rewrap --> vault
```

AAD inclui realm, usuário e identificador do fator/enrollment. O banco nunca
recebe seed ou recovery code em texto. Chaves antigas permanecem apenas durante
a janela de rewrap; remoção prematura torna ciphertext antigo irrecuperável.

## Refresh token

```mermaid
sequenceDiagram
  participant C as Cliente
  participant A as AuthService
  participant S as AuthStore
  C->>A: refresh(token)
  A->>S: rotate_refresh(digest antigo, digest novo)
  alt token ativo
    S-->>A: sessão rotacionada atomicamente
    A-->>C: novos access e refresh
  else token já usado
    S->>S: revoga família
    S-->>A: replay detectado
    A-->>C: TOKEN_REUSED
  end
```

## Fronteiras

```mermaid
flowchart LR
  browser[Browser/WASM não confiável] --> host[Host HTTP/BFF]
  host --> binding[Binding/adapter]
  binding --> core[Core confiável]
  core --> db[(Storage)]
  core --> outbox[(Outbox)]
  secret[Secret manager/HSM] --> binding
```

WASM expõe somente validação client-side. Password hashing, tokens, sessões,
TOTP, recovery codes, API keys e key material continuam server-side. O parser
WASM nunca substitui a decisão server-side.

Email serve somente para ownership e recuperação. Link recebido por email não
cria sessão, não satisfaz MFA e não autoriza gestão de passkeys.

## SQLite

`SqliteMigrator` é executado separadamente. `SqliteAuthStore::open` valida
`PRAGMA user_version` e recusa drift. Transições de replay, rotação, ativação e
revogação usam transações `IMMEDIATE`. O schema v6 adiciona rate limit sliding e
leases de outbox. Bootstrap e mutações IAM revalidam a
permissão do ator na mesma transação. SQLite é indicado para instância única ou
baixo write contention; escala horizontal exige outro adapter.

## PostgreSQL, Redis e outbox distribuído

```mermaid
sequenceDiagram
  participant W1 as Worker A
  participant W2 as Worker B
  participant P as PostgreSQL outbox
  W1->>P: claim(limit, lease, claim A)
  P-->>W1: eventos 1..N (SKIP LOCKED)
  W2->>P: claim(limit, lease, claim B)
  P-->>W2: somente eventos não leased
  W1->>P: acknowledge(evento, claim A)
  alt worker cai
    P->>P: lease expira
    W2->>P: claim novamente
  end
```

PostgreSQL 16–18 é o store distribuído oficial. O pool é limitado, possui
timeouts de acquire/connect/statement/lock/transação ociosa e TLS `verify-full`
por padrão. Migrações são explícitas, checksummed e protegidas por advisory lock.
O startup valida versão, conjunto mínimo de tabelas e estado de importação.

O outbox usa `FOR UPDATE SKIP LOCKED`, claim opaco e lease entre 5 segundos e 15
minutos. A semântica é at-least-once: consumidores devem ser idempotentes. Ack
sem claim, claim incorreto ou expirado não entrega o evento.

Redis 7/8 implementa somente rate limiting. Um script Lua atômico mantém janela
sliding exata e lockout para buckets independentes de conta e rede. Chaves usam
BLAKE3 keyed com segredo do host. Falha Redis nega a tentativa; não há fallback
local que permita bypass entre réplicas. Topologias Cluster/Sentinel e réplica
de leitura não fazem parte do contrato 0.6.

## Migração SQLite → PostgreSQL

A ferramenta `sdk-auth-migrate` exige SQLite v6 íntegro, adquire lock que impede
novos escritores e aceita somente PostgreSQL vazio. `sdk_import_status` é gravado
antes da cópia; todas as tabelas são convertidas e inseridas em uma transação.
Crash ou erro deixa status não completo e `PostgresAuthStore::connect` falha
fechado. Migração online/dual-write foi rejeitada nesta fase.
