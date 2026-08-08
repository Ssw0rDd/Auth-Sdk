# Auditoria técnica 0.4

Data: 2026-07-29. Escopo: fundação arquitetural 0.4, facades por capacidade,
composition root, unit of work, audit log, provider criptográfico, assurance,
schema SQLite v4, adapters Memory/SQLite, Node, WASM e gates do workspace.
Revisão interna; não substitui pentest, revisão criptográfica independente ou
certificação de conformidade.

## Resultado

Nenhum achado crítico ou alto permanece aberto. A fundação 0.4 atingiu o gate
interno mínimo de 9,5/10. O gate libera esta fase; não aprova antecipadamente os
módulos da 0.5.

| Área | Nota | Evidência principal |
|---|---:|---|
| Arquitetura | 9,6 | Facades por capacidade, ports dyn-compatible e composition root único |
| Segurança | 9,6 | Fail-closed, journal atômico, audit append-only, assurance conservador |
| Performance | 9,5 | Hot paths medidos; journal adiciona somente escrita necessária |
| Escalabilidade | 9,5 | Ports independentes; limites de SQLite declarados |
| Legibilidade | 9,5 | API segmentada e ADR; `AuthService` interno ainda grande |
| Acoplamento | 9,6 | Core sem framework; audit e outbox separados |
| Coesão | 9,5 | Facades coesas; decomposição física interna permanece pendente |
| API pública | 9,5 | IDs tipados, builders validados, enums evolutivos |
| Bugs, memória e concorrência | 9,6 | Contratos cross-adapter, transações `IMMEDIATE`, zero `unsafe` manual |
| Testes e documentação | 9,5 | 54 testes, rustdoc, MSRV, WASM, Node, coverage e ADR |
| **Final** | **9,5** | **Gate atendido com riscos residuais explícitos** |

| Crate afetado | Nota final |
|---|---:|
| `sdk-auth-types` | 9,6 |
| `sdk-auth-crypto` | 9,7 |
| `sdk-auth-core` | 9,5 |
| `sdk-auth-memory` | 9,5 |
| `sdk-auth-sqlite` | 9,5 |
| `sdk-auth-node` | 9,5 |
| `sdk-auth-wasm` | 9,7 |
| `sdk-auth-testing` | 9,5 |

Nota alta representa controles e evidência no escopo auditado, não promessa de
invulnerabilidade.

## Arquitetura, acoplamento e coesão

- `SdkAuth` expõe `identity`, `authentication`, `authenticators`, `sessions`,
  `recovery`, `audit`, `outbox`, `iam` e `authorization`.
- As facades delegam ao mesmo Core. Nenhuma regra foi duplicada em adapter,
  binding ou WASM.
- Ports continuam object-safe; não expõem closures transacionais, lifetimes do
  adapter ou tipos de framework.
- `SdkStore` exige `AuditStore` e `UnitOfWorkStore`. Um adapter incompatível é
  rejeitado pelo builder antes de atender tráfego.
- Audit e outbox possuem IDs, APIs e ciclo de vida distintos. `AuditId` não é
  semanticamente reutilizado como `EventId`.
- Login, verificação de e-mail e revogação geram registros audit-only. Eventos
  de entrega continuam opcionais e não são usados como audit log.
- Não há dependências circulares.

Dívida: `AuthService` ainda concentra a implementação histórica de autenticação
e MFA. As facades estabilizam o contrato externo, mas a decomposição física em
use cases menores deve ocorrer antes de 1.0, preservando comandos atômicos.

## Segurança e threat model

- Estado, audit e evento opcional são confirmados na mesma transação SQLite ou
  seção crítica Memory. Falha de journal impede commit parcial observável.
- SQLite usa transações `IMMEDIATE` nos fluxos concorrentes e queries
  parametrizadas com isolamento por realm.
- Leitura de audit exige usuário, sessão ativa, senha, MFA fresco e
  `iam.audit:read`. API key não acessa o control plane.
- Audit não possui delete nem acknowledgement. Payloads são JSON limitado e sem
  segredo; bearer tokens, senhas, seeds e códigos não são registrados.
- Ciphertext persiste versão, algoritmo, key ID, nonce e conteúdo autenticado.
  Versão ou algoritmo desconhecido falha fechado.
- `CryptoProvider` declara capacidades e status FIPS. O provider software não se
  apresenta como FIPS validado.
- `Session::assurance` não promove trusted-device para AAL2. TOTP e recovery
  code nunca são marcados phishing-resistant.
- Não há `unsafe`, `unwrap`, `expect`, `panic!`, `todo!` ou `unimplemented!` no
  código manual auditado.

Cobertura de ameaças: OWASP A01/A02/A03/A04/A07/A09; ASVS V2/V3/V4/V7;
CWE-285, CWE-287, CWE-307, CWE-312, CWE-330, CWE-384, CWE-613, CWE-862 e
CWE-863; STRIDE para spoofing, tampering, repudiation, information disclosure,
DoS e elevation of privilege. LINDDUN permanece responsabilidade conjunta com
o host para retenção, correlação, IP e dados de dispositivo.

Fora do escopo do Core: TLS, cookies, CSRF, CORS, CSP, WAF, rate limit global,
SMTP, SIEM, secret manager/HSM operacional, autorização por objeto e resposta a
incidente.

## Criptografia

- Passwords: Argon2id com parâmetros persistidos em PHC e política de rehash.
- Tokens opacos: 256 bits de `OsRng`; somente digest BLAKE3 v1 é persistido.
- TOTP: HMAC-SHA-1 apenas pela interoperabilidade RFC 6238, não como hash geral.
- Vault: XChaCha20-Poly1305 com nonce aleatório, AAD contextual, key ID e rotação.
- Segredos Rust usam tipos redigidos e zeroizáveis. JavaScript não oferece a
  mesma garantia.
- Migração futura de digest BLAKE3 para HMAC deve ser versionada e dual-read;
  troca silenciosa revogaria credenciais existentes.

## API pública e compatibilidade

- A API recomendada é segmentada pelas facades; o acesso monolítico existe
  somente como compatibilidade interna do binding Node durante 0.x.
- `AuditId`, `EventId`, IDs de sessão, usuário e realm impedem mistura acidental.
- Builders rejeitam provider criptográfico misturado com capacidades legadas.
- `#[non_exhaustive]` é usado em enums que devem evoluir.
- SQLite schema v4 recusa schema antigo. Schema futuro aditivo é aceito apenas
  quando declara `min_reader_version` e `min_writer_version` compatíveis.
- Alterações de trait em 0.4 são breaking para adapters privados, permitidas na
  fase pre-1.0 e registradas no changelog/ADR.

## Performance, escalabilidade e complexidade

Baseline local Windows x86_64; benchmark não é SLA:

- RBAC, 256 grants e 128 scopes: 595,61–613,78 ns;
- digest BLAKE3 de token opaco: 104,78–105,87 ns;
- parse/checksum/digest de API key: 1,2953–1,3209 µs;
- validação de password policy: 186,38–202,08 ns;
- Argon2id no perfil mínimo de benchmark: 35,142–35,637 ms;
- TOTP, janela ±1: 2,8788–3,0265 µs;
- normalização de recovery code: 273,08–284,14 ns;
- abertura XChaCha20-Poly1305: 2,4367–2,5126 µs.

Argon2id deve ser calibrado no hardware de produção; o perfil rápido do
benchmark não é recomendação operacional. Audit acrescenta uma inserção por
mutação relevante. Login audit-only não cria pressão artificial no outbox.

Memory é destinado a teste/desenvolvimento. SQLite é adequado a instância única
ou baixa contenção; escrita horizontal exige adapter Postgres e, quando houver
rate limit distribuído, backend dedicado como Redis.

## Bugs, leaks, race conditions e `unsafe`

Não foi identificado memory leak, `unsafe` manual ou panic deliberado. Testes
cobrem refresh concorrente, bootstrap IAM concorrente, replay, single-use,
cross-realm, revogação, migração e reopen. O binding N-API mantém detalhes Rust
fora da API JavaScript; strings e buffers JS devem ser tratados pelo host como
não zeroizáveis.

Possível fonte de complexidade: o arquivo interno de serviços e os adapters
SQLite/Memory são grandes. Separá-los por bounded context melhorará revisão sem
alterar a API pública, mas não deve fragmentar transações em vários serviços.

## Evidências executadas

- `cargo fmt --all -- --check`: passou.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passou.
- `cargo test --workspace --all-features`: 54 testes passaram.
- `cargo +1.88.0 check --workspace --all-targets`: MSRV passou.
- `cargo doc --workspace --no-deps --all-features`: passou.
- WASM `wasm32-unknown-unknown`: passou.
- Node N-API release, smoke SQLite e `npm audit`: passaram; zero vulnerabilidades.
- `cargo audit --deny warnings`: 228 dependências, nenhum advisory.
- `cargo deny check`: advisories, bans, licenças e sources passaram.
- Cobertura total do workspace: 76,97% de linhas. Node/WASM e glue sem harness
  Rust reduzem o total.
- Cobertura da lógica de segurança filtrada: 90,86% de linhas; gate interno
  de Core/Crypto/Validation atendido.
- `cargo +nightly fuzz check`: três targets compilaram. Runtime local Windows
  não iniciou por `STATUS_DLL_NOT_FOUND`; CI Linux deve executar os corpora.
- Mutation testing não executado: `cargo-mutants` não está instalado.
- Benchmarks isolados de authorization e Core passaram. O comando agregado do
  workspace excedeu o timeout local e não é tratado como sucesso.

## Riscos residuais e dívida técnica

| ID | Severidade | Estado | Risco / ação |
|---|---|---|---|
| SDK-018 | média | aceito | TOTP e recovery code não resistem a phishing em tempo real; priorizar WebAuthn/passkeys na 0.5. |
| SDK-019 | média | migração | Digests de bearer token/API key são BLAKE3 sem chave; projetar HMAC versionado e dual-read antes de troca. |
| SDK-020 | média | host | RBAC genérico não resolve ownership/IDOR; host deve autorizar realm e objeto após o grant. |
| SDK-021 | baixa | aberto | `AuthService` interno permanece monolítico; decompor por use case antes de 1.0. |
| SDK-022 | baixa | aberto | Cobertura bruta do workspace é 76,97%; criar harness de binding/glue sem mascarar métricas. |
| SDK-023 | baixa | CI | Runtime fuzz Windows falha por DLL; executar continuamente em Linux. |
| SDK-024 | baixa | aberto | Mutation score ainda não medido; instalar e fixar `cargo-mutants` no CI periódico. |
| SDK-025 | baixa | observar | RustCrypto 0.10/0.11 duplica dependências transitivas por Argon2 0.5; acompanhar convergência sem upgrade inseguro. |
| SDK-026 | baixa | aceito | SQLite é single-writer; não prometer escala horizontal sem adapter Postgres. |

## Decisões difíceis de reverter

- formatos persistidos de ciphertext e nomes de kind no audit;
- semântica e isolamento de `RealmId`;
- separação entre `AuditId` e `EventId`;
- formato público de error codes;
- estratégia de migração SQLite e compatibilidade reader/writer.

Mudanças nessas áreas exigem migração versionada, dual-read ou nova major.

## Gate para a próxima etapa

A fundação 0.4 está aprovada em 9,5/10. A 0.5 deve começar por WebAuthn/passkeys
e modelo de authenticator, não por JWT/PASETO, ABAC ou novos bindings. Antes de
publicar 1.0: remover a compatibilidade monolítica, testar adapter Postgres,
executar fuzz Linux e obter revisão externa de segurança.

## Referências primárias

- Rust Reference, dyn compatibility:
  <https://doc.rust-lang.org/stable/reference/items/traits.html>
- Rust API Guidelines, future proofing:
  <https://rust-lang.github.io/api-guidelines/future-proofing.html>
- NIST SP 800-63B, authenticators:
  <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/>
- rusqlite `TransactionBehavior::Immediate`:
  <https://docs.rs/rusqlite/latest/rusqlite/enum.TransactionBehavior.html>
