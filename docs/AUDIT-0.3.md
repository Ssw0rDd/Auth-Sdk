# Auditoria técnica 0.3

Data: 2026-07-29. Escopo: RBAC, IAM, API keys, adapters Memory/SQLite, Node,
WASM, migração v3, documentação e gates do workspace. Revisão interna; não é
certificação nem pentest independente.

## Resultado

Nenhum achado crítico ou alto permanece aberto. O módulo 0.3 atingiu o gate
interno mínimo de 9,5. A nota expressa evidência atual, não invulnerabilidade.

| Crate | Arq. | Seg. | Perf. | Escala | Legib. | Acopl. | Coesão | API | Bugs/memória | Testes/docs | Final |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `sdk-auth-authorization` | 9,8 | 9,8 | 9,7 | 9,7 | 9,7 | 9,8 | 9,9 | 9,7 | 9,8 | 9,6 | 9,7 |
| `sdk-auth-crypto` | 9,8 | 9,8 | 9,6 | 9,7 | 9,8 | 9,8 | 9,9 | 9,7 | 9,7 | 9,6 | 9,7 |
| `sdk-auth-core` | 9,6 | 9,8 | 9,5 | 9,5 | 9,5 | 9,7 | 9,6 | 9,5 | 9,7 | 9,6 | 9,6 |
| `sdk-auth-memory` | 9,7 | 9,7 | 9,6 | 9,5 | 9,6 | 9,7 | 9,8 | 9,6 | 9,7 | 9,7 | 9,6 |
| `sdk-auth-sqlite` | 9,7 | 9,8 | 9,5 | 9,5 | 9,5 | 9,7 | 9,7 | 9,6 | 9,7 | 9,7 | 9,6 |
| `sdk-auth-node` | 9,6 | 9,6 | 9,5 | 9,5 | 9,6 | 9,6 | 9,7 | 9,5 | 9,5 | 9,6 | 9,5 |
| `sdk-auth-wasm` | 9,8 | 9,8 | 9,8 | 9,8 | 9,8 | 9,9 | 9,9 | 9,7 | 9,9 | 9,6 | 9,8 |
| `sdk-auth-testing` | 9,7 | 9,8 | 9,6 | 9,6 | 9,7 | 9,8 | 9,8 | 9,6 | 9,8 | 9,8 | 9,7 |

`Bugs/memória` mede prevenção e risco residual; nota maior significa risco menor.

## Revisão obrigatória

### Arquitetura, acoplamento e coesão

- `sdk-auth-authorization` não faz I/O; Core contém casos de uso; adapters
  implementam ports; Node/WASM só traduzem tipos.
- `SdkAuth` é o composition root e separa authentication, IAM e authorization.
- Não há dependência circular. O WASM desabilita o feature `domain` e não traz
  UUID, RNG, storage ou credenciais server-side.
- `IamStore` exige que cada mutação revalide o ator atomicamente. Memory usa um
  lock; SQLite usa transação `IMMEDIATE`.

Dívida: métodos legados de autenticação e MFA ainda vivem em `AuthService`; a
entrada `mfa()` é uma fachada sobre o mesmo serviço. Separar internamente sem
quebrar transações é trabalho da 0.4, não motivo para duplicar regras agora.

### Segurança

- Permissões canônicas `resource:action`, exatas, sem wildcard e deny-by-default.
- Bootstrap único, role owner reservada e último owner humano protegido.
- Leitura e mutação IAM exigem usuário verificado, sessão ativa, senha, MFA
  fresco e permissão. API keys não podem operar o control plane.
- Segredo de API key usa 256 bits de `OsRng`; banco recebe apenas digest BLAKE3.
  Checksum serve só para detectar erro de digitação, não como autenticador.
- Scope obrigatório só reduz permissões atuais. Roles, permissões, expiração,
  revogação e status do principal são reavaliados em toda decisão.
- TTL padrão 90 dias, máximo 365 dias e overlap de rotação máximo 24 horas.
- Consultas são parametrizadas e isoladas por realm. Eventos não contêm segredo.
- `unsafe`, `unwrap`, `expect`, `panic`, `todo` e `unimplemented` são negados.

Cobertura principal: OWASP Top 10 A01/A02/A03/A04/A07/A09; ASVS V2/V3/V4;
CWE-285, CWE-287, CWE-307, CWE-330, CWE-384, CWE-613 e CWE-862; NIST
SP 800-63B-4. O grant genérico não substitui autorização por objeto contra IDOR.

### Performance e complexidade

A avaliação RBAC atual é busca linear limitada: no pior perfil público, até 256
grants e 128 scopes. Isso evita índices/cache stale e mantém revogação imediata.
O custo de I/O domina os adapters. Baseline local Windows x86_64:

- RBAC com 256 grants e 128 scopes: 751,55–763,05 ns;
- parse, checksum e digest de API key: 1,6356–1,6664 µs;
- BLAKE3 de bearer token: 122,75–124,57 ns;
- Argon2id recomendado: 47,746–49,693 ms;
- TOTP com janela ±1: 3,6831–3,7556 µs;
- abertura XChaCha20-Poly1305: 2,9337–3,1410 µs.

Criterion marcou regressão de 10–33% nos benchmarks antigos. Como todos os hot
paths, inclusive código não alterado, mudaram juntos após atualização de
toolchain/dependências, não há evidência suficiente para atribuir causa à 0.3.
Os valores absolutos permanecem aceitáveis, mas o próximo CI deve comparar em
runner dedicado antes de aceitar nova degradação. Benchmark não é SLA.

### Escalabilidade

Memory serve a teste/desenvolvimento. SQLite usa WAL, timeout, FKs, índices e
transações `IMMEDIATE`, adequado a uma instância ou baixa contenção. Produção
horizontal ainda exige adapter Postgres/Redis e teste multiprocesso.

### API pública, legibilidade e versionamento

- Value objects têm campos privados, construtores validados, serde validado e
  IDs tipados. `#[non_exhaustive]` protege enums evolutivos.
- Error codes `PERMISSION_DENIED` e `REALM_NOT_INITIALIZED` são estáveis; erros
  de credencial não revelam existência de usuário ou chave.
- API keys retornam bearer material uma vez; listagens expõem só metadados.
- Node preserva os mesmos casos de uso; WASM expõe somente parser client-safe.
- Migração SQLite v3 é explícita e `open` recusa schema incompatível.

### Bugs, leaks, race conditions e `unsafe`

Não foi identificado leak ou `unsafe` no código manual. Segredos Rust usam tipos
redigidos/zeroizáveis; JavaScript não garante zeroização. Foram cobertos race de
bootstrap, replay, cross-realm, scope excessivo, role removida, principal
desabilitado, rotação/grace, revogação e proteção do último owner.

## Evidências

- `cargo fmt --all -- --check`: passou.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passou.
- `cargo test --workspace --all-features`: 49 testes passaram.
- `cargo +1.88.0 check --workspace --all-targets`: MSRV passou.
- `cargo doc --workspace --all-features --no-deps`: passou.
- WASM `wasm32-unknown-unknown`: passou com feature client-only.
- `cargo audit --deny warnings`: 228 dependências, nenhum advisory.
- `cargo deny check`: advisories, bans, licenças e fontes passaram; duplicatas
  transitivas foram apenas warnings aceitos.
- Node release, TypeScript, smoke SQLite/IAM end-to-end e `npm audit`: passaram;
  zero vulnerabilidades reportadas.
- Cobertura filtrada de Authorization/Core/Crypto/MFA/Validation: 90,47% linhas.
- Fuzz IAM compilou. Execução local Windows falhou por DLL do libFuzzer ausente;
  CI Linux executa os três targets por 20 segundos.
- Mutation testing não foi executado porque `cargo-mutants` não está instalado.

## Riscos residuais e melhorias

| ID | Severidade | Estado | Risco / ação |
|---|---|---|---|
| SDK-011 | média | aceito | TOTP não é phishing-resistant. Implementar WebAuthn/passkeys em 0.4. |
| SDK-012 | média | host | RBAC genérico não resolve ownership/IDOR. Exigir policy de recurso no host após o grant. |
| SDK-013 | baixa | aberto | `AuthService` ainda agrega authentication e MFA. Separar fachadas internas sem quebrar atomicidade. |
| SDK-014 | baixa | aceito | SQLite não escala escrita horizontal. Criar adapter Postgres antes disso. |
| SDK-015 | baixa | CI | Runtime fuzz Windows indisponível; manter execução Linux e investigar redistribuível do libFuzzer. |
| SDK-016 | baixa | aberto | Executar mutation score e teste de kill durante commit em runner dedicado. |
| SDK-017 | baixa | observar | Baselines antigos regrediram no host local; confirmar em runner estável. |

Próxima etapa recomendada: 0.4 WebAuthn/passkeys e separação interna das fachadas,
antes de JWT/PASETO ou ABAC. Tokens opacos continuam mais simples de revogar.
