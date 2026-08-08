# Auditoria técnica 0.2

Data: 2026-07-28. Escopo: workspace, lockfiles, binding Node, migrações e fluxos
MFA. Revisão interna; não é certificação ou pentest independente.

## Resultado

Nenhum achado crítico ou alto permaneceu aberto. Todos os crates atingiram o
gate interno mínimo de 9,5. A nota mede o estado revisado, não invulnerabilidade.

| Crate | Arq. | Seg. | Perf. | Escala | Legib. | Acopl. | Coesão | API | Bugs/memória | Testes/docs | Final |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `sdk-auth-error` | 9,8 | 9,7 | 9,8 | 9,8 | 9,8 | 9,9 | 9,9 | 9,7 | 9,8 | 9,7 | 9,8 |
| `sdk-auth-types` | 9,8 | 9,7 | 9,7 | 9,7 | 9,8 | 9,8 | 9,8 | 9,6 | 9,7 | 9,6 | 9,7 |
| `sdk-auth-validation` | 9,8 | 9,6 | 9,6 | 9,7 | 9,8 | 9,8 | 9,8 | 9,7 | 9,8 | 9,8 | 9,7 |
| `sdk-auth-crypto` | 9,8 | 9,8 | 9,6 | 9,7 | 9,8 | 9,8 | 9,9 | 9,7 | 9,7 | 9,8 | 9,7 |
| `sdk-auth-mfa` | 9,8 | 9,8 | 9,7 | 9,8 | 9,8 | 9,8 | 9,9 | 9,7 | 9,8 | 9,8 | 9,8 |
| `sdk-auth-core` | 9,7 | 9,7 | 9,5 | 9,6 | 9,6 | 9,8 | 9,7 | 9,5 | 9,6 | 9,7 | 9,6 |
| `sdk-auth-memory` | 9,7 | 9,6 | 9,6 | 9,5 | 9,7 | 9,7 | 9,8 | 9,6 | 9,7 | 9,7 | 9,6 |
| `sdk-auth-sqlite` | 9,7 | 9,7 | 9,5 | 9,5 | 9,6 | 9,7 | 9,7 | 9,6 | 9,7 | 9,8 | 9,6 |
| `sdk-auth-testing` | 9,7 | 9,7 | 9,6 | 9,6 | 9,7 | 9,8 | 9,8 | 9,6 | 9,8 | 9,8 | 9,7 |
| `sdk-auth-node` | 9,6 | 9,5 | 9,5 | 9,5 | 9,7 | 9,6 | 9,7 | 9,5 | 9,5 | 9,7 | 9,5 |
| `sdk-auth-wasm` | 9,8 | 9,8 | 9,8 | 9,8 | 9,8 | 9,8 | 9,9 | 9,7 | 9,9 | 9,6 | 9,8 |

`Bugs/memória` mede prevenção e risco residual: nota maior significa risco menor.

## Revisão obrigatória

### Arquitetura, acoplamento e coesão

- Core não depende de storage, runtime ou FFI.
- `AuthStore` compõe traits segregadas de identidade, sessão, challenge, rate
  limit, evento e MFA.
- `sdk-auth-mfa` contém somente primitivas; orquestração permanece no Core.
- Node e WASM traduzem tipos sem regra de negócio.
- Não há ciclo entre crates.

Dívida: `AuthService` concentra muitos casos de uso em um arquivo. A coesão ainda
é de aplicação, mas 0.3 deve separar serviços de autenticação, MFA e autorização
sem fragmentar as transações.

### Segurança

- Argon2id para senha; tokens de 256 bits via `OsRng`.
- XChaCha20-Poly1305 para seed TOTP, nonce de 192 bits, AAD contextual e key ID.
- TOTP HMAC-SHA1 somente por interoperabilidade RFC 6238, counter monotônico.
- Recovery codes de 80 bits e trusted tokens persistidos somente por digest.
- Sem sessão antes de MFA; email não é bypass; password reset preserva o fator.
- Consumo, rotação, replay e criação de sessão são atômicos.
- Rate limits separados para login, reautenticação, enrollment e gestão MFA.
- Erros não revelam existência de conta ou estado interno de storage/crypto.

Mapeamento principal: OWASP ASVS V2/V3, OWASP Top 10 A01/A02/A03/A04/A07/A09,
CWE-287, CWE-307, CWE-327, CWE-330, CWE-384, CWE-613 e NIST SP 800-63B.

### Performance e benchmark esperado

O caminho caro intencional é Argon2id. TOTP e abertura do vault ficam em
microssegundos; SQLite/FFI dominam os adapters. Baseline local Windows x86_64:

- BLAKE3 de token: 102,60–104,11 ns;
- policy de senha: 185,82–195,90 ns;
- Argon2id recomendado: 37,003–38,559 ms;
- verificação TOTP com janela ±1: 2,9768–3,2195 µs;
- normalização de recovery code: 276,17–298,04 ns;
- abertura XChaCha20-Poly1305: 2,3941–2,4307 µs.

O aumento observado no microbenchmark da policy de senha não é material em valor
absoluto, mas deve continuar sendo acompanhado no CI. Benchmark não é SLA.

### Escalabilidade

Memory é apenas teste/desenvolvimento. SQLite usa WAL, timeout e transações
`IMMEDIATE`, adequado a uma instância ou baixa contenção de escrita. Produção
horizontal exige adapter Postgres/Redis com o mesmo contrato atômico.

### API pública e legibilidade

- `LoginOutcome` e a união TypeScript impedem interpretação ambígua.
- Segredos possuem tipos redigidos; Node expõe material de chave como
  `Uint8Array`, não string.
- Migração SQLite é explícita e idempotente; `open` recusa drift.
- Todos os itens públicos passam `missing_docs = deny` e rustdoc.

Breaking changes são aceitáveis porque os pacotes continuam privados. Antes de
publicar, revisar nomes dos comandos, uso de `Box` em outcomes e estabilidade de
error codes.

### Bugs, memory leaks e `unsafe`

Não foi identificado leak ou bloco `unsafe` no código manual. `Zeroizing` cobre
senhas, seeds e key material no Rust; ciphertext e digests não são secretos em
texto. O runtime JavaScript pode manter cópias e não oferece zeroização forte.
Macros N-API geram a fronteira FFI fora do controle do código manual.

Foram testados replay concorrente, realm isolation, expiração, rewrap, reset,
replacement, regeneration, revogação, migração legada e paridade Memory/SQLite.

## Evidências

- `cargo fmt --all -- --check`: passou.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passou.
- `cargo test --workspace --all-features`: 40 testes passaram.
- `cargo +1.88.0 check --workspace --all-targets`: MSRV passou.
- `cargo doc --workspace --all-features --no-deps`: passou.
- WASM `wasm32-unknown-unknown`: passou.
- `cargo audit --deny warnings`: 227 dependências, nenhum advisory.
- `cargo deny check`: advisories, bans, licenças e fontes passaram; duplicatas
  transitivas permanecem como warning aceito.
- Node release, TypeScript, smoke SQLite e `npm audit`: passaram, zero
  vulnerabilidades reportadas.
- Cobertura filtrada de Core/Crypto/MFA/Validation: 93,05% das linhas e 90,42%
  das regiões.
- Dois fuzz targets compilam em nightly; execução contínua roda no CI Linux.
  Execução local Windows não iniciou por DLL do libFuzzer ausente.

## Riscos residuais e melhorias

| ID | Severidade | Estado | Risco / ação |
|---|---|---|---|
| SDK-005 | média | aceito | TOTP é phishing-prone. Priorizar WebAuthn/passkeys em 0.4. |
| SDK-006 | média | host | Perda/compromisso do keyring afeta fatores. Integrar secret manager/HSM, backup e runbook de rotação. |
| SDK-007 | baixa | aceito | SQLite limita write scale. Criar adapter Postgres antes de escalar horizontalmente. |
| SDK-008 | baixa | host | Strings/buffers JS podem sobreviver no heap. Evitar logs, dumps e referências longas. |
| SDK-009 | baixa | CI | Fuzz runtime foi bloqueado localmente por DLL; CI Linux executa ambos os targets a cada mudança. |
| SDK-010 | informativa | aberto | Mutation testing e teste de kill durante commit ainda não foram executados. |

Próxima auditoria deve incluir pentest independente, mutation score, stress
multiprocesso SQLite e teste de recuperação de key rotation.
