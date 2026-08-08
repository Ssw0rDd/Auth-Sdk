# Auditoria técnica 0.1

Data: 2026-07-28. Escopo: código do workspace e dependências bloqueadas em
`Cargo.lock`/`package-lock.json`. Esta é uma revisão interna, não uma
certificação independente.

## Resultado

Nenhum achado crítico ou alto aberto. Todos os módulos atingiram o gate interno
de 9,5. A nota não significa ausência futura de vulnerabilidades.

| Crate | Arq. | Seg. | Perf. | Escala | Legib. | Baixo acopl. | Coesão | API | Bugs | Memória | `unsafe` | Dívida | Complex. | Testes/docs | Final |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `sdk-auth-error` | 9,8 | 9,7 | 9,8 | 9,8 | 9,8 | 9,9 | 9,9 | 9,7 | 9,7 | 9,9 | 10 | 9,6 | 9,9 | 9,7 | 9,8 |
| `sdk-auth-types` | 9,8 | 9,7 | 9,7 | 9,7 | 9,8 | 9,8 | 9,8 | 9,7 | 9,6 | 9,7 | 10 | 9,6 | 9,8 | 9,6 | 9,7 |
| `sdk-auth-validation` | 9,8 | 9,6 | 9,6 | 9,7 | 9,8 | 9,8 | 9,8 | 9,7 | 9,7 | 9,9 | 10 | 9,6 | 9,6 | 9,8 | 9,7 |
| `sdk-auth-crypto` | 9,8 | 9,8 | 9,6 | 9,7 | 9,8 | 9,8 | 9,9 | 9,7 | 9,7 | 9,7 | 10 | 9,6 | 9,7 | 9,8 | 9,7 |
| `sdk-auth-core` | 9,8 | 9,7 | 9,5 | 9,6 | 9,7 | 9,8 | 9,7 | 9,6 | 9,6 | 9,7 | 10 | 9,5 | 9,5 | 9,8 | 9,6 |
| `sdk-auth-memory` | 9,7 | 9,6 | 9,6 | 9,5 | 9,7 | 9,7 | 9,8 | 9,6 | 9,6 | 9,7 | 10 | 9,6 | 9,6 | 9,7 | 9,6 |
| `sdk-auth-sqlite` | 9,7 | 9,7 | 9,5 | 9,5 | 9,6 | 9,7 | 9,7 | 9,6 | 9,6 | 9,7 | 10 | 9,5 | 9,5 | 9,7 | 9,6 |
| `sdk-auth-testing` | 9,7 | 9,6 | 9,6 | 9,6 | 9,8 | 9,8 | 9,8 | 9,6 | 9,7 | 9,8 | 10 | 9,6 | 9,7 | 9,8 | 9,7 |
| `sdk-auth-node` | 9,6 | 9,5 | 9,5 | 9,5 | 9,7 | 9,6 | 9,7 | 9,5 | 9,5 | 9,5 | 9,5 | 9,5 | 9,6 | 9,6 | 9,5 |
| `sdk-auth-wasm` | 9,8 | 9,8 | 9,8 | 9,8 | 9,8 | 9,8 | 9,9 | 9,7 | 9,7 | 9,9 | 10 | 9,6 | 9,9 | 9,6 | 9,8 |

`Bugs` e `Memória` medem prevenção/risco residual: nota maior significa risco
menor. O crate Node não herda `unsafe_code = "forbid"` porque macros N-API geram
FFI; o código manual não contém bloco `unsafe`.

## Revisão por módulo

- `error`: códigos estáveis, contexto sanitizado e snapshot da forma pública.
  Melhoria: política formal de evolução de códigos antes de publicação.
- `types`: newtypes por realm, UUIDv7 e redaction de segredos. Limite: cópias
  feitas por runtimes externos não podem ser zeroizadas por Rust.
- `validation`: traits síncrona/assíncrona, formatos compostos e limites de
  regex/URL. CPF/CNPJ validam estrutura; não comprovam identidade.
- `crypto`: Argon2id com piso de 19 MiB, `t=2`, `p=1`; tokens de 256 bits via
  `OsRng`; BLAKE3 e comparação constante. Parâmetros devem ser recalibrados no
  hardware de produção.
- `core`: casos de uso e transições no domínio; sem dependência de DB/HTTP/FFI.
  Spans `tracing` não incluem argumentos sensíveis. A complexidade principal
  está em rotação/revogação e merece mutation testing.
- `memory`: adapter atômico para testes/desenvolvimento; não é storage de
  produção, não é multiprocesso e perde dados ao reiniciar.
- `sqlite`: SQL parametrizado, foreign keys, WAL, timeout e transações
  `IMMEDIATE`. SQLite é adequado para instância única/baixo write contention;
  escala horizontal exige outro adapter.
- `testing`: relógio determinístico e contrato comum para Memory/SQLite. Faltam
  testes de caos de disco e kill durante commit.
- `node`: binding fino e smoke test ponta a ponta. Strings JavaScript não têm
  zeroização garantida; o host deve evitar logs, dumps e retenção de referências.
- `wasm`: apenas validação client-safe; hashing, sessão e segredos server-side
  não são exportados.

## Achados residuais

| ID | Severidade | Estado | Risco e decisão |
|---|---|---|---|
| SDK-001 | baixa | aceito em 0.1 | Limite por conta reduz brute force, mas pode causar lockout temporário dirigido. Combinar com escopo de rede e mitigação no host. |
| SDK-002 | baixa | aceito em 0.1 | Token de email/reset é entregue diretamente ao host confiável; o outbox é deliberadamente livre de segredo. Falha de envio exige emitir novo desafio. |
| SDK-003 | informativa | documentado | Segredos recebidos como `string` no Node podem sobreviver no heap JS mesmo após a cópia Rust ser zeroizada. |
| SDK-004 | informativa | roadmap | Não há garantia FIPS, HSM, RBAC, MFA, API keys, Postgres/Redis ou bindings Java/.NET/Python no 0.1. |

## Evidências executadas

- `cargo +1.88.0 check --workspace --all-targets`: passou; MSRV validada.
- `cargo fmt --all -- --check`: passou.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passou.
- `cargo test --workspace --all-features`: 28 testes passaram.
- `cargo doc --workspace --no-deps`: passou com documentação pública obrigatória.
- `cargo audit --deny warnings`: 209 dependências, sem advisory.
- `cargo deny check`: advisories, bans, licenças e fontes passaram; há duplicatas
  transitivas de `cpufeatures`, `getrandom` e `syn`, sem falha do gate.
- `cargo check -p sdk-auth-wasm --target wasm32-unknown-unknown`: passou.
- `npm ci`, `npm run build`, `npm test`, `npm audit`: passaram; zero
  vulnerabilidades reportadas.
- cobertura filtrada para core/crypto/validation: 98,14% das linhas e 96,05%
  das regiões.
- smoke Node: registro, verificação, login, validação e logout usando SQLite real.

## Benchmark local

Windows x86_64, build release, Criterion; números servem como baseline local,
não como SLA:

- digest BLAKE3 de token opaco: 104,49–108,08 ns;
- política de senha: 170,77–179,43 ns;
- hash Argon2id recomendado: 35,141–36,732 ms.

Para `error`, `types`, adapters, testing, Node e WASM, o esperado é overhead fino
frente a serialização, SQLite ou FFI. Antes de produção devem ser adicionados
benchmarks concorrentes por adapter e hardware-alvo, com tendência no CI.
