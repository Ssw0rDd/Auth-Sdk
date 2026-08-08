# Auditoria técnica 0.7 — baseline da evolução pública

- Data: 2026-08-08
- Baseline preservado: commit `9edcc2e`
- Escopo: 16 crates Rust, bindings Node/WASM, schemas v6, CI, supply chain e
  fluxos de identidade, sessão, recuperação, MFA, IAM e passkeys
- Resultado: nenhum achado crítico ou alto confirmado; um bloqueio moderado de
  portabilidade corrigido no caminho padrão

## Resumo de severidade

| Severidade | Confirmados | Estado |
|---|---:|---|
| Crítico | 0 | — |
| Alto | 0 | — |
| Moderado | 1 | corrigido e coberto por CI |
| Baixo/dívida | 5 | planejado para as fases seguintes |

Ausência de achado não equivale a certificação, prova formal ou garantia de que
não existam vulnerabilidades. O gate público ainda exige auditoria externa e a
matriz remota completa.

## Achado moderado corrigido

### A07-001 — workspace padrão exigia OpenSSL externo no Windows

**Reprodução anterior:** `cargo test --workspace --all-features` abortava em
`openssl-sys 0.9.117` antes dos testes porque não havia OpenSSL instalado.

**Causa:** `sdk-auth-node -> sdk-auth-webauthn -> webauthn-rs-core` possui uma
dependência obrigatória de OpenSSL. O CI instalava a biblioteca em todas as
plataformas e, por isso, não exercitava a experiência de instalação limpa.

**Correção:** o conjunto padrão agora contém os crates portáveis; WebAuthn e Node
continuam no workspace/gate nativo. Um job em três sistemas executa o caminho
padrão sem instalar bibliotecas externas. A decisão completa está no ADR 0007.

**Evidência:** `cargo test --all-features` passou localmente sem OpenSSL, Perl,
make ou compilador C, com 95 testes verdes.

## Fluxos revalidados

- Cadastro é atômico nos stores Memory, SQLite e PostgreSQL e possui unicidade
  `(realm_id, normalized_email)`; corrida não cria usuário duplicado.
- Login desconhecido usa verificação Argon2 falsa e compartilha erro público com
  senha incorreta.
- Refresh é single-use; replay revoga a sessão/família e gera evento.
- Password reset consome challenge, troca hash, revoga sessões e trusted devices
  na mesma unidade atômica.
- Email verification, TOTP, recovery code, trusted device e cerimônias passkey
  possuem TTL e consumo único.
- Realm participa de lookups e constraints de identidade/sessão/autorização.
- SQL usa parâmetros; código próprio proíbe `unsafe`, `unwrap`, `expect`, `panic`,
  `todo` e `unimplemented` pelos lints do workspace.

## Dívida de baixo risco

1. Os métodos de dispatch de reset/verificação retornam `Option` ao host. Isso é
   necessário para entrega, mas é um footgun de enumeração se uma integração
   refletir o valor ao cliente. O server kit/BFF deve sempre responder de forma
   genérica e manter o dispatch apenas no backend confiável.
2. O binding Node ainda é privado e não possui matriz de prebuilds assinados.
3. A listagem de API keys mantém a query N+1 documentada na auditoria 0.6.
4. Dependências upstream mantêm múltiplas versões transitivas; `cargo-deny`
   aprova a política, mas reporta warnings de duplicação.
5. Ainda faltam baselines persistidos de carga p50/p95/p99 e contenção.

## Gates executados

- `cargo test --all-features`: aprovado, 95 testes, 0 falhas.
- `cargo fmt --all -- --check`: aprovado.
- `cargo clippy --all-targets --all-features -- -D warnings`: aprovado.
- `cargo audit --deny warnings`: aprovado, 0 advisories no lockfile.
- `cargo deny check`: advisories, bans, licenses e sources aprovados.
- Scan local de segredos e chaves privadas: nenhum segredo confirmado.

## Limites desta auditoria

- O build nativo WebAuthn/Node não foi executado nesta máquina porque a toolchain
  OpenSSL não está instalada; ele permanece obrigatório na matriz nativa do CI.
- PostgreSQL/Redis reais não foram iniciados neste gate local; os contratos
  distribuídos permanecem condicionados aos jobs de serviço.
- Não houve pentest externo, OpenID conformance, análise formal nem auditoria de
  código de dependências de terceiros.
