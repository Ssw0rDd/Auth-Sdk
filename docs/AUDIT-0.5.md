# Auditoria técnica 0.5 — WebAuthn/passkeys

- Data: 2026-07-29
- Escopo: Core WebAuthn, adapter `webauthn-rs`, Memory, SQLite v5, Node, CI e documentação
- Resultado: aprovado para continuar privado; publicação pública ainda bloqueada por auditoria externa
- Nota final: **9,5/10**

## Resultado por critério

| Critério | Nota | Evidência e limite |
|---|---:|---|
| Arquitetura | 9,7 | Porta no Core, adapter isolado, composition root explícito, sem tipos upstream na API |
| Segurança | 9,6 | UV obrigatória, origin/RP binding, estado server-side, uso único, limites e commit atômico |
| Performance | 9,5 | Fluxos limitados; start registration medido em 3,79–3,89 µs localmente |
| Escalabilidade | 9,5 | Contratos assíncronos e stateless no Core; SQLite continua single-writer |
| Legibilidade | 9,5 | Tipos e resultados explícitos; módulo Core WebAuthn já é grande |
| Acoplamento | 9,8 | Core depende somente de ports; OpenSSL e `webauthn-rs` ficam no adapter |
| Coesão | 9,6 | Cerimônias, credenciais e gestão formam uma capability única |
| API pública | 9,6 | Capability opcional, erros estáveis, envelopes versionados e enum não exaustivo |
| Bugs e concorrência | 9,6 | Replay, clone, rename/revoke e stores Memory/SQLite exercitados pelo mesmo contrato |
| Memória e leaks | 9,6 | Campos limitados e cerimônias expiradas removidas; nenhuma retenção permanente conhecida |
| `unsafe` | 9,8 | Zero `unsafe` próprio fora da fronteira N-API gerada; dependências nativas permanecem externas |
| Dívida técnica | 9,5 | E2E com navegador real, discoverable credentials e decomposição física foram adiados |
| Complexidade | 9,5 | Estado protocolar inevitável, protegido por tipos e transições explícitas |
| Testes e documentação | 9,6 | 60 testes, coverage security-critical 91,17%, rustdoc, ADR e threat model |

Não há achado crítico ou alto aberto. A nota não declara invulnerabilidade nem
substitui auditoria criptográfica independente.

## Arquitetura e API

- `WebAuthnEngine` é a porta criptográfica transport-neutral. O Core nunca
  conhece `webauthn-rs`, navegador, HTTP, Node ou banco concreto.
- `PasskeyService` contém regras de negócio: proof de gestão, limites, binding
  de realm/user/session, TTL, replay, assurance e política de clone.
- `PasskeyStore` exige conclusões atômicas. Login só cria sessão quando consumo
  da cerimônia, atualização da credencial e gravação de estado têm sucesso.
- `SdkAuthBuilder` aceita store e engine juntos ou falha fechado. Desabilitar a
  capability não altera fluxos existentes.
- Credential/state possuem `provider_id` e versão. Mudança incompatível exige
  migração explícita; deserialize oportunista é proibido.
- API Node traduz apenas DTOs e erros. O JSON WebAuthn precisa da conversão
  binária padrão do browser; a SDK não finge que JSON é o tipo nativo da Web API.

Dependências proibidas continuam respeitadas: Core não depende de SQLite,
Memory, N-API, WASM, OpenSSL ou `webauthn-rs`; stores não contêm regra de IAM ou
de protocolo; bindings não decidem assurance, replay ou autorização.

## Segurança

Controles implementados:

- user verification `required`; passkey produz AAL2, não AAL3;
- attestation `none`, evitando uma alegação falsa de hardware provenance;
- allow-list de origins exatas, sem wildcard, subdomínio ou porta implícita;
- RP ID por realm e configuração imutável durante a vida da credencial;
- estado da cerimônia somente no servidor; cliente recebe handle aleatório de
  256 bits e o banco persiste apenas seu digest;
- TTL de cinco minutos, máximo de cinco falhas e tamanhos limitados;
- registro preso à mesma sessão, realm e usuário que autorizaram o begin;
- credential ID globalmente único;
- counter positivo precisa crescer. Regressão revoga a passkey, nega a sessão e
  grava `PasskeyCloneSuspected` atomicamente;
- password reset preserva passkeys/MFA, mas revoga sessões e trusted devices;
- email não cria sessão, não satisfaz MFA e não autoriza gestão de autenticador;
- logs `Debug` redigem credential IDs, blobs, options e ceremony state;
- cerimônias expiradas são coletadas ao criar novos challenges, impedindo
  crescimento permanente dos stores.

Threats cobertas: spoofing, tampering, replay, credential stuffing, brute force,
session fixation/hijacking, IDOR cross-realm, race de uso único, SQL injection,
DoS por payload, authenticator clone signal e privilege escalation na gestão.
TLS, cookies, CSRF, CORS, CSP, WAF, rate limit distribuído e secret management
continuam responsabilidade do host.

## Persistência e concorrência

- SQLite schema v5 separa credentials e ceremonies, usa foreign keys, índices e
  queries parametrizadas.
- Mutações sensíveis usam transações `IMMEDIATE`; Memory usa uma única seção
  crítica por transição.
- Replay concorrente produz no máximo uma conclusão bem-sucedida.
- Cerimônias consumidas permanecem até expirar para distinguir replay; depois
  são removidas oportunisticamente.
- SQLite é adequado a processo único e baixa/média concorrência. Multi-instância
  e alta escrita exigem PostgreSQL/Redis na fase 0.6, sem fingir que pooling
  transforma SQLite em store distribuído.

## Performance

O benchmark Criterion `webauthn_start_passkey_registration`, executado localmente
com 10 amostras e janela de um segundo, mediu **3,7899–3,8943 µs**. Isso mede
apenas criação/serialização inicial do challenge; não inclui rede, navegador,
authenticator, persistência ou finish criptográfico. É baseline de tendência,
não SLO portátil.

Custos dominantes continuam sendo Argon2id, I/O do store e round-trip do
authenticator. Clones de blobs são limitados e necessários para atravessar a
porta provider-owned. Otimização zero-allocation agressiva aqui aumentaria
acoplamento e risco por ganho irrelevante frente à latência externa.

## Evidências executadas

- `cargo fmt --all -- --check`: passou.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passou.
- `cargo test --workspace --all-features`: **60 testes passaram**.
- `cargo +1.88.0 check --workspace --all-targets`: MSRV passou.
- `cargo doc --workspace --no-deps` com rustdoc warnings negados: passou.
- `cargo check -p sdk-auth-wasm --target wasm32-unknown-unknown`: passou.
- Node N-API release build e smoke SQLite/WebAuthn: passaram.
- `npm audit --audit-level=high`: zero vulnerabilidades.
- `cargo audit --deny warnings`: 264 dependências, nenhum advisory.
- `cargo deny check`: advisories, bans, licenses e sources passaram; duplicações
  transitivas foram reportadas como warning.
- Coverage da lógica própria security-critical: **91,17% de linhas**.
- Coverage de `sdk-auth-core/src/webauthn.rs`: **93,35% de linhas**.
- `cargo +nightly fuzz build webauthn_response`: passou.
- Runtime de fuzz local Windows: bloqueado por
  `STATUS_DLL_NOT_FOUND` do runtime ASan. O job Linux executa 20 segundos por
  target; o runtime local não é reportado como sucesso.
- Benchmark WebAuthn Criterion: passou; baseline acima registrada.

## Riscos residuais e dívida

1. **Username-first:** a etapa begin pode revelar diferença entre conta
   inexistente, sem passkey ou com passkey. Mensagem genérica e rate limit local
   reduzem abuso, mas usernameless/conditional UI é a correção estrutural futura.
2. **OpenSSL:** amplia supply chain, tempo de build e obrigação de patching. A
   dependência fica confinada ao adapter e é verificada por audit/deny.
3. **E2E real:** não há teste automatizado com browser e virtual authenticator.
   O contrato usa engine determinística; o adapter testa configuração e begin,
   enquanto verificação protocolar é propriedade upstream.
4. **Arquivos grandes:** Core WebAuthn e stores concretos cresceram. Separação
   interna por registration/authentication/management melhorará review, desde
   que não fragmente as transações.
5. **Duplicações transitivas:** `webauthn-rs` traz versões paralelas de crates
   criptográficas/serde auxiliares. Não são vulneráveis hoje, mas aumentam
   superfície de atualização.
6. **BLAKE3 legado:** digests de handles/tokens não usam chave. Entropia de 256
   bits impede preimage prático; uma migração futura para HMAC deve ser
   versionada e dual-read.

## Decisões difíceis de reverter

- RP ID: alterá-lo invalida credenciais existentes.
- Formatos persistidos e `provider_id`: exigem estratégia de migração.
- Schema SQLite v5: binário 0.4 não é reader/writer compatível.
- Semântica de assurance AAL2 e códigos públicos de erro: consumidores podem
  persistir políticas e métricas baseadas nesses valores.

## Adiado conscientemente

- 0.6+: virtual-authenticator E2E, PostgreSQL, Redis e rate limit distribuído.
- Depois: discoverable credentials, conditional UI e usernameless login.
- Somente com requisito concreto: enterprise attestation e política de modelo
  de authenticator.
- Não aprovado: magic-link como autenticador, presence-only passkeys, estado de
  cerimônia no cliente e implementação criptográfica própria.

## Referências primárias

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [Android passkeys](https://developer.android.com/identity/passkeys/create-passkeys)
- [Apple passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)
- [`webauthn-rs` documentation](https://docs.rs/webauthn-rs/latest/webauthn_rs/)
