# Implementação do plano 0.7

- Data: 2026-08-08
- Estado: alpha completo no repositório; publicação ainda bloqueada
- Baseline preservado: `9edcc2e`

## Fase 1 — debug e arquitetura

- Auditados Core, ports, stores Memory/SQLite/PostgreSQL/Redis, migrations,
  Node/Wasm, WebAuthn, IAM, CI e supply chain.
- Corrigido o default workspace que arrastava OpenSSL/WebAuthn para o caminho
  portátil (A07-001).
- Formalizado o domínio `User` + múltiplos autenticadores, em vez de usuários
  locais/sociais duplicados.
- Findings e limites estão em [AUDIT-0.7](AUDIT-0.7.md), [threat
  model](THREAT_MODEL.md) e ADRs 0007–0010.

## Fase 2 — implementação e fixes

- Identidade federada `(realm, issuer, subject)` e constraint única; email
  verificado é somente candidato a link.
- Primeiro login federado grava usuário sem senha, identidade, sessão, audit e
  outbox atomicamente; login repetido funciona mesmo sem email posterior.
- Link explícito exige sessão local e prova fresca. Nenhum auto-link por email.
- Google OIDC, Microsoft pessoal/Hotmail, Microsoft tenant e GitHub OAuth com
  Authorization Code, PKCE S256, state, nonce e validação protocolar.
- Binding OAuth Node Rustls separado; WebAuthn virou feature opcional no binding
  principal.
- BFF/browser suportam senha, MFA, OAuth, link, passkey, sessão renovável e
  logout sem expor tokens.
- Binding Node ganhou email/assurance e inspeção pública allowlisted.

## Fase 3 — UI/design

- `<sdk-auth-login>` e `<sdk-auth-challenge>` em Lit, wrappers React e
  controllers token-blind.
- Tema forge vermelho/preto, Syne + Manrope + IBM Plex Mono, motion reduzível,
  forced colors, layout desktop/mobile, foco/alertas e sem segredo em estado
  reativo/markup.
- Login por Google/GitHub/Microsoft, senha, passkey opcional, remember-me, TOTP e
  recovery code.
- Build minificado sem sourcemaps publicáveis; demo local cobre login e challenge.

## Fase 4 — melhorias

- Removido N+1 de `list_api_keys` em SQLite/PostgreSQL com uma query ordenada.
- Refresh rotation é persistida pelo BFF; inspeção/logout são serializados por
  sessão para impedir falso replay concorrente (A07-003).
- Stores BFF AEAD usam AES-256-GCM, nonce aleatório, keyring, AAD contextual,
  TTL e primitives atômicas. Adapter Redis usa NX/PXAT, GETDEL e lease com
  compare-and-delete.
- CI agora separa caminho Rust portátil, matriz nativa, TypeScript/UI/pentest,
  supply chain, fuzz e builds sem source maps.

## Fase 5 — debug pós-mudanças

- Rust: fmt, Clippy `-D warnings`, testes portáteis e contratos aprovados.
- TypeScript: BFF 20, browser 11 e UI 11 testes; typecheck e build aprovados.
- Supply chain: npm sem vulnerabilidades; cargo-deny aprovado; RUSTSEC-2023-0071
  é a única exceção, restrita e revisável (RISK-001).
- Scan de secrets e artefatos publicáveis sem ocorrências; dist sem `.map`.
- A criptografia cobre TLS sob responsabilidade do host, secrets do Core com
  XChaCha20-Poly1305 e estado BFF com AES-256-GCM. Isso não é uma alegação de
  certificação formal ou “invulnerabilidade”.

## Fase 6 — código público e secrets

- ADR 0010 rejeita a promessa impossível de esconder JavaScript/open source.
- Nenhum secret é compilado no frontend, Wasm ou binário distribuído.
- Source/declaration maps não são publicados; bundles são minificados.
- CSP/SRI/TLS são controles de entrega; decisões permanecem server-side.
- Criptografia própria/blockchain foi rejeitada em favor de AEAD padronizada.

## Fase 7 — pentest controlado

- [`security/pentest`](../security/pentest/README.md) contém harness isolado com
  9 ataques automatizados contra CSRF, cookies duplicados, parser/body, paths
  ambíguos e exfiltração de secrets.
- Unit/contract tests adicionais cobrem OAuth replay/mix-up, issuer mismatch,
  PKCE, link, MFA, passkey, ciphertext tamper/context swap e refresh concorrente.
- Fuzz targets Rust permanecem para validação, MFA, IAM e WebAuthn.

## Fase 8 — documentação e integração

- Arquitetura, threat model, security policy, contexto de domínio e ADRs
  atualizados.
- OpenAPI 3.1 token-blind em [`docs/openapi/bff.yaml`](openapi/bff.yaml).
- Guias Node/TypeScript, browser/React e Rust/Python/Go/Java em
  [`docs/integrations`](integrations).
- Hosts sem binding nativo usam sidecar same-origin; Python/UniFFI continua
  explicitamente planejado para 1.0, não anunciado como pronto.

## Bloqueios para publicação estável

1. auditoria externa independente e pentest de ambiente real;
2. conformance remota Google/Microsoft/GitHub e rotação/revogação real;
3. prebuilds N-API assinados, checksums, provenance/SBOM e matriz de instalação;
4. testes reais PostgreSQL/Redis nos jobs de serviço e benchmark p50/p95/p99;
5. remoção de RISK-001 assim que `rsa` publicar correção.

Esses itens não invalidam o alpha implementado, mas impedem chamar a release de
“perfeita”, certificada ou pronta para produção crítica.
