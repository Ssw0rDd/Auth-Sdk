# Roadmap

## Entregue

- `0.1`: autenticação essencial, tokens opacos, sessões por realm, SQLite,
  Node.js e WebAssembly client-safe.
- `0.2`: TOTP, recovery codes, trusted devices, vault versionado e migrações
  SQLite explícitas.
- `0.3`: API keys restritas, service accounts, catálogo de permissões, RBAC
  exato, IAM com step-up e autorização credential-bound.
- `0.4`: facades por capacidade, assurance, `CryptoProvider`, sealed records
  versionados, journal atômico, audit log separado e schema SQLite v4.
- `0.5`: WebAuthn/passkeys UV-required, estado server-side, origens exatas,
  detecção de counter anômalo, recovery policy e schema SQLite v5.
- `0.6`: PostgreSQL 16–18, Redis 7/8 complementar, pooling, rate limit distribuído,
  outbox leased, SQLite v6, migração offline e factory Node assíncrona.
- `0.7-alpha`: identidade federada issuer/subject sem auto-link, schema v7,
  Google/GitHub/Microsoft, binding OAuth Rustls portátil, BFF token-blind, MFA e
  passkey browser, UI Lit/React e stores BFF AEAD.

## Entrega atual 0.7

- Magic link de login foi rejeitado: email permanece apenas como verificação e
  recuperação e nunca cria sessão nem satisfaz step-up.
- A fase alpha permanece não publicável até prebuilds N-API assinados,
  conformance remota dos providers e auditoria externa independente.

## Próximas etapas aprovadas

- `0.8`: home region por realm, Realm/Organization/Membership, groups planos,
  autorização por recurso e
  adapters OpenFGA/SpiceDB.
- `0.9`: OAuth/OIDC client, resource server, perfil JWT estrito e kit de servidor
  transport-neutral. Authorization Server/OP continua experimental.
- `1.0`: Python/UniFFI, facade blocking, conformance e auditoria externa.

## Versão 2.0

Authorization Server/OpenID Provider estável, SAML, active-active multi-region,
delegação avançada e novas ABIs somente após demanda comprovada.
