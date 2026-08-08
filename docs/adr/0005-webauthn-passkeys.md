# ADR 0005: WebAuthn/passkeys e recovery boundary

- Status: accepted
- Date: 2026-07-29
- Release: 0.5.0

## Contexto

A SDK precisa de autenticação phishing-resistant sem mover regras para Node,
browser ou frameworks. WebAuthn é protocolar e criptograficamente complexo;
implementação própria criaria risco de challenge, origin, RP ID, UV, parsing
CBOR/COSE e signature validation incorretos. O roadmap também previa magic link,
mas email não é um autenticador adequado para a garantia declarada.

## Decisão

1. O Core define `WebAuthnEngine`, `PasskeyStore` e `PasskeyService`; nenhum tipo
   upstream entra na API pública.
2. `sdk-auth-webauthn` implementa a porta com `webauthn-rs` 0.5.5. A dependência
   MPL-2.0 e OpenSSL são explícitas; código próprio permanece MIT/Apache-2.0.
3. Cada realm possui RP ID imutável, nome e allow-list de origens exatas. Não são
   ativados subdomínios, porta arbitrária, presence-only keys ou workaround de
   vendor.
4. HTTPS é obrigatório como origem base. Android pode adicionar
   `android:apk-key-hash:<SHA-256-base64url>` exato por signing certificate.
5. Passkey usa user verification `required` e attestation `none`.
6. Login 0.5 é username-first. Conditional UI, discoverable/usernameless login e
   enterprise attestation ficam adiados.
7. Estado de registration/authentication é serializado apenas para persistence
   server-side. O cliente recebe um handle aleatório de 256 bits; somente o
   digest é persistido. Estado, credential blob e JSON possuem limites.
8. Estado e credentials carregam `provider_id` e versão. Incompatibilidade falha
   fechada e exige migração explícita.
9. Registro exige access token e prova fresca. Sessão passkey UV recente é
   aceita; caso contrário senha atual e segundo fator existente são exigidos.
   Finish precisa da mesma sessão, realm e usuário que iniciaram a cerimônia.
10. Credential ID é globalmente único. Múltiplas passkeys são permitidas até o
    limite configurado; label é apenas metadata.
11. Login cria sessão opaca somente na mesma transação que consome a cerimônia e
    atualiza a credencial. Counter positivo precisa aumentar. Anomalia revoga a
    passkey, grava audit denied e retorna `AUTHENTICATOR_COMPROMISED`.
12. Sessão passkey é classificada como AAL2, phishing-resistant e user-verified.
    A SDK não afirma AAL3 sem attestation/hardware policy verificável.
13. Password reset preserva MFA e passkeys, mas revoga sessões e trusted devices.
    Email nunca cria sessão, satisfaz MFA ou autoriza gestão de passkeys.

## Consequências

- O adapter WebAuthn possui dependência nativa OpenSSL. Build e deploy precisam
  das development/runtime libraries e patching operacional.
- Build release inicial é mais lento e supply-chain maior.
- Username-first permite diferenças observáveis na etapa de descoberta. Erros
  permanecem genéricos e o host deve aplicar rate limit global; eliminação desse
  sinal depende do fluxo discoverable futuro.
- RP ID alterado invalida credenciais. Mudança exige novo realm ou migração
  planejada, nunca edição silenciosa.
- Rollback funcional desativa a capability no composition root sem apagar as
  tabelas v5. Binário 0.4 não abre schema v5; rollback binário exige restaurar o
  backup pré-migração ou publicar patch compatível.

## Alternativas rejeitadas

- Implementar WebAuthn manualmente: risco e custo de auditoria inaceitáveis.
- Biblioteca RP recente apenas para evitar MPL/OpenSSL: maturidade insuficiente.
- Magic-link login: reduziria assurance ao comprometimento do email.
- JWT/PASETO para ceremony state no cliente: amplia replay, key rotation e
  exposição; estado server-side é obrigatório.
- Attestation obrigatória: prejudica privacidade e compatibilidade sem requisito
  enterprise concreto.
