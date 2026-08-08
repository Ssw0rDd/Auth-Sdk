# ADR 0008 — Identidade federada e vínculo de contas

- Status: aceito
- Release: 0.7.0
- Data: 2026-08-08

## Contexto

Google, GitHub e Microsoft expõem atributos humanos mutáveis junto com um
identificador durável. Usar e-mail, username ou UPN como chave de login externo
duplica usuários quando o atributo muda e pode tomar uma conta quando o atributo
é reciclado. Vincular automaticamente um subject externo a uma conta local que
possua o mesmo e-mail transforma a confiança do provedor em bypass do
autenticador e MFA já configurados no realm.

O usuário da SDK precisa continuar sendo o subject estável do realm. Senha,
passkey e identidades externas são autenticadores associados, não classes de
usuário diferentes.

## Decisão

- A chave federada é `(realm_id, issuer HTTPS exato, subject durável)`.
- `provider_id` escolhe configuração e telemetria; não substitui o issuer.
- E-mail só participa da descoberta quando o adapter verificou a afirmação de
  ownership. Nunca autentica e nunca cria vínculo automático.
- Se o e-mail verificado encontra conta existente, a SDK persiste challenge
  aleatório de uso único e exige sessão ativa mais prova fresca do autenticador
  da conta. MFA continua obrigatório quando estiver habilitado.
- Se não existe conta nem vínculo e registro federado está habilitado, usuário,
  identidade, sessão, audit e outbox são criados na mesma transação.
- Usuário criado por provedor começa sem `password_hash`. Reset/estabelecimento
  posterior de senha pode adicionar a credencial local sem trocar `user_id`.
- Corridas de primeiro login são resolvidas pelas constraints de e-mail e
  issuer/subject. O perdedor relê o estado e autentica ou inicia link; não cria
  uma segunda conta.
- Sessão federada é classificada conservadoramente como AAL1. A SDK não promove
  `acr`, MFA ou phishing resistance do provedor sem um profile explícito e
  verificável.
- Subject e e-mail são redigidos em `Debug`; tokens e secrets continuam fora de
  audit, outbox e tracing.

## Identificadores por adapter

- Google OIDC: issuer validado + `sub`; `email` é atributo mutável.
- GitHub: authority fixa `https://github.com` + `id` numérico retornado por
  `GET /user`; `login` e e-mail não são subject.
- Microsoft OIDC: issuer validado e tenant-bound + `sub` para isolamento por
  cliente. Um profile futuro multi-app pode usar `tid + oid` conscientemente,
  nunca e-mail, UPN ou `preferred_username`.

## Invariantes

1. Uma identidade externa ativa pertence a no máximo um usuário por realm.
2. Um e-mail normalizado pertence a no máximo um usuário por realm.
3. Alteração de e-mail/username no provedor não altera o vínculo existente.
4. E-mail igual sem issuer/subject conhecido nunca cria sessão da conta local.
5. Criação federada e primeira sessão são all-or-nothing.
6. Challenge de link expira, é single-use, pertence a um usuário e persiste só
   o digest do bearer.
7. Conta sem senha executa fake verification e retorna o mesmo erro público de
   credencial inválida de uma conta desconhecida.

## Alternativas rejeitadas

- Auto-link por e-mail: permite account takeover quando a confiança, lifecycle
  ou reciclagem de e-mail divergem entre realm e provedor.
- Um usuário por método: duplica autorização, audit e ownership de recursos.
- Password hash sintético para conta social: representa uma credencial que não
  existe e complica reset, assurance e migração.
- Username/login como subject: é renomeável e não define autoridade.
- Criptografia própria do subject: não corrige semântica de identidade e impede
  constraints e investigação operacional. O campo é dado pessoal protegido por
  controles de acesso, retenção e criptografia do storage do host.

## Consequências

O schema sobe para v7. SQLite reconstrói `users` transacionalmente para tornar a
senha nullable e executa `foreign_key_check`; PostgreSQL remove `NOT NULL`. O
migrador offline passa a copiar identidades e challenges. Hosts precisam decidir
se permitem registro no primeiro login e manter redirect/provider configuration
por realm.

## Fontes

- Google OIDC claims: https://developers.google.com/identity/openid-connect/reference
- GitHub OAuth web flow: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
- GitHub authenticated user: https://docs.github.com/en/rest/users/users#get-the-authenticated-user
- Microsoft ID-token claims: https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
- OAuth 2.0 Security BCP: https://www.rfc-editor.org/rfc/rfc9700
