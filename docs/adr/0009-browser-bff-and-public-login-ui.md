# ADR 0009 — BFF browser, cliente sem tokens e UI pública

- Status: aceito
- Release: 0.7.0
- Data: 2026-08-08

## Contexto

Uma SPA que recebe access ou refresh token torna qualquer XSS capaz de roubar a
sessão. Guardar o bearer em `localStorage`, `sessionStorage`, IndexedDB ou em uma
variável JavaScript não muda essa fronteira. OAuth também exige `state`, nonce e
PKCE ligados à transação e consumidos uma única vez. A UI opcional da SDK não
pode conhecer client secret, verifier, token do provedor ou token da SDK.

O SDK precisa funcionar em hosts Node sem impor Express, Next ou outro framework,
e o componente visual deve continuar utilizável com qualquer backend que cumpra
o mesmo contrato.

## Decisão

- `sdk-auth-oauth` executa os protocolos no servidor. OIDC valida discovery,
  JWKS, assinatura, issuer, audience, expiração, nonce e `at_hash`; GitHub troca
  o code, relê `/user` e usa o `id` numérico como subject.
- `@sdk-auth/bff` é um handler Fetch server-side e framework-neutral. Access e
  refresh tokens ficam exclusivamente em `BrowserSessionStore` no servidor. O
  browser recebe somente um identificador aleatório de sessão.
- A sessão usa cookie `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`, sem
  `Domain`. HTTP só pode ser habilitado para loopback e usa nomes `ska-dev-*`.
- Mutações exigem Origin exata, `Sec-Fetch-Site: same-origin` quando presente e
  double-submit CSRF. `SameSite` é defesa adicional, não substituta.
- Início OAuth é `POST`; o BFF persiste state, nonce e PKCE verifier server-side.
  Um cookie de flow `HttpOnly` liga a transação ao browser. Callback consome o
  state atomicamente antes da troca do code, inclusive em erro ou mismatch.
- Cada provider possui callback próprio. Provider, issuer e subject são
  revalidados para impedir mix-up. Redirect pós-login/erro é configuração fixa
  same-origin; query string nunca escolhe destino.
- `@sdk-auth/browser` conhece apenas CSRF, sessão pública e URL de autorização.
  Ele nunca aceita nem retorna access/refresh/provider tokens e projeta campos
  públicos por allow-list, mesmo se um backend defeituoso enviar propriedades a
  mais.
- MFA, vínculo de conta e WebAuthn usam um `PendingFlowStore`; o cookie contém
  apenas um ID aleatório `HttpOnly`. Challenge token, link token e ceremony token
  ficam no servidor. Opções públicas WebAuthn e a resposta do authenticator são
  os únicos dados da cerimônia que atravessam a fronteira.
- A inspeção BFF devolve a projeção pública e um `BackendSession` possivelmente
  rotacionado; o novo refresh token é persistido no store antes da resposta.
  Inspeção e logout são serializados por browser session para impedir que duas
  rotações concorrentes pareçam replay do mesmo refresh token.
- `@sdk-auth/ui` é Web Component Lit com wrapper React. Eventos de senha e
  provider são explícitos; `connectAuthLogin` pode ligá-los a qualquer cliente
  token-blind. Senha é lida apenas no submit e não vira estado reativo/markup.
- Stores Memory do BFF são limitados e destinados a testes ou processo único.
  Produção precisa de store compartilhado, TTL, take atômico e criptografia no
  storage.
- `@sdk-auth/bff/stores` fornece AES-256-GCM com nonce aleatório, key ID e AAD
  contendo deployment, tipo e record ID. O port de blobs continua responsável
  por `putIfAbsent` e `getAndDelete` distribuídos e atômicos.

## Invariantes

1. Nenhuma resposta ou cookie browser-visible contém token SDK, token do
   provider, client secret ou PKCE verifier.
2. Uma callback OAuth válida pertence ao mesmo provider e browser que iniciou a
   transação e só pode ser usada uma vez.
3. Nenhum GET inicia mutação de login/logout; callback só muda estado após
   validar e consumir a transação.
4. Redirect externo é exclusivamente a authorization URL HTTPS produzida pelo
   adapter. Redirect interno é fixo e same-origin.
5. Erros públicos não incluem mensagem de banco, provider, stack ou secret.
6. Código entregue ao browser é público por natureza; minificação, CSP e
   ausência de sourcemaps publicados reduzem exposição acidental, mas não são controles de
   autenticação.
7. Nenhum refresh rotacionado pode ser devolvido ao browser ou descartado sem
   atualizar o store de sessão BFF.
8. O lock de sessão precisa ser distribuído. O adapter Redis usa lease com owner
   aleatório e release compare-and-delete; lock apenas local é proibido em escala.

## Alternativas rejeitadas

- Tokens em storage do browser: amplia o impacto de XSS e viola a fronteira BFF.
- OAuth iniciado por GET: login CSRF e prefetchers podem disparar mutação.
- State autocontido sem replay store: não garante consumo único.
- Auto-link por e-mail do provider: permite takeover e duplica a semântica de
  identidade descrita no ADR 0008.
- Redirect recebido por query: cria open redirect e pode exfiltrar code/state.
- “Criptografar” JavaScript com algoritmo próprio: a chave teria de chegar ao
  mesmo browser e não esconderia lógica nem secrets de um atacante.

## Consequências

Hosts implementam `AuthBackend`, `OAuthProviderAdapter` e stores compartilhados,
ou usam bindings oficiais. O proxy deve preservar a origem externa sem confiar
em headers de clientes arbitrários. Escala horizontal exige Redis/PostgreSQL ou
store equivalente para transações e sessões BFF. A UI é opcional e pode ser
substituída sem alterar o Core.

## Fontes

- OAuth 2.0 Security BCP: https://www.rfc-editor.org/rfc/rfc9700
- OAuth 2.0 for Browser-Based Applications (work in progress): https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/26/
- OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- Microsoft OIDC: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
