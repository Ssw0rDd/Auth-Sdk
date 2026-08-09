# @sdk-auth/browser

Token-blind browser client for an SDK-Auth BFF. It supports password + MFA,
Google/GitHub/Microsoft redirects, explicit federated account linking,
passkeys, session inspection and logout without exposing SDK bearer tokens to
JavaScript.

```sh
npm install @sdk-auth/browser
```

```ts
import { createAuthClient } from '@sdk-auth/browser'

const auth = createAuthClient({ basePath: '/auth' })
const session = await auth.session()
```

Serve it only with the same-origin BFF over HTTPS. Do not persist credentials,
OAuth tokens or backend refresh tokens in `localStorage`/`sessionStorage`.

See the repository [Getting started](../../docs/GETTING_STARTED.md) for full
compose.

This package is an alpha and is not yet approved for production-critical use.
