# Integração Node.js + TypeScript

Esta é a composição recomendada para 0.7: Rust cuida das regras e persistência,
o binding N-API faz somente tradução, o BFF possui cookies/CSRF e TypeScript
conecta o framework HTTP e a UI.

> Os pacotes nativos continuam privados durante o alpha. Use o workspace ou
> prebuilds verificados; não publique um binário local como release oficial.

```ts
import { NodeAuthService, migrateSqlite } from '@sdk-auth/internal-node'
import { NodeOidcProvider } from '@sdk-auth/oauth-node'
import { createAuthBff } from '@sdk-auth/bff'
import {
  createNativeOAuthAdapter,
  createNodeAuthBackend,
  createNodePasskeyBackend,
} from '@sdk-auth/bff/node'
import {
  createEncryptedBffStores,
  createRedisAtomicBlobStore,
} from '@sdk-auth/bff/stores'

const origin = 'https://app.example.com'
const callback = `${origin}/auth/oauth/google/callback`

migrateSqlite('./auth.db')
const native = new NodeAuthService({
  sqlitePath: './auth.db',
  activeKeyId: 'mfa-2026-08',
  vaultKeys: [{ keyId: 'mfa-2026-08', material: mfaKeyFromSecretManager }],
  webauthnRealms: [{
    realmId: 'main',
    rpId: 'app.example.com',
    rpName: 'Example',
    origins: [origin],
  }],
})

const googleNative = await NodeOidcProvider.google(
  process.env.GOOGLE_CLIENT_ID!,
  process.env.GOOGLE_CLIENT_SECRET!,
  callback,
)
const google = createNativeOAuthAdapter({
  providerId: 'google',
  issuer: 'https://accounts.google.com',
  redirectUri: callback,
  provider: googleNative,
})

const blobs = createRedisAtomicBlobStore(redisClient)
const stores = createEncryptedBffStores({
  blobs,
  prefix: 'production-main',
  activeKeyId: 'bff-2026-08',
  keys: { 'bff-2026-08': bffKeyFromSecretManager },
})

export const authFetch = createAuthBff({
  publicOrigin: origin,
  providers: { google },
  backend: createNodeAuthBackend({ realmId: 'main', service: native }),
  passkeys: createNodePasskeyBackend({ realmId: 'main', service: native }),
  ...stores,
  postLoginPath: '/account',
  linkRequiredPath: '/login?flow=link',
  registrationRequiredPath: '/register?flow=federated',
})
```

O adapter do framework deve construir `Request` com a origem pública já
validada e devolver todos os headers `Set-Cookie`. Não confie diretamente em
`X-Forwarded-*`; configure uma lista de proxies confiáveis. Google, Microsoft e
GitHub exigem callback exatamente igual à configurada no provider.

Nunca logue options, retornos nativos, body de senha/MFA ou conteúdo dos stores.
`mfaKeyFromSecretManager` e `bffKeyFromSecretManager` devem ser chaves diferentes
e não podem morar no SQLite/Redis.

O `runExclusive` do store é parte da segurança de refresh rotation. Não troque o
adapter Redis por um mutex em memória quando houver mais de um processo.
