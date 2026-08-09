# @sdk-auth/bff

Framework-neutral, token-blind backend-for-frontend primitives for SDK-Auth.
The browser receives only an opaque `HttpOnly` session cookie; access, refresh,
OAuth transaction, MFA, link and passkey ceremony tokens remain server-side.

```sh
npm install @sdk-auth/bff
```

Use `@sdk-auth/bff/node` for the native SDK adapters and
`@sdk-auth/bff/stores` for encrypted shared state. The in-memory stores are for
single-process development only. Production stores must preserve atomic
`putIfAbsent`, `getAndDelete` and per-session `runExclusive` semantics across
all replicas.

This package is an alpha and is not yet approved for production-critical use.
See the repository [Getting started](../../docs/GETTING_STARTED.md),
[Configuration](../../docs/CONFIGURATION.md), OpenAPI, migration guide, threat
model and security policy before integration.
