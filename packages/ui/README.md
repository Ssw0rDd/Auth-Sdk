# @sdk-auth/ui

Accessible Lit Web Components and React wrappers for SDK-Auth. The optional
forge theme uses a red/black visual system, responsive motion and reduced-motion
and forced-colors fallbacks.

```sh
npm install @sdk-auth/ui
```

```ts
import '@sdk-auth/ui'
import '@sdk-auth/ui/theme.css'
```

```html
<sdk-auth-login show-passkey></sdk-auth-login>
<sdk-auth-challenge hidden></sdk-auth-challenge>
```

Connect components to `@sdk-auth/browser`; never inject backend tokens or
provider secrets into component properties, DOM attributes or Vite variables.
React bindings are exported from `@sdk-auth/ui/react`.

See the repository [Getting started](../../docs/GETTING_STARTED.md) for wiring
examples.

This package is an alpha and is not yet approved for production-critical use.
