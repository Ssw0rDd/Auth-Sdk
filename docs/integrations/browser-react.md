# Integração browser, Web Component e React

```ts
import { BrowserAuthClient } from '@sdk-auth/browser'
import { connectAuthChallenge, connectAuthLogin } from '@sdk-auth/ui'
import '@sdk-auth/ui'
import '@sdk-auth/ui/theme.css'

const client = new BrowserAuthClient()
const login = document.querySelector('sdk-auth-login')!
const challenge = document.querySelector('sdk-auth-challenge')!

login.showPasskey = true
connectAuthLogin(login, client, {
  onAuthenticated: () => location.assign('/account'),
  onSecondFactorRequired: ({ methods }) => {
    challenge.methods = methods
    login.hidden = true
    challenge.hidden = false
  },
})
connectAuthChallenge(challenge, client, {
  onAuthenticated: () => location.assign('/account'),
})
```

O wrapper React exporta `AuthLogin` e `AuthChallenge` de `@sdk-auth/ui/react`.
Não copie senha/proof para store global, query, analytics ou error reporting.
Eventos carregam o segredo apenas durante o submit; o componente não o reflete
em atributo/HTML.

O BFF precisa estar na mesma origem. A aplicação deve usar CSP sem `unsafe-eval`,
evitar HTML não sanitizado e manter dependências frontend atualizadas. O pacote
não publica source maps, mas todo código browser continua observável por design.
