import './auth-login'
import './auth-challenge'
import './theme.css'

import type { SdkAuthLogin } from './auth-login'
import type { SdkAuthChallenge } from './auth-challenge'

const login = document.querySelector<SdkAuthLogin>('sdk-auth-login')
const challenge = document.querySelector<SdkAuthChallenge>('sdk-auth-challenge')

function selectDemoView(): void {
  const showChallenge =
    window.location.hash === '#challenge' ||
    new URLSearchParams(window.location.search).get('view') === 'challenge'
  if (login) login.hidden = showChallenge
  if (challenge) challenge.hidden = !showChallenge
}

window.addEventListener('hashchange', selectDemoView)
selectDemoView()

login?.addEventListener('sdk-auth:provider', () => {
  login.busy = true
  window.setTimeout(() => {
    login.busy = false
  }, 900)
})

login?.addEventListener('sdk-auth:password-submit', () => {
  window.location.hash = 'challenge'
})

login?.addEventListener('sdk-auth:passkey', () => {
  login.error = 'Demo local: conecte WebAuthn ao seu BFF.'
})

challenge?.addEventListener('sdk-auth:second-factor-submit', () => {
  challenge.error = 'Demo local: conecte esta prova ao seu BFF.'
})
