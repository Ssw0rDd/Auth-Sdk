import {
  type AuthProvider,
  type PasswordSubmitDetail,
  type PasskeySubmitDetail,
  type ProviderSubmitDetail,
  SdkAuthLogin,
} from './auth-login'
import {
  type ChallengeMethod,
  type SecondFactorSubmitDetail,
  SdkAuthChallenge,
} from './auth-challenge'

export interface TokenBlindPasswordProgress {
  status: 'authenticated' | 'second_factor_required'
  methods?: ChallengeMethod[]
  expiresAt?: string
}

export interface TokenBlindAuthClient {
  password(credentials: {
    email: string
    password: string
    rememberMe?: boolean
  }): Promise<void | TokenBlindPasswordProgress>
  startProvider(provider: AuthProvider, options?: { rememberMe?: boolean }): Promise<string>
  passkey?(request: PasskeySubmitDetail): Promise<void>
}

export interface ConnectAuthLoginOptions {
  navigate?: (authorizationUrl: string) => void
  onAuthenticated?: () => void | Promise<void>
  onSecondFactorRequired?: (progress: {
    methods: ChallengeMethod[]
    expiresAt: string
  }) => void | Promise<void>
  errorMessage?: string
}

/** Connects the optional UI to a token-blind BFF client and returns a disposer. */
export function connectAuthLogin(
  element: SdkAuthLogin,
  client: TokenBlindAuthClient,
  options: ConnectAuthLoginOptions = {},
): () => void {
  const errorMessage =
    options.errorMessage ?? 'Não foi possível entrar. Confira seus dados e tente novamente.'
  const navigate = options.navigate ?? defaultNavigate

  const passwordListener: EventListener = (event) => {
    if (!(event instanceof CustomEvent) || element.busy) return
    const detail: unknown = event.detail
    if (!isPasswordDetail(detail)) return
    void run(element, errorMessage, async () => {
      const progress = await client.password({
        email: detail.email,
        password: detail.password,
        rememberMe: detail.rememberMe,
      })
      if (isSecondFactorProgress(progress)) {
        await options.onSecondFactorRequired?.({
          methods: progress.methods,
          expiresAt: progress.expiresAt,
        })
      } else {
        await options.onAuthenticated?.()
      }
    })
  }

  const providerListener: EventListener = (event) => {
    if (!(event instanceof CustomEvent) || element.busy) return
    const detail: unknown = event.detail
    if (!isProviderDetail(detail)) return
    void run(element, errorMessage, async () => {
      const authorizationUrl = detail.rememberMe === undefined
        ? await client.startProvider(detail.provider)
        : await client.startProvider(detail.provider, { rememberMe: detail.rememberMe })
      navigate(validateAuthorizationUrl(authorizationUrl))
    })
  }

  const passkeyListener: EventListener = (event) => {
    if (!(event instanceof CustomEvent) || element.busy) return
    const detail: unknown = event.detail
    if (!isPasskeyDetail(detail)) return
    void run(element, errorMessage, async () => {
      if (client.passkey === undefined) throw new Error('passkey client is not configured')
      await client.passkey(detail)
      await options.onAuthenticated?.()
    })
  }

  element.addEventListener('sdk-auth:password-submit', passwordListener)
  element.addEventListener('sdk-auth:provider', providerListener)
  element.addEventListener('sdk-auth:passkey', passkeyListener)
  return () => {
    element.removeEventListener('sdk-auth:password-submit', passwordListener)
    element.removeEventListener('sdk-auth:provider', providerListener)
    element.removeEventListener('sdk-auth:passkey', passkeyListener)
  }
}

export interface TokenBlindChallengeClient {
  completeSecondFactor(request: SecondFactorSubmitDetail): Promise<void>
}

export interface ConnectAuthChallengeOptions {
  onAuthenticated?: () => void | Promise<void>
  errorMessage?: string
}

/** Connects the second-factor UI without exposing the server-side challenge token. */
export function connectAuthChallenge(
  element: SdkAuthChallenge,
  client: TokenBlindChallengeClient,
  options: ConnectAuthChallengeOptions = {},
): () => void {
  const errorMessage = options.errorMessage ?? 'A prova não foi aceita. Tente novamente.'
  const listener: EventListener = (event) => {
    if (!(event instanceof CustomEvent) || element.busy) return
    const detail: unknown = event.detail
    if (!isSecondFactorDetail(detail)) return
    void run(element, errorMessage, async () => {
      await client.completeSecondFactor(detail)
      await options.onAuthenticated?.()
    })
  }
  element.addEventListener('sdk-auth:second-factor-submit', listener)
  return () => element.removeEventListener('sdk-auth:second-factor-submit', listener)
}

async function run(
  element: SdkAuthLogin | SdkAuthChallenge,
  errorMessage: string,
  operation: () => Promise<void>,
) {
  element.error = ''
  element.busy = true
  try {
    await operation()
  } catch {
    element.error = errorMessage
  } finally {
    element.busy = false
  }
}

function isPasswordDetail(value: unknown): value is PasswordSubmitDetail {
  if (value === null || typeof value !== 'object') return false
  const detail = value as Partial<PasswordSubmitDetail>
  return (
    typeof detail.email === 'string' &&
    detail.email.length <= 320 &&
    typeof detail.password === 'string' &&
    detail.password.length <= 4_096 &&
    (detail.rememberMe === undefined || typeof detail.rememberMe === 'boolean')
  )
}

function isProviderDetail(value: unknown): value is ProviderSubmitDetail {
  if (value === null || typeof value !== 'object') return false
  const provider = (value as Partial<ProviderSubmitDetail>).provider
  return provider === 'google' || provider === 'github' || provider === 'microsoft'
}

function isPasskeyDetail(value: unknown): value is PasskeySubmitDetail {
  if (value === null || typeof value !== 'object') return false
  const detail = value as Partial<PasskeySubmitDetail>
  return (
    typeof detail.email === 'string' &&
    detail.email.length >= 3 &&
    detail.email.length <= 320 &&
    typeof detail.rememberMe === 'boolean'
  )
}

function isSecondFactorProgress(
  value: void | TokenBlindPasswordProgress,
): value is { status: 'second_factor_required'; methods: ChallengeMethod[]; expiresAt: string } {
  return (
    value !== undefined &&
    value.status === 'second_factor_required' &&
    Array.isArray(value.methods) &&
    value.methods.length >= 1 &&
    value.methods.every((method) => method === 'totp' || method === 'recovery_code') &&
    typeof value.expiresAt === 'string' &&
    Number.isFinite(Date.parse(value.expiresAt))
  )
}

function isSecondFactorDetail(value: unknown): value is SecondFactorSubmitDetail {
  if (value === null || typeof value !== 'object') return false
  const detail = value as Partial<SecondFactorSubmitDetail>
  return (
    (detail.method === 'totp' || detail.method === 'recovery_code') &&
    typeof detail.proof === 'string' &&
    detail.proof.length >= 1 &&
    detail.proof.length <= 512 &&
    typeof detail.trustDevice === 'boolean'
  )
}

function validateAuthorizationUrl(value: string): string {
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new Error('invalid authorization URL')
  }
  for (const forbidden of ['access_token', 'client_secret', 'code_verifier', 'refresh_token']) {
    if (url.searchParams.has(forbidden)) throw new Error('secret in authorization URL')
  }
  return url.href
}

function defaultNavigate(authorizationUrl: string): void {
  if (typeof window === 'undefined') throw new Error('navigate callback required outside a browser')
  window.location.assign(authorizationUrl)
}
