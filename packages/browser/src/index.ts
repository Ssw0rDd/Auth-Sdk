export type KnownAuthProvider = 'github' | 'google' | 'microsoft'

export interface BrowserAuthClientOptions {
  /** Absolute BFF base URL. Defaults to `${window.location.origin}/auth`. */
  baseUrl?: string
  /** Required outside a browser when baseUrl should be checked against a separate origin. */
  browserOrigin?: string
  fetch?: typeof fetch
  /** Injectable for tests; defaults to `navigator.credentials` in browsers. */
  credentials?: { get(options: CredentialRequestOptions): Promise<unknown> }
}

export interface PasswordCredentials {
  email: string
  password: string
  rememberMe?: boolean
}

export type SecondFactorMethod = 'totp' | 'recovery_code'

export type PasswordLoginProgress =
  | { status: 'authenticated' }
  | {
      status: 'second_factor_required'
      methods: SecondFactorMethod[]
      expiresAt: string
    }

export interface CompleteSecondFactorRequest {
  method: SecondFactorMethod
  proof: string
  trustDevice?: boolean
}

export interface CompleteFederatedLinkRequest {
  kind: 'password' | 'current_passkey_session'
  password?: string
  secondFactorMethod?: SecondFactorMethod
  secondFactor?: string
}

export interface PasskeyLoginRequest {
  email: string
  rememberMe?: boolean
}

export interface BrowserUser {
  userId: string
  email: string | null
  assuranceLevel: 'aal1' | 'aal2' | 'aal3'
  expiresAt: string
}

export type BrowserSession =
  | { authenticated: false }
  | { authenticated: true; user: BrowserUser }

export class BrowserAuthError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string) {
    super(`${code} (${status})`)
    this.name = 'BrowserAuthError'
    this.status = status
    this.code = code
  }
}

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,512}$/u
const PROVIDER_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/u
const MAX_RESPONSE_BYTES = 16_384

/**
 * Same-origin, token-blind browser client. CSRF values live only in memory;
 * access and refresh tokens never appear in this API.
 */
export class BrowserAuthClient {
  readonly #baseUrl: string
  readonly #fetch: typeof fetch
  readonly #credentials: { get(options: CredentialRequestOptions): Promise<unknown> } | null
  #csrfPromise: Promise<string> | null = null

  constructor(options: BrowserAuthClientOptions = {}) {
    const runtimeOrigin = typeof location === 'undefined' ? null : location.origin
    if (
      runtimeOrigin !== null &&
      options.browserOrigin !== undefined &&
      options.browserOrigin !== runtimeOrigin
    ) {
      throw new Error('browserOrigin does not match the current browser')
    }
    const provisionalBase = options.baseUrl ?? `${runtimeOrigin ?? options.browserOrigin ?? ''}/auth`
    let base: URL
    try {
      base = new URL(provisionalBase)
    } catch {
      throw new Error('baseUrl must be absolute')
    }
    const browserOrigin = runtimeOrigin ?? options.browserOrigin ?? base.origin
    if (base.origin !== browserOrigin) throw new Error('baseUrl must be same-origin')
    if (base.protocol !== 'https:' && !(base.protocol === 'http:' && isLoopback(base.hostname))) {
      throw new Error('baseUrl must use HTTPS')
    }
    if (base.username || base.password || base.search || base.hash) {
      throw new Error('invalid baseUrl')
    }
    const pathname = base.pathname.replace(/\/+$/u, '')
    if (!pathname || pathname === '/' || pathname.includes('//')) throw new Error('invalid baseUrl path')
    this.#baseUrl = `${base.origin}${pathname}`
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis)
    this.#credentials = options.credentials ??
      (typeof navigator === 'undefined' ? null : navigator.credentials)
  }

  async password(credentials: PasswordCredentials): Promise<PasswordLoginProgress> {
    const email = credentials.email.trim()
    if (email.length < 3 || email.length > 320) throw new BrowserAuthError(0, 'invalid_request')
    if (credentials.password.length < 1 || credentials.password.length > 4_096) {
      throw new BrowserAuthError(0, 'invalid_request')
    }
    const response = await this.#mutation('/password', {
      email,
      password: credentials.password,
      ...(credentials.rememberMe === undefined ? {} : { rememberMe: credentials.rememberMe }),
    })
    if (response.status === 204) return { status: 'authenticated' }
    if (response.status !== 202) throw await responseError(response)
    const body = await responseJson(response)
    const methods = parseSecondFactorMethods(body?.methods)
    const expiresAt = body?.expiresAt
    if (
      body?.status !== 'second_factor_required' ||
      methods === null ||
      typeof expiresAt !== 'string' ||
      !Number.isFinite(Date.parse(expiresAt))
    ) {
      throw new BrowserAuthError(502, 'invalid_response')
    }
    return { status: 'second_factor_required', methods, expiresAt }
  }

  async completeSecondFactor(request: CompleteSecondFactorRequest): Promise<void> {
    if (
      !isSecondFactorMethod(request.method) ||
      request.proof.length < 1 ||
      request.proof.length > 512
    ) {
      throw new BrowserAuthError(0, 'invalid_request')
    }
    const response = await this.#mutation('/mfa/complete', {
      method: request.method,
      proof: request.proof,
      trustDevice: request.trustDevice === true,
    })
    await expectStatus(response, 204)
  }

  async completeFederatedLink(request: CompleteFederatedLinkRequest): Promise<void> {
    if (!validFederatedLinkRequest(request)) throw new BrowserAuthError(0, 'invalid_request')
    const response = await this.#mutation('/link/complete', request)
    await expectStatus(response, 204)
  }

  async cancelPendingFlow(): Promise<void> {
    const response = await this.#mutation('/flow/cancel')
    await expectStatus(response, 204)
  }

  async passkey(request: PasskeyLoginRequest): Promise<void> {
    const email = request.email.trim()
    if (email.length < 3 || email.length > 320) throw new BrowserAuthError(0, 'invalid_request')
    if (this.#credentials === null) throw new BrowserAuthError(0, 'passkey_unavailable')
    const started = await this.#mutation('/passkey/login/start', {
      email,
      ...(request.rememberMe === undefined ? {} : { rememberMe: request.rememberMe }),
    })
    if (!started.ok) throw await responseError(started)
    const body = await responseJson(started)
    if (!isRecord(body?.publicKey)) throw new BrowserAuthError(502, 'invalid_response')
    const publicKey = passkeyRequestOptions(body.publicKey)

    let credential: unknown
    try {
      credential = await this.#credentials.get({ publicKey })
    } catch {
      throw new BrowserAuthError(0, 'ceremony_cancelled')
    }
    const serialized = serializeAssertion(credential)
    const completed = await this.#mutation('/passkey/login/complete', { credential: serialized })
    await expectStatus(completed, 204)
  }

  async startProvider(
    provider: KnownAuthProvider | string,
    options: { rememberMe?: boolean } = {},
  ): Promise<string> {
    if (!PROVIDER_PATTERN.test(provider)) throw new BrowserAuthError(0, 'invalid_provider')
    const response = await this.#mutation(
      `/oauth/${provider}/start`,
      options.rememberMe === undefined ? {} : { rememberMe: options.rememberMe },
    )
    if (!response.ok) throw await responseError(response)
    const body = await responseJson(response)
    const value = body?.authorizationUrl
    if (typeof value !== 'string') throw new BrowserAuthError(502, 'invalid_response')
    let authorizationUrl: URL
    try {
      authorizationUrl = new URL(value)
    } catch {
      throw new BrowserAuthError(502, 'invalid_response')
    }
    if (
      authorizationUrl.protocol !== 'https:' ||
      authorizationUrl.username ||
      authorizationUrl.password ||
      authorizationUrl.hash
    ) {
      throw new BrowserAuthError(502, 'invalid_response')
    }
    for (const forbidden of ['access_token', 'client_secret', 'code_verifier', 'refresh_token']) {
      if (authorizationUrl.searchParams.has(forbidden)) {
        throw new BrowserAuthError(502, 'invalid_response')
      }
    }
    return authorizationUrl.href
  }

  async session(): Promise<BrowserSession> {
    const response = await this.#request('/session', { method: 'GET' })
    if (!response.ok) throw await responseError(response)
    const body = await responseJson(response)
    if (body?.authenticated === false) return { authenticated: false }
    const user = body?.authenticated === true && isRecord(body.user) ? body.user : null
    if (user === null) throw new BrowserAuthError(502, 'invalid_response')
    const userId = user.userId
    const email = user.email
    const assuranceLevel = user.assuranceLevel
    const expiresAt = user.expiresAt
    if (
      typeof userId !== 'string' ||
      userId.length < 1 ||
      userId.length > 255 ||
      (email !== null && (typeof email !== 'string' || email.length > 320)) ||
      (assuranceLevel !== 'aal1' && assuranceLevel !== 'aal2' && assuranceLevel !== 'aal3') ||
      typeof expiresAt !== 'string' ||
      !Number.isFinite(Date.parse(expiresAt))
    ) {
      throw new BrowserAuthError(502, 'invalid_response')
    }
    return {
      authenticated: true,
      user: { assuranceLevel, email, expiresAt, userId },
    }
  }

  async logout(): Promise<void> {
    const response = await this.#mutation('/logout')
    await expectStatus(response, 204)
    this.#csrfPromise = null
  }

  /**
   * Registers an email/password identity. The verification secret never leaves
   * the BFF; the host delivers it out-of-band. Completes with 204 even when the
   * address is already registered (anti-enumeration).
   */
  async register(credentials: { email: string; password: string }): Promise<void> {
    const email = credentials.email.trim()
    if (email.length < 3 || email.length > 320) throw new BrowserAuthError(0, 'invalid_request')
    if (credentials.password.length < 1 || credentials.password.length > 4_096) {
      throw new BrowserAuthError(0, 'invalid_request')
    }
    const response = await this.#mutation('/register', {
      email,
      password: credentials.password,
    })
    await expectStatus(response, 204)
  }

  /** Consumes an email-verification token from the delivery channel. */
  async verifyEmail(request: { token: string }): Promise<void> {
    const token = request.token.trim()
    if (!TOKEN_PATTERN.test(token)) throw new BrowserAuthError(0, 'invalid_request')
    const response = await this.#mutation('/email/verify', { token })
    await expectStatus(response, 204)
  }

  async #mutation(path: string, body?: unknown): Promise<Response> {
    let csrf = await this.#csrf()
    let response = await this.#request(path, mutationInit(csrf, body))
    if (await isCsrfRejection(response)) {
      this.#csrfPromise = null
      csrf = await this.#csrf()
      response = await this.#request(path, mutationInit(csrf, body))
    }
    return response
  }

  #csrf(): Promise<string> {
    this.#csrfPromise ??= this.#request('/csrf', { method: 'GET' })
      .then(async (response) => {
        if (!response.ok) throw await responseError(response)
        const body = await responseJson(response)
        if (typeof body?.csrfToken !== 'string' || !TOKEN_PATTERN.test(body.csrfToken)) {
          throw new BrowserAuthError(502, 'invalid_response')
        }
        return body.csrfToken
      })
      .catch((error: unknown) => {
        this.#csrfPromise = null
        throw error
      })
    return this.#csrfPromise
  }

  async #request(path: string, init: RequestInit): Promise<Response> {
    try {
      return await this.#fetch(`${this.#baseUrl}${path}`, {
        ...init,
        cache: 'no-store',
        credentials: 'same-origin',
        mode: 'same-origin',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        headers: {
          accept: 'application/json',
          ...headersObject(init.headers),
        },
      })
    } catch (error) {
      if (error instanceof BrowserAuthError) throw error
      throw new BrowserAuthError(0, 'network_error')
    }
  }
}

function mutationInit(csrf: string, body: unknown): RequestInit {
  const hasBody = body !== undefined
  return {
    method: 'POST',
    headers: {
      ...(hasBody ? { 'content-type': 'application/json' } : {}),
      'x-csrf-token': csrf,
    },
    ...(hasBody ? { body: JSON.stringify(body) } : {}),
  }
}

async function isCsrfRejection(response: Response): Promise<boolean> {
  if (response.status !== 403) return false
  try {
    const body = await responseJson(response.clone())
    return body?.error === 'request_rejected'
  } catch {
    return false
  }
}

async function expectStatus(response: Response, status: number): Promise<void> {
  if (response.status !== status) throw await responseError(response)
}

async function responseError(response: Response): Promise<BrowserAuthError> {
  try {
    const body = await responseJson(response)
    const code = typeof body?.error === 'string' && /^[a-z0-9_]{1,64}$/u.test(body.error)
      ? body.error
      : 'request_failed'
    return new BrowserAuthError(response.status, code)
  } catch {
    return new BrowserAuthError(response.status, 'request_failed')
  }
}

async function responseJson(response: Response): Promise<Record<string, unknown> | null> {
  const type = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase()
  if (type !== 'application/json') throw new BrowserAuthError(502, 'invalid_response')
  const declared = Number(response.headers.get('content-length'))
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new BrowserAuthError(502, 'invalid_response')
  }
  const text = await response.text()
  if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
    throw new BrowserAuthError(502, 'invalid_response')
  }
  try {
    const value: unknown = JSON.parse(text)
    return isRecord(value) ? value : null
  } catch {
    throw new BrowserAuthError(502, 'invalid_response')
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function parseSecondFactorMethods(value: unknown): SecondFactorMethod[] | null {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > 2 ||
    value.some((method) => !isSecondFactorMethod(method)) ||
    new Set(value).size !== value.length
  ) {
    return null
  }
  return value as SecondFactorMethod[]
}

function isSecondFactorMethod(value: unknown): value is SecondFactorMethod {
  return value === 'totp' || value === 'recovery_code'
}

function validFederatedLinkRequest(request: CompleteFederatedLinkRequest): boolean {
  if (request.kind !== 'password' && request.kind !== 'current_passkey_session') return false
  if (
    request.kind === 'password' &&
    (request.password === undefined || request.password.length < 1 || request.password.length > 4_096)
  ) {
    return false
  }
  if (request.kind === 'current_passkey_session' && request.password !== undefined) return false
  const hasMethod = request.secondFactorMethod !== undefined
  const hasProof = request.secondFactor !== undefined
  return (
    hasMethod === hasProof &&
    (!hasMethod ||
      (isSecondFactorMethod(request.secondFactorMethod) &&
        typeof request.secondFactor === 'string' &&
        request.secondFactor.length >= 1 &&
        request.secondFactor.length <= 512))
  )
}

function passkeyRequestOptions(value: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  if (
    typeof value.challenge !== 'string' ||
    value.challenge.length < 16 ||
    value.challenge.length > 2_048 ||
    value.userVerification !== 'required'
  ) {
    throw new BrowserAuthError(502, 'invalid_response')
  }
  const allowCredentials = value.allowCredentials === undefined
    ? undefined
    : parseCredentialDescriptors(value.allowCredentials)
  const timeout = value.timeout
  if (timeout !== undefined && (typeof timeout !== 'number' || !Number.isFinite(timeout) || timeout < 1)) {
    throw new BrowserAuthError(502, 'invalid_response')
  }
  const rpId = value.rpId
  if (rpId !== undefined && (typeof rpId !== 'string' || rpId.length < 1 || rpId.length > 255)) {
    throw new BrowserAuthError(502, 'invalid_response')
  }
  return {
    challenge: decodeBase64Url(value.challenge),
    userVerification: 'required',
    ...(allowCredentials === undefined ? {} : { allowCredentials }),
    ...(timeout === undefined ? {} : { timeout }),
    ...(rpId === undefined ? {} : { rpId }),
    ...(isRecord(value.extensions)
      ? { extensions: value.extensions as AuthenticationExtensionsClientInputs }
      : {}),
  }
}

function parseCredentialDescriptors(value: unknown): PublicKeyCredentialDescriptor[] {
  if (!Array.isArray(value) || value.length > 64) throw new BrowserAuthError(502, 'invalid_response')
  return value.map((item) => {
    if (!isRecord(item) || item.type !== 'public-key' || typeof item.id !== 'string') {
      throw new BrowserAuthError(502, 'invalid_response')
    }
    return {
      type: 'public-key',
      id: decodeBase64Url(item.id),
      ...(Array.isArray(item.transports)
        ? { transports: item.transports.filter(isAuthenticatorTransport) }
        : {}),
    }
  })
}

function isAuthenticatorTransport(value: unknown): value is AuthenticatorTransport {
  return value === 'ble' || value === 'hybrid' || value === 'internal' || value === 'nfc' || value === 'usb'
}

function serializeAssertion(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object') throw new BrowserAuthError(0, 'ceremony_cancelled')
  const credential = value as {
    id?: unknown
    rawId?: unknown
    type?: unknown
    response?: {
      authenticatorData?: unknown
      clientDataJSON?: unknown
      signature?: unknown
      userHandle?: unknown
    }
    getClientExtensionResults?: () => AuthenticationExtensionsClientOutputs
  }
  if (
    typeof credential.id !== 'string' ||
    credential.id.length < 1 ||
    credential.id.length > 2_048 ||
    credential.type !== 'public-key' ||
    credential.response === undefined
  ) {
    throw new BrowserAuthError(502, 'invalid_credential')
  }
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: 'public-key',
    response: {
      authenticatorData: encodeBase64Url(credential.response.authenticatorData),
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      signature: encodeBase64Url(credential.response.signature),
      userHandle:
        credential.response.userHandle === null
          ? null
          : encodeBase64Url(credential.response.userHandle),
    },
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
  }
}

function decodeBase64Url(value: string): ArrayBuffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new BrowserAuthError(502, 'invalid_response')
  const padding = '='.repeat((4 - (value.length % 4)) % 4)
  let binary: string
  try {
    binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding)
  } catch {
    throw new BrowserAuthError(502, 'invalid_response')
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  return bytes.buffer
}

function encodeBase64Url(value: unknown): string {
  let bytes: Uint8Array
  if (value instanceof ArrayBuffer) bytes = new Uint8Array(value)
  else if (ArrayBuffer.isView(value)) bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  else throw new BrowserAuthError(502, 'invalid_credential')
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function headersObject(headers: HeadersInit | undefined): Record<string, string> {
  return Object.fromEntries(new Headers(headers).entries())
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]'
}
