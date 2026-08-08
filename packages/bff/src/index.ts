export interface OAuthTransaction {
  state: string
  nonce: string
  pkceVerifier: string
}

export interface OAuthBeginRequest {
  redirectUri: string
}

export interface OAuthExchangeRequest extends OAuthBeginRequest {
  code: string
  transaction: OAuthTransaction
}

export interface FederatedIdentity {
  issuer: string
  subject: string
  email?: string
  emailVerified: boolean
  displayName?: string
}

export interface OAuthProviderAdapter {
  /** Canonical HTTPS issuer. It must exactly match the verified profile issuer. */
  readonly issuer: string
  begin(request: OAuthBeginRequest): Promise<{
    authorizationUrl: string
    transaction: OAuthTransaction
  }>
  exchange(request: OAuthExchangeRequest): Promise<FederatedIdentity>
}

export interface BackendSession {
  accessToken: string
  refreshToken: string
  expiresAt: string
}

export type SecondFactorMethod = 'totp' | 'recovery_code'

export type PasswordBackendOutcome =
  | { kind: 'authenticated'; session: BackendSession }
  | {
      kind: 'second_factor_required'
      challengeToken: string
      methods: SecondFactorMethod[]
      expiresAt: string
    }

export type FederatedBackendOutcome =
  | { kind: 'authenticated'; session: BackendSession }
  | {
      kind: 'link_required'
      linkUserId: string
      linkToken: string
      expiresAt: string
    }
  | { kind: 'registration_required' }

export interface FederatedLinkProof {
  kind: 'password' | 'current_passkey_session'
  password?: string
  secondFactorMethod?: SecondFactorMethod
  secondFactor?: string
}

export interface PublicSession {
  userId: string
  email?: string
  assuranceLevel: 'aal1' | 'aal2' | 'aal3'
  expiresAt: string
}

export interface BackendSessionInspection {
  backend: BackendSession
  public: PublicSession
}

export interface AuthBackend {
  password(credentials: {
    email: string
    password: string
    rememberMe: boolean
  }): Promise<PasswordBackendOutcome>
  completeSecondFactor(request: {
    challengeToken: string
    method: SecondFactorMethod
    proof: string
    trustDevice: boolean
  }): Promise<BackendSession>
  federated(request: {
    provider: string
    identity: FederatedIdentity
    rememberMe: boolean
  }): Promise<FederatedBackendOutcome>
  completeFederatedLink(request: {
    session: BackendSession
    linkToken: string
    proof: FederatedLinkProof
  }): Promise<void>
  inspect(session: BackendSession): Promise<BackendSessionInspection | null>
  revoke(session: BackendSession): Promise<void>
}

export interface PasskeyBackend {
  beginLogin(request: { email: string; rememberMe: boolean }): Promise<{
    ceremonyToken: string
    publicKey: Record<string, unknown>
    expiresAt: string
  }>
  finishLogin(request: { ceremonyToken: string; responseJson: string }): Promise<BackendSession>
}

/** Throw only for an authentication decision, never for infrastructure errors. */
export class AuthenticationRejectedError extends Error {
  constructor() {
    super('authentication rejected')
    this.name = 'AuthenticationRejectedError'
  }
}

export interface StoredOAuthTransaction {
  binding: string
  expiresAt: number
  provider: string
  rememberMe: boolean
  transaction: OAuthTransaction
}

export interface OAuthTransactionStore {
  /** Inserts a transaction, failing closed if the state already exists. */
  put(state: string, value: StoredOAuthTransaction): Promise<void>
  /** Atomically reads and removes a transaction. */
  take(state: string): Promise<StoredOAuthTransaction | null>
}

export interface StoredBrowserSession {
  backend: BackendSession
  expiresAt: number
}

export interface BrowserSessionStore {
  put(id: string, value: StoredBrowserSession): Promise<void>
  get(id: string): Promise<StoredBrowserSession | null>
  delete(id: string): Promise<void>
  /** Serializes refresh-sensitive work for one session across all processes. */
  runExclusive<T>(id: string, operation: () => Promise<T>): Promise<T>
}

export type StoredPendingFlow =
  | {
      kind: 'second_factor'
      challengeToken: string
      methods: SecondFactorMethod[]
      expiresAt: number
    }
  | {
      kind: 'federated_link'
      linkToken: string
      linkUserId: string
      expiresAt: number
    }
  | {
      kind: 'passkey_login'
      ceremonyToken: string
      expiresAt: number
    }

export interface PendingFlowStore {
  put(id: string, value: StoredPendingFlow): Promise<void>
  get(id: string): Promise<StoredPendingFlow | null>
  delete(id: string): Promise<void>
}

/**
 * Single-process development store. Production deployments should provide a
 * shared store with atomic get-and-delete semantics and encrypted persistence.
 */
export class MemoryOAuthTransactionStore implements OAuthTransactionStore {
  readonly #capacity: number
  readonly #values = new Map<string, StoredOAuthTransaction>()

  constructor(capacity = 2_048) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new Error('invalid capacity')
    this.#capacity = capacity
  }

  async put(state: string, value: StoredOAuthTransaction): Promise<void> {
    this.#prune(Date.now())
    if (this.#values.has(state)) throw new Error('OAuth state collision')
    if (this.#values.size >= this.#capacity) throw new Error('OAuth transaction capacity reached')
    this.#values.set(state, value)
  }

  async take(state: string): Promise<StoredOAuthTransaction | null> {
    const value = this.#values.get(state) ?? null
    this.#values.delete(state)
    if (value === null || value.expiresAt <= Date.now()) return null
    return value
  }

  #prune(now: number): void {
    for (const [state, value] of this.#values) {
      if (value.expiresAt <= now) this.#values.delete(state)
    }
  }
}

/** Single-process development store. Use a shared encrypted store in production. */
export class MemoryBrowserSessionStore implements BrowserSessionStore {
  readonly #capacity: number
  readonly #values = new Map<string, StoredBrowserSession>()
  readonly #locks = new Map<string, Promise<void>>()

  constructor(capacity = 10_000) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new Error('invalid capacity')
    this.#capacity = capacity
  }

  async put(id: string, value: StoredBrowserSession): Promise<void> {
    this.#prune(Date.now())
    if (!this.#values.has(id) && this.#values.size >= this.#capacity) {
      throw new Error('browser session capacity reached')
    }
    this.#values.set(id, value)
  }

  async get(id: string): Promise<StoredBrowserSession | null> {
    const value = this.#values.get(id) ?? null
    if (value === null || value.expiresAt <= Date.now()) {
      this.#values.delete(id)
      return null
    }
    return value
  }

  async delete(id: string): Promise<void> {
    this.#values.delete(id)
  }

  async runExclusive<T>(id: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.#locks.get(id) ?? Promise.resolve()
    let release = (): void => {}
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const tail = previous.then(() => gate)
    this.#locks.set(id, tail)
    await previous
    try {
      return await operation()
    } finally {
      release()
      if (this.#locks.get(id) === tail) this.#locks.delete(id)
    }
  }

  #prune(now: number): void {
    for (const [id, value] of this.#values) {
      if (value.expiresAt <= now) this.#values.delete(id)
    }
  }
}

/**
 * Single-process development store. Production stores must encrypt bearer
 * fields at rest and make their capacity and expiration behavior explicit.
 */
export class MemoryPendingFlowStore implements PendingFlowStore {
  readonly #capacity: number
  readonly #values = new Map<string, StoredPendingFlow>()

  constructor(capacity = 2_048) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new Error('invalid capacity')
    this.#capacity = capacity
  }

  async put(id: string, value: StoredPendingFlow): Promise<void> {
    this.#prune(Date.now())
    if (this.#values.has(id)) throw new Error('pending flow collision')
    if (this.#values.size >= this.#capacity) throw new Error('pending flow capacity reached')
    this.#values.set(id, value)
  }

  async get(id: string): Promise<StoredPendingFlow | null> {
    const value = this.#values.get(id) ?? null
    if (value === null || value.expiresAt <= Date.now()) {
      this.#values.delete(id)
      return null
    }
    return value
  }

  async delete(id: string): Promise<void> {
    this.#values.delete(id)
  }

  #prune(now: number): void {
    for (const [id, value] of this.#values) {
      if (value.expiresAt <= now) this.#values.delete(id)
    }
  }
}

export interface AuthBffConfig {
  publicOrigin: string
  providers: Readonly<Record<string, OAuthProviderAdapter>>
  backend: AuthBackend
  transactions: OAuthTransactionStore
  sessions: BrowserSessionStore
  pendingFlows: PendingFlowStore
  passkeys?: PasskeyBackend
  basePath?: string
  postLoginPath?: string
  oauthErrorPath?: string
  linkRequiredPath?: string
  registrationRequiredPath?: string
  transactionTtlSeconds?: number
  browserSessionTtlSeconds?: number
  maxJsonBytes?: number
  /** Permits plain HTTP only on a loopback host and changes cookie names. */
  allowInsecureLoopback?: boolean
}

interface ResolvedConfig {
  origin: string
  basePath: string
  postLoginUrl: string
  oauthErrorUrl: string
  linkRequiredUrl: string
  registrationRequiredUrl: string
  providers: Readonly<Record<string, OAuthProviderAdapter>>
  backend: AuthBackend
  transactions: OAuthTransactionStore
  sessions: BrowserSessionStore
  pendingFlows: PendingFlowStore
  passkeys?: PasskeyBackend
  transactionTtlSeconds: number
  browserSessionTtlSeconds: number
  maxJsonBytes: number
  cookieNames: {
    csrf: string
    flow: string
    pending: string
    session: string
  }
  secureCookies: boolean
}

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,512}$/u
const PROVIDER_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/u

export function createAuthBff(config: AuthBffConfig): (request: Request) => Promise<Response> {
  const resolved = resolveConfig(config)
  return async (request) => {
    try {
      return await handleRequest(resolved, request)
    } catch {
      return problem(503, 'temporarily_unavailable')
    }
  }
}

async function handleRequest(config: ResolvedConfig, request: Request): Promise<Response> {
  let url: URL
  try {
    url = new URL(request.url)
  } catch {
    return problem(400, 'invalid_request')
  }
  if (url.origin !== config.origin) return problem(400, 'invalid_request')

  if (url.pathname === `${config.basePath}/csrf`) {
    if (request.method !== 'GET') return methodNotAllowed('GET')
    return issueCsrf(config)
  }
  if (url.pathname === `${config.basePath}/password`) {
    if (request.method !== 'POST') return methodNotAllowed('POST')
    return passwordLogin(config, request)
  }
  if (url.pathname === `${config.basePath}/mfa/complete`) {
    if (request.method !== 'POST') return methodNotAllowed('POST')
    return completeSecondFactor(config, request)
  }
  if (url.pathname === `${config.basePath}/link/complete`) {
    if (request.method !== 'POST') return methodNotAllowed('POST')
    return completeFederatedLink(config, request)
  }
  if (url.pathname === `${config.basePath}/flow/cancel`) {
    if (request.method !== 'POST') return methodNotAllowed('POST')
    return cancelPendingFlow(config, request)
  }
  if (url.pathname === `${config.basePath}/passkey/login/start`) {
    if (request.method !== 'POST') return methodNotAllowed('POST')
    return passkeyLoginStart(config, request)
  }
  if (url.pathname === `${config.basePath}/passkey/login/complete`) {
    if (request.method !== 'POST') return methodNotAllowed('POST')
    return passkeyLoginComplete(config, request)
  }
  if (url.pathname === `${config.basePath}/session`) {
    if (request.method !== 'GET') return methodNotAllowed('GET')
    return currentSession(config, request)
  }
  if (url.pathname === `${config.basePath}/logout`) {
    if (request.method !== 'POST') return methodNotAllowed('POST')
    return logout(config, request)
  }

  const route = oauthRoute(config.basePath, url.pathname)
  if (route === null) return problem(404, 'not_found')
  if (route.action === 'start') {
    if (request.method !== 'POST') return methodNotAllowed('POST')
    return oauthStart(config, request, route.provider)
  }
  if (request.method !== 'GET') return methodNotAllowed('GET')
  return oauthCallback(config, request, url, route.provider)
}

function oauthRoute(
  basePath: string,
  pathname: string,
): { action: 'start' | 'callback'; provider: string } | null {
  if (!pathname.startsWith(`${basePath}/oauth/`)) return null
  const rest = pathname.slice(`${basePath}/oauth/`.length).split('/')
  if (rest.length !== 2) return null
  const provider = rest[0]
  const action = rest[1]
  if (provider === undefined || !PROVIDER_PATTERN.test(provider)) return null
  if (action !== 'start' && action !== 'callback') return null
  return { action, provider }
}

function issueCsrf(config: ResolvedConfig): Response {
  const token = randomToken()
  const response = json(200, { csrfToken: token })
  response.headers.append(
    'set-cookie',
    cookie(config, config.cookieNames.csrf, token, {
      httpOnly: false,
      maxAge: 3_600,
      sameSite: 'Strict',
    }),
  )
  return response
}

async function passwordLogin(config: ResolvedConfig, request: Request): Promise<Response> {
  if (!validMutation(config, request)) return problem(403, 'request_rejected')
  const body = await readJson(request, config.maxJsonBytes)
  if (body === null) return problem(400, 'invalid_request')
  if (body.rememberMe !== undefined && typeof body.rememberMe !== 'boolean') {
    return problem(400, 'invalid_request')
  }
  const rememberMe = body.rememberMe === true
  const email = typeof body.email === 'string' ? body.email.trim() : ''
  const password = typeof body.password === 'string' ? body.password : ''
  if (email.length < 3 || email.length > 320 || password.length < 1 || password.length > 4_096) {
    return problem(400, 'invalid_request')
  }

  let outcome: PasswordBackendOutcome
  try {
    outcome = await config.backend.password({ email, password, rememberMe })
    validatePasswordOutcome(outcome)
  } catch (error) {
    return error instanceof AuthenticationRejectedError
      ? problem(401, 'authentication_failed')
      : problem(503, 'temporarily_unavailable')
  }
  if (outcome.kind === 'authenticated') {
    return installBrowserSession(config, request, outcome.session, json(204, undefined))
  }
  const pendingId = randomToken()
  const expiresAt = Math.min(
    Date.parse(outcome.expiresAt),
    Date.now() + config.transactionTtlSeconds * 1_000,
  )
  try {
    await config.pendingFlows.put(pendingId, {
      kind: 'second_factor',
      challengeToken: outcome.challengeToken,
      methods: [...outcome.methods],
      expiresAt,
    })
  } catch {
    return problem(503, 'temporarily_unavailable')
  }
  const response = json(202, {
    status: 'second_factor_required',
    methods: outcome.methods,
    expiresAt: new Date(expiresAt).toISOString(),
  })
  setPendingCookie(config, response, pendingId, expiresAt)
  return response
}

async function completeSecondFactor(config: ResolvedConfig, request: Request): Promise<Response> {
  if (!validMutation(config, request)) return problem(403, 'request_rejected')
  const body = await readJson(request, config.maxJsonBytes)
  if (body === null) return problem(400, 'invalid_request')
  if (body.rememberMe !== undefined && typeof body.rememberMe !== 'boolean') {
    return problem(400, 'invalid_request')
  }
  const rememberMe = body.rememberMe === true
  const pending = await readPendingFlow(config, request)
  if (pending === null || pending.value.kind !== 'second_factor') {
    return clearPending(config, problem(409, 'no_pending_challenge'))
  }
  const method = parseSecondFactorMethod(body.method)
  const proof = typeof body.proof === 'string' ? body.proof : ''
  const trustDevice = body.trustDevice === true
  if (
    method === null ||
    !pending.value.methods.includes(method) ||
    proof.length < 1 ||
    proof.length > 512
  ) {
    return problem(400, 'invalid_request')
  }

  let session: BackendSession
  try {
    session = await config.backend.completeSecondFactor({
      challengeToken: pending.value.challengeToken,
      method,
      proof,
      trustDevice,
    })
    validateBackendSession(session)
  } catch (error) {
    return error instanceof AuthenticationRejectedError
      ? problem(401, 'authentication_failed')
      : problem(503, 'temporarily_unavailable')
  }
  await config.pendingFlows.delete(pending.id)
  const response = await installBrowserSession(config, request, session, json(204, undefined))
  return clearPending(config, response)
}

async function oauthStart(
  config: ResolvedConfig,
  request: Request,
  providerName: string,
): Promise<Response> {
  if (!validMutation(config, request)) return problem(403, 'request_rejected')
  const provider = ownProvider(config.providers, providerName)
  if (provider === null) return problem(404, 'not_found')
  const body = await readJson(request, config.maxJsonBytes)
  if (body === null) return problem(400, 'invalid_request')
  if (body.rememberMe !== undefined && typeof body.rememberMe !== 'boolean') {
    return problem(400, 'invalid_request')
  }
  const rememberMe = body.rememberMe === true

  const existingBinding = readCookie(request, config.cookieNames.flow)
  const binding = existingBinding !== null && TOKEN_PATTERN.test(existingBinding)
    ? existingBinding
    : randomToken()
  const redirectUri = callbackUrl(config, providerName)

  let authorizationUrl: string
  let transaction: OAuthTransaction
  try {
    const started = await provider.begin({ redirectUri })
    authorizationUrl = validateAuthorizationUrl(started.authorizationUrl)
    transaction = started.transaction
    validateOAuthTransaction(transaction)
    await config.transactions.put(transaction.state, {
      binding,
      expiresAt: Date.now() + config.transactionTtlSeconds * 1_000,
      provider: providerName,
      rememberMe,
      transaction,
    })
  } catch {
    return problem(503, 'provider_unavailable')
  }

  const response = json(200, { authorizationUrl })
  response.headers.append(
    'set-cookie',
    cookie(config, config.cookieNames.flow, binding, {
      httpOnly: true,
      maxAge: config.transactionTtlSeconds,
      sameSite: 'Lax',
    }),
  )
  return response
}

async function oauthCallback(
  config: ResolvedConfig,
  request: Request,
  url: URL,
  providerName: string,
): Promise<Response> {
  const provider = ownProvider(config.providers, providerName)
  if (provider === null) return problem(400, 'invalid_oauth_response')

  const states = url.searchParams.getAll('state')
  if (states.length !== 1 || !TOKEN_PATTERN.test(states[0] ?? '')) {
    return problem(400, 'invalid_oauth_response')
  }
  const stored = await config.transactions.take(states[0] ?? '')
  const binding = readCookie(request, config.cookieNames.flow)
  if (
    stored === null ||
    binding === null ||
    !constantTimeTextEqual(stored.binding, binding) ||
    stored.provider !== providerName ||
    stored.transaction.state !== states[0]
  ) {
    return problem(400, 'invalid_oauth_response')
  }

  if (url.searchParams.has('error')) return clearFlow(config, redirect(config.oauthErrorUrl))
  const codes = url.searchParams.getAll('code')
  if (codes.length !== 1 || (codes[0]?.length ?? 0) < 1 || (codes[0]?.length ?? 0) > 2_048) {
    return problem(400, 'invalid_oauth_response')
  }

  let outcome: FederatedBackendOutcome
  try {
    const identity = await provider.exchange({
      code: codes[0] ?? '',
      redirectUri: callbackUrl(config, providerName),
      transaction: stored.transaction,
    })
    validateIdentity(identity, provider.issuer)
    outcome = await config.backend.federated({
      provider: providerName,
      identity,
      rememberMe: stored.rememberMe,
    })
    validateFederatedOutcome(outcome)
  } catch {
    return clearFlow(config, redirect(config.oauthErrorUrl))
  }
  if (outcome.kind === 'authenticated') {
    const response = await installBrowserSession(
      config,
      request,
      outcome.session,
      redirect(config.postLoginUrl),
    )
    return clearFlow(config, response)
  }
  if (outcome.kind === 'registration_required') {
    return clearFlow(config, redirect(config.registrationRequiredUrl))
  }

  const pendingId = randomToken()
  const expiresAt = Math.min(
    Date.parse(outcome.expiresAt),
    Date.now() + config.transactionTtlSeconds * 1_000,
  )
  try {
    await config.pendingFlows.put(pendingId, {
      kind: 'federated_link',
      linkToken: outcome.linkToken,
      linkUserId: outcome.linkUserId,
      expiresAt,
    })
  } catch {
    return clearFlow(config, redirect(config.oauthErrorUrl))
  }
  const response = clearFlow(config, redirect(config.linkRequiredUrl))
  setPendingCookie(config, response, pendingId, expiresAt)
  return response
}

async function completeFederatedLink(config: ResolvedConfig, request: Request): Promise<Response> {
  if (!validMutation(config, request)) return problem(403, 'request_rejected')
  const body = await readJson(request, config.maxJsonBytes)
  if (body === null) return problem(400, 'invalid_request')
  const pending = await readPendingFlow(config, request)
  if (pending === null || pending.value.kind !== 'federated_link') {
    return clearPending(config, problem(409, 'no_pending_link'))
  }
  const sessionId = readCookie(request, config.cookieNames.session)
  if (sessionId === null || !TOKEN_PATTERN.test(sessionId)) {
    return problem(401, 'authentication_required')
  }
  const storedSession = await config.sessions.get(sessionId)
  if (storedSession === null) return clearSession(config, problem(401, 'authentication_required'))
  const proof = parseFederatedLinkProof(body)
  if (proof === null) return problem(400, 'invalid_request')

  try {
    await config.backend.completeFederatedLink({
      session: storedSession.backend,
      linkToken: pending.value.linkToken,
      proof,
    })
  } catch (error) {
    return error instanceof AuthenticationRejectedError
      ? problem(401, 'authentication_failed')
      : problem(503, 'temporarily_unavailable')
  }
  await config.pendingFlows.delete(pending.id)
  return clearPending(config, json(204, undefined))
}

async function cancelPendingFlow(config: ResolvedConfig, request: Request): Promise<Response> {
  if (!validMutation(config, request)) return problem(403, 'request_rejected')
  const id = readCookie(request, config.cookieNames.pending)
  if (id !== null && TOKEN_PATTERN.test(id)) await config.pendingFlows.delete(id)
  return clearPending(config, json(204, undefined))
}

async function passkeyLoginStart(config: ResolvedConfig, request: Request): Promise<Response> {
  if (!validMutation(config, request)) return problem(403, 'request_rejected')
  if (config.passkeys === undefined) return problem(404, 'not_found')
  const body = await readJson(request, config.maxJsonBytes)
  if (body === null) return problem(400, 'invalid_request')
  const email = typeof body.email === 'string' ? body.email.trim() : ''
  const rememberMe = body.rememberMe === true
  if (
    email.length < 3 ||
    email.length > 320 ||
    (body.rememberMe !== undefined && typeof body.rememberMe !== 'boolean')
  ) {
    return problem(400, 'invalid_request')
  }

  try {
    const started = await config.passkeys.beginLogin({ email, rememberMe })
    validateBearerExpiry(started.ceremonyToken, started.expiresAt)
    validatePasskeyOptions(started.publicKey, config.maxJsonBytes)
    const expiresAt = Math.min(
      Date.parse(started.expiresAt),
      Date.now() + config.transactionTtlSeconds * 1_000,
    )
    const pendingId = randomToken()
    await config.pendingFlows.put(pendingId, {
      kind: 'passkey_login',
      ceremonyToken: started.ceremonyToken,
      expiresAt,
    })
    const response = json(200, {
      publicKey: started.publicKey,
      expiresAt: new Date(expiresAt).toISOString(),
    })
    setPendingCookie(config, response, pendingId, expiresAt)
    return response
  } catch (error) {
    return error instanceof AuthenticationRejectedError
      ? problem(401, 'authentication_failed')
      : problem(503, 'temporarily_unavailable')
  }
}

async function passkeyLoginComplete(config: ResolvedConfig, request: Request): Promise<Response> {
  if (!validMutation(config, request)) return problem(403, 'request_rejected')
  if (config.passkeys === undefined) return problem(404, 'not_found')
  const body = await readJson(request, config.maxJsonBytes)
  if (body === null || !isRecord(body.credential)) return problem(400, 'invalid_request')
  const pending = await readPendingFlow(config, request)
  if (pending === null || pending.value.kind !== 'passkey_login') {
    return clearPending(config, problem(409, 'no_pending_challenge'))
  }
  const responseJson = JSON.stringify(body.credential)
  if (
    new TextEncoder().encode(responseJson).byteLength > config.maxJsonBytes ||
    body.credential.type !== 'public-key' ||
    typeof body.credential.id !== 'string' ||
    body.credential.id.length < 1 ||
    body.credential.id.length > 2_048
  ) {
    return problem(400, 'invalid_request')
  }

  let session: BackendSession
  try {
    session = await config.passkeys.finishLogin({
      ceremonyToken: pending.value.ceremonyToken,
      responseJson,
    })
    validateBackendSession(session)
  } catch (error) {
    return error instanceof AuthenticationRejectedError
      ? problem(401, 'authentication_failed')
      : problem(503, 'temporarily_unavailable')
  }
  await config.pendingFlows.delete(pending.id)
  const response = await installBrowserSession(config, request, session, json(204, undefined))
  return clearPending(config, response)
}

async function currentSession(config: ResolvedConfig, request: Request): Promise<Response> {
  const id = readCookie(request, config.cookieNames.session)
  if (id === null || !TOKEN_PATTERN.test(id)) return json(200, { authenticated: false })
  return config.sessions.runExclusive(id, () => currentSessionLocked(config, id))
}

async function currentSessionLocked(config: ResolvedConfig, id: string): Promise<Response> {
  const stored = await config.sessions.get(id)
  if (stored === null) return clearSession(config, json(200, { authenticated: false }))

  let inspection: BackendSessionInspection | null
  try {
    inspection = await config.backend.inspect(stored.backend)
  } catch {
    return problem(503, 'temporarily_unavailable')
  }
  if (inspection === null) {
    await config.sessions.delete(id)
    return clearSession(config, json(200, { authenticated: false }))
  }
  try {
    validateBackendSession(inspection.backend)
    validatePublicSession(inspection.public)
    await config.sessions.put(id, { ...stored, backend: inspection.backend })
  } catch {
    return problem(503, 'temporarily_unavailable')
  }
  const view = inspection.public
  return json(200, {
    authenticated: true,
    user: {
      assuranceLevel: view.assuranceLevel,
      email: view.email ?? null,
      expiresAt: view.expiresAt,
      userId: view.userId,
    },
  })
}

async function logout(config: ResolvedConfig, request: Request): Promise<Response> {
  if (!validMutation(config, request)) return problem(403, 'request_rejected')
  const id = readCookie(request, config.cookieNames.session)
  if (id !== null && TOKEN_PATTERN.test(id)) {
    await config.sessions.runExclusive(id, async () => {
      const stored = await config.sessions.get(id)
      await config.sessions.delete(id)
      if (stored !== null) {
        try {
          await config.backend.revoke(stored.backend)
        } catch {
          // The local session is invalidated even if upstream revocation is unavailable.
        }
      }
    })
  }
  return clearSession(config, json(204, undefined))
}

async function installBrowserSession(
  config: ResolvedConfig,
  request: Request,
  backend: BackendSession,
  response: Response,
): Promise<Response> {
  const previousId = readCookie(request, config.cookieNames.session)
  let previous: StoredBrowserSession | null = null
  if (previousId !== null && TOKEN_PATTERN.test(previousId)) {
    try {
      previous = await config.sessions.get(previousId)
    } catch {
      return problem(503, 'temporarily_unavailable')
    }
  }
  const id = randomToken()
  try {
    await config.sessions.put(id, {
      backend,
      expiresAt: Date.now() + config.browserSessionTtlSeconds * 1_000,
    })
  } catch {
    try {
      await config.backend.revoke(backend)
    } catch {
      // The original storage error is returned; secrets are never exposed.
    }
    return problem(503, 'temporarily_unavailable')
  }
  if (previousId !== null && TOKEN_PATTERN.test(previousId)) {
    try {
      await config.sessions.delete(previousId)
    } catch {
      // The newly issued cookie replaces access to the previous local session.
    }
  }
  if (previous !== null) {
    try {
      await config.backend.revoke(previous.backend)
    } catch {
      // Rotation succeeds locally even if upstream cleanup is temporarily unavailable.
    }
  }
  response.headers.append(
    'set-cookie',
    cookie(config, config.cookieNames.session, id, {
      httpOnly: true,
      maxAge: config.browserSessionTtlSeconds,
      sameSite: 'Lax',
    }),
  )
  return response
}

function clearSession(config: ResolvedConfig, response: Response): Response {
  clearCookie(config, response, config.cookieNames.session, true, 'Lax')
  return response
}

function clearPending(config: ResolvedConfig, response: Response): Response {
  clearCookie(config, response, config.cookieNames.pending, true, 'Strict')
  return response
}

function clearFlow(config: ResolvedConfig, response: Response): Response {
  clearCookie(config, response, config.cookieNames.flow, true, 'Lax')
  return response
}

function clearCookie(
  config: ResolvedConfig,
  response: Response,
  name: string,
  httpOnly: boolean,
  sameSite: 'Lax' | 'Strict',
): void {
  response.headers.append(
    'set-cookie',
    `${name}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; ${
      httpOnly ? 'HttpOnly; ' : ''
    }${config.secureCookies ? 'Secure; ' : ''}SameSite=${sameSite}`,
  )
}

function setPendingCookie(
  config: ResolvedConfig,
  response: Response,
  id: string,
  expiresAt: number,
): void {
  const maxAge = Math.max(1, Math.ceil((expiresAt - Date.now()) / 1_000))
  response.headers.append(
    'set-cookie',
    cookie(config, config.cookieNames.pending, id, {
      httpOnly: true,
      maxAge,
      sameSite: 'Strict',
    }),
  )
}

function validMutation(config: ResolvedConfig, request: Request): boolean {
  if (request.headers.get('origin') !== config.origin) return false
  const fetchSite = request.headers.get('sec-fetch-site')
  if (fetchSite !== null && fetchSite !== 'same-origin') return false
  const cookieToken = readCookie(request, config.cookieNames.csrf)
  const headerToken = request.headers.get('x-csrf-token')
  return (
    cookieToken !== null &&
    headerToken !== null &&
    TOKEN_PATTERN.test(cookieToken) &&
    TOKEN_PATTERN.test(headerToken) &&
    constantTimeTextEqual(cookieToken, headerToken)
  )
}

async function readJson(request: Request, limit: number): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase()
  if (contentType !== 'application/json') return null
  const declared = Number(request.headers.get('content-length'))
  if (Number.isFinite(declared) && declared > limit) return null
  if (request.body === null) return null

  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  while (true) {
    const result = await reader.read()
    if (result.done) break
    length += result.value.byteLength
    if (length > limit) {
      await reader.cancel()
      return null
    }
    chunks.push(result.value)
  }
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  try {
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null
    return parsed as Record<string, unknown>
  } catch {
    return null
  }
}

function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get('cookie')
  if (header === null) return null
  let result: string | null = null
  for (const part of header.split(';')) {
    const separator = part.indexOf('=')
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue
    if (result !== null) return null
    result = part.slice(separator + 1).trim()
  }
  return result
}

async function readPendingFlow(
  config: ResolvedConfig,
  request: Request,
): Promise<{ id: string; value: StoredPendingFlow } | null> {
  const id = readCookie(request, config.cookieNames.pending)
  if (id === null || !TOKEN_PATTERN.test(id)) return null
  const value = await config.pendingFlows.get(id)
  return value === null ? null : { id, value }
}

function parseSecondFactorMethod(value: unknown): SecondFactorMethod | null {
  return value === 'totp' || value === 'recovery_code' ? value : null
}

function parseFederatedLinkProof(body: Record<string, unknown>): FederatedLinkProof | null {
  const kind = body.kind
  if (kind !== 'password' && kind !== 'current_passkey_session') return null
  const password = typeof body.password === 'string' ? body.password : undefined
  if (kind === 'password' && (password === undefined || password.length < 1 || password.length > 4_096)) {
    return null
  }
  if (kind === 'current_passkey_session' && password !== undefined) return null

  const hasMethod = body.secondFactorMethod !== undefined
  const hasProof = body.secondFactor !== undefined
  if (hasMethod !== hasProof) return null
  const secondFactorMethod = hasMethod ? parseSecondFactorMethod(body.secondFactorMethod) : null
  const secondFactor = typeof body.secondFactor === 'string' ? body.secondFactor : undefined
  if (hasMethod && (secondFactorMethod === null || secondFactor === undefined)) return null
  if (secondFactor !== undefined && (secondFactor.length < 1 || secondFactor.length > 512)) return null
  return {
    kind,
    ...(password === undefined ? {} : { password }),
    ...(secondFactorMethod === null || secondFactor === undefined
      ? {}
      : { secondFactorMethod, secondFactor }),
  }
}

function cookie(
  config: ResolvedConfig,
  name: string,
  value: string,
  options: { httpOnly: boolean; maxAge: number; sameSite: 'Lax' | 'Strict' },
): string {
  return `${name}=${value}; Path=/; Max-Age=${options.maxAge}; ${
    options.httpOnly ? 'HttpOnly; ' : ''
  }${config.secureCookies ? 'Secure; ' : ''}SameSite=${options.sameSite}; Priority=High`
}

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function constantTimeTextEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left)
  const rightBytes = new TextEncoder().encode(right)
  const size = Math.max(leftBytes.length, rightBytes.length)
  let difference = leftBytes.length ^ rightBytes.length
  for (let index = 0; index < size; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0)
  }
  return difference === 0
}

function callbackUrl(config: ResolvedConfig, provider: string): string {
  return `${config.origin}${config.basePath}/oauth/${provider}/callback`
}

function ownProvider(
  providers: Readonly<Record<string, OAuthProviderAdapter>>,
  name: string,
): OAuthProviderAdapter | null {
  return Object.prototype.hasOwnProperty.call(providers, name) ? (providers[name] ?? null) : null
}

function validateOAuthTransaction(value: OAuthTransaction): void {
  if (!TOKEN_PATTERN.test(value.state) || !TOKEN_PATTERN.test(value.nonce)) {
    throw new Error('invalid OAuth transaction token')
  }
  if (
    value.pkceVerifier.length < 43 ||
    value.pkceVerifier.length > 128 ||
    !/^[A-Za-z0-9._~-]+$/u.test(value.pkceVerifier)
  ) {
    throw new Error('invalid PKCE verifier')
  }
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

function validateIdentity(identity: FederatedIdentity, expectedIssuer: string): void {
  if (identity.issuer !== expectedIssuer) throw new Error('issuer mismatch')
  validateHttpsIssuer(identity.issuer)
  if (identity.subject.length < 1 || identity.subject.length > 255) throw new Error('invalid subject')
  if (identity.email !== undefined && identity.email.length > 320) throw new Error('invalid email')
  if (identity.email === undefined && identity.emailVerified) throw new Error('verified email missing')
  if (identity.displayName !== undefined && identity.displayName.length > 512) {
    throw new Error('invalid display name')
  }
}

function validateBackendSession(session: BackendSession): void {
  if (
    session.accessToken.length < 16 ||
    session.refreshToken.length < 16 ||
    !Number.isFinite(Date.parse(session.expiresAt))
  ) {
    throw new Error('invalid backend session')
  }
}

function validatePasswordOutcome(outcome: PasswordBackendOutcome): void {
  if (outcome.kind === 'authenticated') {
    validateBackendSession(outcome.session)
    return
  }
  validateBearerExpiry(outcome.challengeToken, outcome.expiresAt)
  if (
    outcome.methods.length < 1 ||
    outcome.methods.length > 2 ||
    new Set(outcome.methods).size !== outcome.methods.length ||
    outcome.methods.some((method) => parseSecondFactorMethod(method) === null)
  ) {
    throw new Error('invalid second-factor methods')
  }
}

function validateFederatedOutcome(outcome: FederatedBackendOutcome): void {
  if (outcome.kind === 'authenticated') {
    validateBackendSession(outcome.session)
    return
  }
  if (outcome.kind === 'registration_required') return
  if (outcome.linkUserId.length < 1 || outcome.linkUserId.length > 255) {
    throw new Error('invalid link user')
  }
  validateBearerExpiry(outcome.linkToken, outcome.expiresAt)
}

function validateBearerExpiry(token: string, expiresAt: string): void {
  const expiry = Date.parse(expiresAt)
  if (!TOKEN_PATTERN.test(token) || !Number.isFinite(expiry) || expiry <= Date.now()) {
    throw new Error('invalid pending bearer')
  }
}

function validatePasskeyOptions(value: Record<string, unknown>, limit: number): void {
  const serialized = JSON.stringify(value)
  if (
    !isRecord(value) ||
    new TextEncoder().encode(serialized).byteLength > limit ||
    typeof value.challenge !== 'string' ||
    value.challenge.length < 16 ||
    value.challenge.length > 2_048 ||
    value.userVerification !== 'required'
  ) {
    throw new Error('invalid passkey options')
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function validatePublicSession(session: PublicSession): void {
  if (session.userId.length < 1 || session.userId.length > 255) throw new Error('invalid user id')
  if (!['aal1', 'aal2', 'aal3'].includes(session.assuranceLevel)) {
    throw new Error('invalid assurance level')
  }
  if (!Number.isFinite(Date.parse(session.expiresAt))) throw new Error('invalid expiry')
  if (session.email !== undefined && session.email.length > 320) throw new Error('invalid email')
}

function resolveConfig(config: AuthBffConfig): ResolvedConfig {
  const publicUrl = new URL(config.publicOrigin)
  if (publicUrl.username || publicUrl.password || publicUrl.search || publicUrl.hash) {
    throw new Error('publicOrigin must be an origin')
  }
  if (publicUrl.pathname !== '/') throw new Error('publicOrigin must be an origin')
  const isSecure = publicUrl.protocol === 'https:'
  const loopback = isLoopback(publicUrl.hostname)
  if (!isSecure && !(config.allowInsecureLoopback === true && publicUrl.protocol === 'http:' && loopback)) {
    throw new Error('publicOrigin must use HTTPS')
  }
  const origin = publicUrl.origin
  const basePath = config.basePath ?? '/auth'
  if (!/^\/[a-z0-9/_-]*$/u.test(basePath) || basePath.endsWith('/') || basePath.includes('//')) {
    throw new Error('invalid basePath')
  }
  const providerEntries = Object.entries(config.providers)
  if (providerEntries.length < 1) throw new Error('at least one provider is required')
  for (const [name, provider] of providerEntries) {
    if (!PROVIDER_PATTERN.test(name)) throw new Error('invalid provider name')
    validateHttpsIssuer(provider.issuer)
  }
  const securePrefix = isSecure ? '__Host-ska-' : 'ska-dev-'
  return {
    origin,
    basePath,
    postLoginUrl: sameOriginUrl(origin, config.postLoginPath ?? '/'),
    oauthErrorUrl: sameOriginUrl(origin, config.oauthErrorPath ?? '/login?error=oauth'),
    linkRequiredUrl: sameOriginUrl(origin, config.linkRequiredPath ?? '/login?flow=link'),
    registrationRequiredUrl: sameOriginUrl(
      origin,
      config.registrationRequiredPath ?? '/register?flow=federated',
    ),
    providers: Object.freeze(Object.fromEntries(providerEntries)),
    backend: config.backend,
    transactions: config.transactions,
    sessions: config.sessions,
    pendingFlows: config.pendingFlows,
    ...(config.passkeys === undefined ? {} : { passkeys: config.passkeys }),
    transactionTtlSeconds: positiveInteger(config.transactionTtlSeconds ?? 600, 'transaction TTL'),
    browserSessionTtlSeconds: positiveInteger(
      config.browserSessionTtlSeconds ?? 28_800,
      'browser session TTL',
    ),
    maxJsonBytes: positiveInteger(config.maxJsonBytes ?? 16_384, 'JSON limit'),
    cookieNames: {
      csrf: `${securePrefix}csrf`,
      flow: `${securePrefix}flow`,
      pending: `${securePrefix}pending`,
      session: `${securePrefix}session`,
    },
    secureCookies: isSecure,
  }
}

function validateHttpsIssuer(value: string): void {
  const issuer = new URL(value)
  if (
    issuer.protocol !== 'https:' ||
    issuer.username ||
    issuer.password ||
    issuer.search ||
    issuer.hash ||
    (issuer.href !== value && !(issuer.pathname === '/' && issuer.origin === value))
  ) {
    throw new Error('invalid provider issuer')
  }
}

function sameOriginUrl(origin: string, path: string): string {
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\')) {
    throw new Error('redirect must be a same-origin path')
  }
  const url = new URL(path, origin)
  if (url.origin !== origin) throw new Error('redirect must be same-origin')
  return url.href
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]'
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`invalid ${label}`)
  return value
}

function securityHeaders(): Headers {
  return new Headers({
    'cache-control': 'no-store, max-age=0',
    'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    'cross-origin-resource-policy': 'same-origin',
    pragma: 'no-cache',
    'referrer-policy': 'no-referrer',
    vary: 'Origin, Sec-Fetch-Site',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  })
}

function json(status: number, body: unknown): Response {
  const headers = securityHeaders()
  if (body === undefined) return new Response(null, { status, headers })
  headers.set('content-type', 'application/json; charset=utf-8')
  return new Response(JSON.stringify(body), { status, headers })
}

function problem(status: number, code: string): Response {
  return json(status, { error: code })
}

function redirect(location: string): Response {
  const headers = securityHeaders()
  headers.set('location', location)
  return new Response(null, { status: 303, headers })
}

function methodNotAllowed(allow: string): Response {
  const response = problem(405, 'method_not_allowed')
  response.headers.set('allow', allow)
  return response
}
