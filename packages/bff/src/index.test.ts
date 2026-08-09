import { describe, expect, it, vi } from 'vitest'

import {
  MemoryBrowserSessionStore,
  MemoryOAuthTransactionStore,
  MemoryPendingFlowStore,
  createAuthBff,
  AuthenticationRejectedError,
  type AuthBackend,
  type BackendSessionInspection,
  type BackendSession,
  type FederatedBackendOutcome,
  type FederatedIdentity,
  type OAuthProviderAdapter,
  type OAuthTransaction,
  type PasswordBackendOutcome,
  type PasskeyBackend,
} from './index'

const origin = 'https://app.example.com'

class FakeProvider implements OAuthProviderAdapter {
  readonly issuer = 'https://issuer.example'
  readonly begin = vi.fn(async () => {
    const transaction: OAuthTransaction = {
      state: 'state_0123456789abcdefghijklmnopqrstuvwxyzABCDE',
      nonce: 'nonce_0123456789abcdefghijklmnopqrstuvwxyzABCDE',
      pkceVerifier: 'verifier_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    }
    return {
      authorizationUrl: `https://issuer.example/authorize?state=${transaction.state}`,
      transaction,
    }
  })
  readonly exchange = vi.fn(async (): Promise<FederatedIdentity> => ({
    issuer: this.issuer,
    subject: 'provider-user-42',
    email: 'owner@example.com',
    emailVerified: true,
    displayName: 'Owner',
  }))
}

class FakeBackend implements AuthBackend {
  readonly password = vi.fn(async (): Promise<PasswordBackendOutcome> => ({
    kind: 'authenticated',
    session: backendSession(),
  }))
  readonly completeSecondFactor = vi.fn(async (): Promise<BackendSession> => backendSession())
  readonly federated = vi.fn(async (): Promise<FederatedBackendOutcome> => ({
    kind: 'authenticated' as const,
    session: backendSession(),
  }))
  readonly completeFederatedLink = vi.fn(async () => {})
  readonly inspect = vi.fn(async (): Promise<BackendSessionInspection | null> => ({
    backend: backendSession(),
    public: {
      userId: 'user-42',
      email: 'owner@example.com',
      assuranceLevel: 'aal1',
      expiresAt: '2026-08-08T20:00:00Z',
    },
  }))
  readonly revoke = vi.fn(async () => {})
}

class FakePasskeys implements PasskeyBackend {
  readonly beginLogin = vi.fn(async () => ({
    ceremonyToken: 'ceremony_0123456789abcdefghijklmnopqrstuvwxyzABCDE',
    publicKey: {
      challenge: 'public_challenge',
      rpId: 'app.example.com',
      userVerification: 'required',
    },
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
  }))
  readonly finishLogin = vi.fn(async () => backendSession())
}

function backendSession(): BackendSession {
  return {
    accessToken: 'server-access-secret',
    refreshToken: 'server-refresh-secret',
    expiresAt: '2026-08-09T00:00:00Z',
  }
}

function createFixture() {
  const provider = new FakeProvider()
  const backend = new FakeBackend()
  const passkeys = new FakePasskeys()
  const handle = createAuthBff({
    publicOrigin: origin,
    providers: { google: provider },
    backend,
    transactions: new MemoryOAuthTransactionStore(),
    sessions: new MemoryBrowserSessionStore(),
    pendingFlows: new MemoryPendingFlowStore(),
    passkeys,
    postLoginPath: '/account',
    oauthErrorPath: '/login?error=oauth',
    linkRequiredPath: '/login?flow=link',
    registrationRequiredPath: '/register?flow=federated',
  })
  return { backend, handle, passkeys, provider }
}

function cookieValue(response: Response, name: string): string {
  const value = response.headers.get('set-cookie')?.match(new RegExp(`${name}=([^;,]+)`))?.[1]
  if (!value) throw new Error(`missing ${name} cookie`)
  return value
}

async function csrf(handle: (request: Request) => Promise<Response>) {
  const response = await handle(new Request(`${origin}/auth/csrf`))
  const token = cookieValue(response, '__Host-ska-csrf')
  return { cookie: `__Host-ska-csrf=${token}`, token }
}

function post(path: string, body: unknown, token: string, cookie: string, extra?: HeadersInit) {
  return new Request(`${origin}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie,
      origin,
      'sec-fetch-site': 'same-origin',
      'x-csrf-token': token,
      ...extra,
    },
    body: JSON.stringify(body),
  })
}

describe('createAuthBff', () => {
  it('blocks cross-origin login before credentials reach the backend', async () => {
    const { backend, handle } = createFixture()
    const response = await handle(
      new Request(`${origin}/auth/password`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'https://evil.example',
          'sec-fetch-site': 'cross-site',
        },
        body: JSON.stringify({ email: 'owner@example.com', password: 'secret' }),
      }),
    )
    expect(response.status).toBe(403)
    expect(backend.password).not.toHaveBeenCalled()
  })

  it('requires a matching double-submit CSRF token', async () => {
    const { backend, handle } = createFixture()
    const issued = await csrf(handle)
    const response = await handle(
      post('/auth/password', { email: 'owner@example.com', password: 'secret' }, 'wrong', issued.cookie),
    )
    expect(response.status).toBe(403)
    expect(backend.password).not.toHaveBeenCalled()
  })

  it('keeps provider and SDK tokens out of browser-visible responses', async () => {
    const { handle } = createFixture()
    const issued = await csrf(handle)
    const start = await handle(post('/auth/oauth/google/start', {}, issued.token, issued.cookie))
    expect(start.status).toBe(200)
    const startBody = await start.text()
    expect(startBody).toContain('https://issuer.example/authorize')
    expect(startBody).not.toContain('verifier_')
    expect(startBody).not.toContain('server-access-secret')
    const flow = cookieValue(start, '__Host-ska-flow')

    const callback = await handle(
      new Request(
        `${origin}/auth/oauth/google/callback?code=valid-code&state=state_0123456789abcdefghijklmnopqrstuvwxyzABCDE`,
        { headers: { cookie: `__Host-ska-flow=${flow}` } },
      ),
    )
    expect(callback.status).toBe(303)
    expect(callback.headers.get('location')).toBe(`${origin}/account`)
    const browserOutput = `${callback.headers.get('set-cookie')} ${await callback.text()}`
    expect(browserOutput).not.toContain('server-access-secret')
    expect(browserOutput).not.toContain('server-refresh-secret')
    expect(browserOutput).not.toContain('verifier_')
    expect(cookieValue(callback, '__Host-ska-session')).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('binds OAuth state to the initiating browser and consumes it once', async () => {
    const { backend, handle } = createFixture()
    const issued = await csrf(handle)
    const start = await handle(post('/auth/oauth/google/start', {}, issued.token, issued.cookie))
    const state = 'state_0123456789abcdefghijklmnopqrstuvwxyzABCDE'
    const wrongBrowser = await handle(
      new Request(`${origin}/auth/oauth/google/callback?code=valid-code&state=${state}`, {
        headers: { cookie: '__Host-ska-flow=another_browser_binding_012345678901234567890' },
      }),
    )
    expect(wrongBrowser.status).toBe(400)
    expect(backend.federated).not.toHaveBeenCalled()

    const replay = await handle(
      new Request(`${origin}/auth/oauth/google/callback?code=valid-code&state=${state}`, {
        headers: { cookie: `__Host-ska-flow=${cookieValue(start, '__Host-ska-flow')}` },
      }),
    )
    expect(replay.status).toBe(400)
    expect(backend.federated).not.toHaveBeenCalled()
  })

  it('rejects provider mix-up and duplicate callback parameters', async () => {
    const { handle } = createFixture()
    const issued = await csrf(handle)
    const start = await handle(post('/auth/oauth/google/start', {}, issued.token, issued.cookie))
    const flow = cookieValue(start, '__Host-ska-flow')
    const state = 'state_0123456789abcdefghijklmnopqrstuvwxyzABCDE'
    const response = await handle(
      new Request(`${origin}/auth/oauth/github/callback?code=a&code=b&state=${state}`, {
        headers: { cookie: `__Host-ska-flow=${flow}` },
      }),
    )
    expect(response.status).toBe(400)
  })

  it('returns only an allowlisted public session projection', async () => {
    const { handle } = createFixture()
    const issued = await csrf(handle)
    const login = await handle(
      post('/auth/password', { email: ' owner@example.com ', password: 'secret' }, issued.token, issued.cookie),
    )
    const sessionCookie = cookieValue(login, '__Host-ska-session')
    const response = await handle(
      new Request(`${origin}/auth/session`, {
        headers: { cookie: `__Host-ska-session=${sessionCookie}` },
      }),
    )
    expect(response.status).toBe(200)
    const body = await response.text()
    expect(body).toContain('user-42')
    expect(body).not.toContain('server-access-secret')
    expect(body).not.toContain('server-refresh-secret')
  })

  it('distinguishes rejected credentials from an internal backend outage', async () => {
    const invalid = createFixture()
    const invalidCsrf = await csrf(invalid.handle)
    invalid.backend.password.mockRejectedValueOnce(new AuthenticationRejectedError())
    const rejected = await invalid.handle(
      post(
        '/auth/password',
        { email: 'owner@example.com', password: 'wrong' },
        invalidCsrf.token,
        invalidCsrf.cookie,
      ),
    )
    expect(rejected.status).toBe(401)
    expect(await rejected.json()).toEqual({ error: 'authentication_failed' })

    const outage = createFixture()
    const outageCsrf = await csrf(outage.handle)
    outage.backend.password.mockRejectedValueOnce(new Error('database host secret.internal failed'))
    const unavailable = await outage.handle(
      post(
        '/auth/password',
        { email: 'owner@example.com', password: 'secret' },
        outageCsrf.token,
        outageCsrf.cookie,
      ),
    )
    expect(unavailable.status).toBe(503)
    expect(await unavailable.text()).not.toContain('secret.internal')
  })

  it('rejects open redirects during construction', () => {
    const provider = new FakeProvider()
    const backend = new FakeBackend()
    expect(() =>
      createAuthBff({
        publicOrigin: origin,
        providers: { google: provider },
        backend,
        transactions: new MemoryOAuthTransactionStore(),
        sessions: new MemoryBrowserSessionStore(),
        pendingFlows: new MemoryPendingFlowStore(),
        postLoginPath: '//evil.example/stolen',
      }),
    ).toThrow(/same-origin/u)
  })

  it('keeps an MFA challenge server-side and consumes it only after a valid proof', async () => {
    const { backend, handle } = createFixture()
    backend.password.mockResolvedValueOnce({
      kind: 'second_factor_required',
      challengeToken: 'challenge_0123456789abcdefghijklmnopqrstuvwxyzABC',
      methods: ['totp', 'recovery_code'],
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
    })
    const issued = await csrf(handle)
    const first = await handle(
      post('/auth/password', { email: 'owner@example.com', password: 'secret' }, issued.token, issued.cookie),
    )
    expect(first.status).toBe(202)
    expect(await first.json()).toMatchObject({
      status: 'second_factor_required',
      methods: ['totp', 'recovery_code'],
    })
    expect(first.headers.get('set-cookie')).not.toContain('challenge_')
    const pending = cookieValue(first, '__Host-ska-pending')

    backend.completeSecondFactor.mockRejectedValueOnce(new AuthenticationRejectedError())
    const rejected = await handle(
      post(
        '/auth/mfa/complete',
        { method: 'totp', proof: '000000', trustDevice: false },
        issued.token,
        `${issued.cookie}; __Host-ska-pending=${pending}`,
      ),
    )
    expect(rejected.status).toBe(401)

    const completed = await handle(
      post(
        '/auth/mfa/complete',
        { method: 'totp', proof: '123456', trustDevice: true },
        issued.token,
        `${issued.cookie}; __Host-ska-pending=${pending}`,
      ),
    )
    expect(completed.status).toBe(204)
    expect(backend.completeSecondFactor).toHaveBeenLastCalledWith({
      challengeToken: 'challenge_0123456789abcdefghijklmnopqrstuvwxyzABC',
      method: 'totp',
      proof: '123456',
      trustDevice: true,
    })
    expect(completed.headers.get('set-cookie')).not.toContain('challenge_')
  })

  it('holds a federated link secret server-side and requires a local session plus fresh proof', async () => {
    const { backend, handle } = createFixture()
    backend.federated.mockResolvedValueOnce({
      kind: 'link_required',
      linkUserId: 'user-42',
      linkToken: 'link_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG',
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
    })
    const issued = await csrf(handle)
    const start = await handle(post('/auth/oauth/google/start', {}, issued.token, issued.cookie))
    const callback = await handle(
      new Request(
        `${origin}/auth/oauth/google/callback?code=valid&state=state_0123456789abcdefghijklmnopqrstuvwxyzABCDE`,
        { headers: { cookie: `__Host-ska-flow=${cookieValue(start, '__Host-ska-flow')}` } },
      ),
    )
    expect(callback.status).toBe(303)
    expect(callback.headers.get('location')).toBe(`${origin}/login?flow=link`)
    expect(callback.headers.get('set-cookie')).not.toContain('link_')
    const pending = cookieValue(callback, '__Host-ska-pending')

    const unauthenticated = await handle(
      post(
        '/auth/link/complete',
        { kind: 'password', password: 'secret' },
        issued.token,
        `${issued.cookie}; __Host-ska-pending=${pending}`,
      ),
    )
    expect(unauthenticated.status).toBe(401)
    expect(backend.completeFederatedLink).not.toHaveBeenCalled()

    const login = await handle(
      post('/auth/password', { email: 'owner@example.com', password: 'secret' }, issued.token, issued.cookie),
    )
    const browserSession = cookieValue(login, '__Host-ska-session')
    const linked = await handle(
      post(
        '/auth/link/complete',
        { kind: 'password', password: 'secret', secondFactorMethod: 'totp', secondFactor: '123456' },
        issued.token,
        `${issued.cookie}; __Host-ska-pending=${pending}; __Host-ska-session=${browserSession}`,
      ),
    )
    expect(linked.status).toBe(204)
    expect(backend.completeFederatedLink).toHaveBeenCalledWith({
      session: backendSession(),
      linkToken: 'link_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG',
      proof: {
        kind: 'password',
        password: 'secret',
        secondFactorMethod: 'totp',
        secondFactor: '123456',
      },
    })
  })

  it('redirects registration-required identities without creating a session', async () => {
    const { backend, handle } = createFixture()
    backend.federated.mockResolvedValueOnce({ kind: 'registration_required' })
    const issued = await csrf(handle)
    const start = await handle(post('/auth/oauth/google/start', {}, issued.token, issued.cookie))
    const callback = await handle(
      new Request(
        `${origin}/auth/oauth/google/callback?code=valid&state=state_0123456789abcdefghijklmnopqrstuvwxyzABCDE`,
        { headers: { cookie: `__Host-ska-flow=${cookieValue(start, '__Host-ska-flow')}` } },
      ),
    )
    expect(callback.status).toBe(303)
    expect(callback.headers.get('location')).toBe(`${origin}/register?flow=federated`)
    expect(callback.headers.get('set-cookie')).not.toContain('__Host-ska-session=')
  })

  it('keeps the passkey ceremony handle server-side across the browser ceremony', async () => {
    const { handle, passkeys } = createFixture()
    const issued = await csrf(handle)
    const started = await handle(
      post(
        '/auth/passkey/login/start',
        { email: 'owner@example.com', rememberMe: true },
        issued.token,
        issued.cookie,
      ),
    )
    expect(started.status).toBe(200)
    expect(await started.json()).toMatchObject({
      publicKey: { challenge: 'public_challenge', userVerification: 'required' },
    })
    expect(started.headers.get('set-cookie')).not.toContain('ceremony_')
    const pending = cookieValue(started, '__Host-ska-pending')

    const completed = await handle(
      post(
        '/auth/passkey/login/complete',
        {
          credential: {
            id: 'credential-id',
            rawId: 'Y3JlZGVudGlhbA',
            type: 'public-key',
            response: {
              authenticatorData: 'YXV0aA',
              clientDataJSON: 'Y2xpZW50',
              signature: 'c2lnbmF0dXJl',
              userHandle: null,
            },
          },
        },
        issued.token,
        `${issued.cookie}; __Host-ska-pending=${pending}`,
      ),
    )
    expect(completed.status).toBe(204)
    expect(passkeys.finishLogin).toHaveBeenCalledWith({
      ceremonyToken: 'ceremony_0123456789abcdefghijklmnopqrstuvwxyzABCDE',
      responseJson: expect.stringContaining('credential-id'),
    })
  })

  it('serializes concurrent session inspection to protect refresh rotation from false replay', async () => {
    const { backend, handle } = createFixture()
    const issued = await csrf(handle)
    const login = await handle(
      post('/auth/password', { email: 'owner@example.com', password: 'secret' }, issued.token, issued.cookie),
    )
    const session = cookieValue(login, '__Host-ska-session')
    let active = 0
    let maximum = 0
    backend.inspect.mockImplementation(async () => {
      active += 1
      maximum = Math.max(maximum, active)
      await new Promise((resolve) => setTimeout(resolve, 5))
      active -= 1
      return {
        backend: backendSession(),
        public: {
          userId: 'user-42',
          email: 'owner@example.com',
          assuranceLevel: 'aal1',
          expiresAt: '2099-08-08T20:00:00Z',
        },
      }
    })
    await Promise.all([
      handle(new Request(`${origin}/auth/session`, { headers: { cookie: `__Host-ska-session=${session}` } })),
      handle(new Request(`${origin}/auth/session`, { headers: { cookie: `__Host-ska-session=${session}` } })),
    ])
    expect(maximum).toBe(1)
  })

  it('registers and verifies email without exposing delivery secrets', async () => {
    const registration = {
      register: vi.fn(async () => {}),
      verifyEmail: vi.fn(async () => {}),
    }
    const provider = new FakeProvider()
    const backend = new FakeBackend()
    const handle = createAuthBff({
      publicOrigin: origin,
      providers: { google: provider },
      backend,
      transactions: new MemoryOAuthTransactionStore(),
      sessions: new MemoryBrowserSessionStore(),
      pendingFlows: new MemoryPendingFlowStore(),
      registration,
    })
    const issued = await csrf(handle)
    const created = await handle(
      post(
        '/auth/register',
        { email: 'new@example.com', password: 'super-secret-pass' },
        issued.token,
        issued.cookie,
      ),
    )
    expect(created.status).toBe(204)
    expect(registration.register).toHaveBeenCalledWith({
      email: 'new@example.com',
      password: 'super-secret-pass',
    })
    const body = await created.text()
    expect(body).toBe('')

    const token = 'a'.repeat(40)
    const verified = await handle(
      post('/auth/email/verify', { token }, issued.token, issued.cookie),
    )
    expect(verified.status).toBe(204)
    expect(registration.verifyEmail).toHaveBeenCalledWith({ token })
  })

  it('returns not_found when registration is not configured', async () => {
    const { handle } = createFixture()
    const issued = await csrf(handle)
    const response = await handle(
      post(
        '/auth/register',
        { email: 'new@example.com', password: 'super-secret-pass' },
        issued.token,
        issued.cookie,
      ),
    )
    expect(response.status).toBe(404)
  })
})
