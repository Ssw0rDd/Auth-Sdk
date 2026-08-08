import { describe, expect, it, vi } from 'vitest'

import { BrowserAuthClient, BrowserAuthError } from './index'

const csrfToken = 'csrf_0123456789abcdefghijklmnopqrstuvwxyzABCDEF'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('BrowserAuthClient', () => {
  it('sends passwords only to the same-origin BFF with an in-memory CSRF token', async () => {
    const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([input, init])
      if (String(input).endsWith('/csrf')) return json({ csrfToken })
      return new Response(null, { status: 204 })
    })
    const client = new BrowserAuthClient({
      baseUrl: 'https://app.example.com/auth',
      fetch: fetcher,
    })
    await client.password({ email: ' owner@example.com ', password: 'legacy' })
    expect(calls).toHaveLength(2)
    expect(calls[1]?.[0]).toBe('https://app.example.com/auth/password')
    expect(calls[1]?.[1]?.credentials).toBe('same-origin')
    expect(new Headers(calls[1]?.[1]?.headers).get('x-csrf-token')).toBe(csrfToken)
    expect(calls[1]?.[1]?.body).toBe(
      JSON.stringify({ email: 'owner@example.com', password: 'legacy' }),
    )
  })

  it('coalesces concurrent CSRF acquisition', async () => {
    let csrfCalls = 0
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith('/csrf')) {
        csrfCalls += 1
        await Promise.resolve()
        return json({ csrfToken })
      }
      return new Response(null, { status: 204 })
    })
    const client = new BrowserAuthClient({ baseUrl: 'https://app.example.com/auth', fetch: fetcher })
    await Promise.all([
      client.password({ email: 'a@example.com', password: 'a' }),
      client.password({ email: 'b@example.com', password: 'b' }),
    ])
    expect(csrfCalls).toBe(1)
  })

  it('refreshes CSRF once after an expired-token rejection', async () => {
    let csrfCalls = 0
    let mutationCalls = 0
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith('/csrf')) {
        csrfCalls += 1
        return json({ csrfToken: `${csrfToken}${csrfCalls}` })
      }
      mutationCalls += 1
      return mutationCalls === 1
        ? json({ error: 'request_rejected' }, 403)
        : new Response(null, { status: 204 })
    })
    const client = new BrowserAuthClient({ baseUrl: 'https://app.example.com/auth', fetch: fetcher })
    await client.logout()
    expect(csrfCalls).toBe(2)
    expect(mutationCalls).toBe(2)
  })

  it('accepts only secret-free HTTPS authorization URLs', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith('/csrf')
        ? json({ csrfToken })
        : json({
            authorizationUrl:
              'https://accounts.example/authorize?state=public-state&code_verifier=server-secret',
          }),
    )
    const client = new BrowserAuthClient({ baseUrl: 'https://app.example.com/auth', fetch: fetcher })
    await expect(client.startProvider('google')).rejects.toMatchObject({
      code: 'invalid_response',
    })
  })

  it('refuses a cross-origin or insecure BFF base URL', () => {
    expect(
      () =>
        new BrowserAuthClient({
          baseUrl: 'https://api.evil.example/auth',
          browserOrigin: 'https://app.example.com',
        }),
    ).toThrow(/same-origin/u)
    expect(
      () =>
        new BrowserAuthClient({
          baseUrl: 'http://app.example.com/auth',
          browserOrigin: 'http://app.example.com',
        }),
    ).toThrow(/HTTPS/u)
  })

  it('returns a typed public session without accepting token-shaped fields', async () => {
    const fetcher = vi.fn(async () =>
      json({
        authenticated: true,
        user: {
          userId: 'user-42',
          email: 'owner@example.com',
          assuranceLevel: 'aal2',
          expiresAt: '2026-08-08T20:00:00Z',
          accessToken: 'must-not-cross-the-boundary',
        },
      }),
    )
    const client = new BrowserAuthClient({ baseUrl: 'https://app.example.com/auth', fetch: fetcher })
    const session = await client.session()
    expect(session).toEqual({
      authenticated: true,
      user: {
        userId: 'user-42',
        email: 'owner@example.com',
        assuranceLevel: 'aal2',
        expiresAt: '2026-08-08T20:00:00Z',
      },
    })
    expect(JSON.stringify(session)).not.toContain('must-not-cross-the-boundary')
  })

  it('uses a stable safe error shape', async () => {
    const client = new BrowserAuthClient({
      baseUrl: 'https://app.example.com/auth',
      fetch: vi.fn(async () => json({ error: 'authentication_failed', detail: 'db secret' }, 401)),
    })
    await expect(client.session()).rejects.toEqual(
      new BrowserAuthError(401, 'authentication_failed'),
    )
  })

  it('returns an allowlisted MFA continuation and completes it through the BFF', async () => {
    const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([input, init])
      if (String(input).endsWith('/csrf')) return json({ csrfToken })
      if (String(input).endsWith('/password')) {
        return json(
          {
            status: 'second_factor_required',
            methods: ['totp', 'recovery_code'],
            expiresAt: new Date(Date.now() + 300_000).toISOString(),
            challengeToken: 'must-not-be-accepted',
          },
          202,
        )
      }
      return new Response(null, { status: 204 })
    })
    const client = new BrowserAuthClient({ baseUrl: 'https://app.example.com/auth', fetch: fetcher })
    const progress = await client.password({
      email: 'owner@example.com',
      password: 'secret',
      rememberMe: true,
    })
    expect(progress).toMatchObject({
      status: 'second_factor_required',
      methods: ['totp', 'recovery_code'],
    })
    expect(JSON.stringify(progress)).not.toContain('challengeToken')

    await client.completeSecondFactor({ method: 'totp', proof: '123456', trustDevice: true })
    expect(calls.at(-1)?.[0]).toBe('https://app.example.com/auth/mfa/complete')
    expect(calls.at(-1)?.[1]?.body).toBe(
      JSON.stringify({ method: 'totp', proof: '123456', trustDevice: true }),
    )
  })

  it('supports explicit account-link proof and pending-flow cancellation', async () => {
    const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([input, init])
      return String(input).endsWith('/csrf')
        ? json({ csrfToken })
        : new Response(null, { status: 204 })
    })
    const client = new BrowserAuthClient({ baseUrl: 'https://app.example.com/auth', fetch: fetcher })
    await client.completeFederatedLink({
      kind: 'password',
      password: 'secret',
      secondFactorMethod: 'recovery_code',
      secondFactor: 'AAAA-BBBB-CCCC',
    })
    expect(calls.at(-1)?.[0]).toBe('https://app.example.com/auth/link/complete')
    await client.cancelPendingFlow()
    expect(calls.at(-1)?.[0]).toBe('https://app.example.com/auth/flow/cancel')
  })

  it('passes rememberMe as a non-secret provider preference', async () => {
    let mutationBody: BodyInit | null | undefined
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/csrf')) return json({ csrfToken })
      mutationBody = init?.body
      return json({ authorizationUrl: 'https://accounts.example/authorize?state=public' })
    })
    const client = new BrowserAuthClient({ baseUrl: 'https://app.example.com/auth', fetch: fetcher })
    await client.startProvider('google', { rememberMe: true })
    expect(mutationBody).toBe(JSON.stringify({ rememberMe: true }))
  })

  it('performs a passkey ceremony and sends only the public credential response', async () => {
    const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    const credentials = {
      get: vi.fn(async (_options: CredentialRequestOptions) => ({
        id: 'credential-id',
        rawId: new TextEncoder().encode('credential-id').buffer,
        type: 'public-key',
        response: {
          authenticatorData: new TextEncoder().encode('auth').buffer,
          clientDataJSON: new TextEncoder().encode('client').buffer,
          signature: new TextEncoder().encode('signature').buffer,
          userHandle: null,
        },
        getClientExtensionResults: () => ({}),
      })),
    }
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push([input, init])
      if (String(input).endsWith('/csrf')) return json({ csrfToken })
      if (String(input).endsWith('/passkey/login/start')) {
        return json({
          publicKey: {
            challenge: 'cHVibGljLWNoYWxsZW5nZQ',
            rpId: 'app.example.com',
            userVerification: 'required',
            allowCredentials: [{ type: 'public-key', id: 'Y3JlZGVudGlhbC1pZA' }],
          },
          expiresAt: new Date(Date.now() + 300_000).toISOString(),
        })
      }
      return new Response(null, { status: 204 })
    })
    const client = new BrowserAuthClient({
      baseUrl: 'https://app.example.com/auth',
      fetch: fetcher,
      credentials,
    })
    await client.passkey({ email: 'owner@example.com', rememberMe: true })
    expect(credentials.get).toHaveBeenCalledOnce()
    const options = credentials.get.mock.calls[0]?.[0] as CredentialRequestOptions
    expect(options.publicKey?.challenge).toBeInstanceOf(ArrayBuffer)
    const completion = String(calls.at(-1)?.[1]?.body)
    expect(completion).toContain('credential-id')
    expect(completion).not.toContain('ceremony_')
  })
})
