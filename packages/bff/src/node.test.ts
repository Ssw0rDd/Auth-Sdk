import { describe, expect, it, vi } from 'vitest'

import { createNativeOAuthAdapter, createNodeAuthBackend, createNodePasskeyBackend } from './node'

const authentication = {
  userId: 'user-42',
  email: 'owner@example.com',
  assuranceLevel: 'aal2',
  sessionId: 'session-42',
  accessToken: 'native-access-secret',
  refreshToken: 'native-refresh-secret',
  accessExpiresAt: '2026-08-08T20:00:00Z',
  sessionExpiresAt: '2026-08-09T00:00:00Z',
}

describe('Node adapters', () => {
  it('maps native password, MFA, federation and link outcomes without exposing native types', async () => {
    const service = {
      login: vi.fn(async () => ({
        kind: 'second_factor_required',
        challengeToken: 'challenge_0123456789abcdefghijklmnopqrstuvwxyzABC',
        methods: ['totp', 'recovery_code'],
        challengeExpiresAt: new Date(Date.now() + 300_000).toISOString(),
      })),
      completeLogin: vi.fn(async () => authentication),
      beginVerifiedFederatedLogin: vi.fn(async () => ({
        kind: 'link_required',
        linkUserId: 'user-42',
        linkToken: 'link_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG',
        linkExpiresAt: new Date(Date.now() + 300_000).toISOString(),
      })),
      completeFederatedLink: vi.fn(async () => ({ identityId: 'identity-1' })),
      inspectAccess: vi.fn(async () => ({
        userId: 'user-42',
        email: 'owner@example.com',
        assuranceLevel: 'aal2',
        sessionExpiresAt: '2026-08-09T00:00:00Z',
      })),
      refresh: vi.fn(async () => authentication),
      logout: vi.fn(async () => {}),
    }
    const backend = createNodeAuthBackend({ realmId: 'realm-1', service })
    await expect(
      backend.password({ email: 'owner@example.com', password: 'secret', rememberMe: true }),
    ).resolves.toMatchObject({ kind: 'second_factor_required', methods: ['totp', 'recovery_code'] })
    await expect(
      backend.completeSecondFactor({
        challengeToken: 'challenge_0123456789abcdefghijklmnopqrstuvwxyzABC',
        method: 'totp',
        proof: '123456',
        trustDevice: true,
      }),
    ).resolves.toMatchObject({ accessToken: 'native-access-secret' })
    await expect(
      backend.federated({
        provider: 'google',
        identity: {
          issuer: 'https://accounts.google.com',
          subject: 'subject-1',
          email: 'owner@example.com',
          emailVerified: true,
        },
        rememberMe: false,
      }),
    ).resolves.toMatchObject({ kind: 'link_required', linkUserId: 'user-42' })

    const session = {
      accessToken: 'native-access-secret',
      refreshToken: 'native-refresh-secret',
      expiresAt: '2099-08-08T20:00:00Z',
    }
    await backend.completeFederatedLink({
      session,
      linkToken: 'link_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG',
      proof: { kind: 'password', password: 'secret' },
    })
    expect(service.completeFederatedLink).toHaveBeenCalledWith(
      'realm-1',
      'native-access-secret',
      'link_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG',
      { kind: 'password', password: 'secret' },
    )
  })

  it('refreshes an expiring access token and persists the rotated backend session', async () => {
    const refreshed = { ...authentication, accessExpiresAt: '2099-08-08T20:00:00Z' }
    const service = {
      login: vi.fn(),
      completeLogin: vi.fn(),
      beginVerifiedFederatedLogin: vi.fn(),
      completeFederatedLink: vi.fn(),
      inspectAccess: vi.fn(async () => ({
        userId: 'user-42',
        email: 'owner@example.com',
        assuranceLevel: 'aal2',
        sessionExpiresAt: '2099-08-09T00:00:00Z',
      })),
      refresh: vi.fn(async () => refreshed),
      logout: vi.fn(),
    }
    const backend = createNodeAuthBackend({ realmId: 'realm-1', service, refreshSkewSeconds: 30 })
    const inspected = await backend.inspect({
      accessToken: 'expired-access-secret',
      refreshToken: 'rotating-refresh-secret',
      expiresAt: '2020-01-01T00:00:00Z',
    })
    expect(service.refresh).toHaveBeenCalledWith('realm-1', 'rotating-refresh-secret')
    expect(inspected?.backend).toMatchObject({
      accessToken: 'native-access-secret',
      refreshToken: 'native-refresh-secret',
    })
    expect(inspected?.public.assuranceLevel).toBe('aal2')
  })

  it('generates PKCE/state/nonce server-side and rejects claim mix-up', async () => {
    const native = {
      authorizationUrl: vi.fn((state: string) => `https://accounts.google.com/o/oauth2/auth?state=${state}`),
      exchangeCode: vi.fn(async () => ({
        providerId: 'microsoft',
        issuer: 'https://accounts.google.com',
        subject: 'subject-1',
        emailVerified: false,
      })),
    }
    const adapter = createNativeOAuthAdapter({
      providerId: 'google',
      issuer: 'https://accounts.google.com',
      redirectUri: 'https://app.example.com/auth/oauth/google/callback',
      provider: native,
    })
    const started = await adapter.begin({
      redirectUri: 'https://app.example.com/auth/oauth/google/callback',
    })
    expect(started.transaction.state).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(started.transaction.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(started.transaction.pkceVerifier.length).toBeGreaterThanOrEqual(43)
    await expect(
      adapter.exchange({ code: 'code', redirectUri: 'https://app.example.com/auth/oauth/google/callback', transaction: started.transaction }),
    ).rejects.toThrow(/provider mix-up/u)
  })

  it('adapts native passkey ceremonies while retaining the ceremony token in the BFF', async () => {
    const service = {
      beginPasskeyLogin: vi.fn(async () => ({
        ceremonyToken: 'ceremony_0123456789abcdefghijklmnopqrstuvwxyzABCDE',
        publicOptionsJson: JSON.stringify({
          challenge: 'public_challenge',
          rpId: 'app.example.com',
          userVerification: 'required',
        }),
        expiresAt: new Date(Date.now() + 300_000).toISOString(),
      })),
      finishPasskeyLogin: vi.fn(async () => authentication),
    }
    const passkeys = createNodePasskeyBackend({ realmId: 'realm-1', service })
    const started = await passkeys.beginLogin({ email: 'owner@example.com', rememberMe: true })
    expect(started.publicKey).toMatchObject({ userVerification: 'required' })
    await expect(
      passkeys.finishLogin({
        ceremonyToken: started.ceremonyToken,
        responseJson: '{"id":"credential"}',
      }),
    ).resolves.toMatchObject({ accessToken: 'native-access-secret' })
    expect(service.finishPasskeyLogin).toHaveBeenCalledWith(
      'realm-1',
      started.ceremonyToken,
      '{"id":"credential"}',
    )
  })
})
