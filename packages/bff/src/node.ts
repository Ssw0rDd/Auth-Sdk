import {
  AuthenticationRejectedError,
  type AuthBackend,
  type BackendSession,
  type FederatedBackendOutcome,
  type FederatedIdentity,
  type FederatedLinkProof,
  type OAuthBeginRequest,
  type OAuthExchangeRequest,
  type OAuthProviderAdapter,
  type PasswordBackendOutcome,
  type PasskeyBackend,
  type PublicSession,
  type SecondFactorMethod,
} from './index'

type AssuranceLevel = PublicSession['assuranceLevel']

export interface NodeAuthenticationLike {
  userId: string
  email: string
  assuranceLevel: string
  sessionId: string
  accessToken: string
  refreshToken: string
  accessExpiresAt: string
  sessionExpiresAt: string
}

export interface NodeAuthServiceLike {
  login(
    realmId: string,
    email: string,
    password: string,
    rememberMe: boolean,
  ): Promise<{
    kind: string
    authentication?: NodeAuthenticationLike
    challengeToken?: string
    methods: string[]
    challengeExpiresAt?: string
  }>
  completeLogin(
    realmId: string,
    challengeToken: string,
    proofKind: string,
    proof: string,
    trustDevice: boolean,
  ): Promise<NodeAuthenticationLike>
  beginVerifiedFederatedLogin(request: {
    realmId: string
    providerId: string
    issuer: string
    subject: string
    email?: string
    emailVerified: boolean
    rememberMe: boolean
  }): Promise<{
    kind: string
    authentication?: NodeAuthenticationLike
    linkUserId?: string
    linkToken?: string
    linkExpiresAt?: string
  }>
  completeFederatedLink(
    realmId: string,
    accessToken: string,
    linkToken: string,
    proof: {
      kind: string
      password?: string
      secondFactorKind?: string
      secondFactor?: string
    },
  ): Promise<unknown>
  inspectAccess(realmId: string, accessToken: string): Promise<{
    userId: string
    email: string
    assuranceLevel: string
    sessionExpiresAt: string
  }>
  refresh(realmId: string, refreshToken: string): Promise<NodeAuthenticationLike>
  logout(realmId: string, accessToken: string): Promise<void>
}

export interface NodeAuthBackendOptions {
  realmId: string
  service: NodeAuthServiceLike
  /** Refresh an access token this many seconds before its expiration. */
  refreshSkewSeconds?: number
}

/** Adapts the native Node facade to the framework-neutral, token-blind BFF. */
export function createNodeAuthBackend(options: NodeAuthBackendOptions): AuthBackend {
  const { realmId, service } = options
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(realmId)) throw new Error('invalid realmId')
  const refreshSkewSeconds = options.refreshSkewSeconds ?? 30
  if (!Number.isSafeInteger(refreshSkewSeconds) || refreshSkewSeconds < 0 || refreshSkewSeconds > 300) {
    throw new Error('invalid refresh skew')
  }

  return {
    async password(credentials): Promise<PasswordBackendOutcome> {
      const result = await translateNativeError(() =>
        service.login(
          realmId,
          credentials.email,
          credentials.password,
          credentials.rememberMe,
        ),
      )
      if (result.kind === 'authenticated' && result.authentication !== undefined) {
        return { kind: 'authenticated', session: nativeSession(result.authentication) }
      }
      const methods = parseMethods(result.methods)
      if (
        result.kind !== 'second_factor_required' ||
        result.challengeToken === undefined ||
        result.challengeExpiresAt === undefined
      ) {
        throw new Error('invalid native password outcome')
      }
      return {
        kind: 'second_factor_required',
        challengeToken: result.challengeToken,
        methods,
        expiresAt: result.challengeExpiresAt,
      }
    },

    async completeSecondFactor(request): Promise<BackendSession> {
      const authentication = await translateNativeError(() =>
        service.completeLogin(
          realmId,
          request.challengeToken,
          request.method,
          request.proof,
          request.trustDevice,
        ),
      )
      return nativeSession(authentication)
    },

    async federated(request): Promise<FederatedBackendOutcome> {
      const result = await translateNativeError(() =>
        service.beginVerifiedFederatedLogin({
          realmId,
          providerId: request.provider,
          issuer: request.identity.issuer,
          subject: request.identity.subject,
          ...(request.identity.email === undefined ? {} : { email: request.identity.email }),
          emailVerified: request.identity.emailVerified,
          rememberMe: request.rememberMe,
        }),
      )
      if (result.kind === 'authenticated' && result.authentication !== undefined) {
        return { kind: 'authenticated', session: nativeSession(result.authentication) }
      }
      if (result.kind === 'registration_required') return { kind: 'registration_required' }
      if (
        result.kind !== 'link_required' ||
        result.linkUserId === undefined ||
        result.linkToken === undefined ||
        result.linkExpiresAt === undefined
      ) {
        throw new Error('invalid native federated outcome')
      }
      return {
        kind: 'link_required',
        linkUserId: result.linkUserId,
        linkToken: result.linkToken,
        expiresAt: result.linkExpiresAt,
      }
    },

    async completeFederatedLink(request): Promise<void> {
      await translateNativeError(() =>
        service.completeFederatedLink(
          realmId,
          request.session.accessToken,
          request.linkToken,
          nativeManagementProof(request.proof),
        ),
      )
    },

    async inspect(session) {
      try {
        let backend = session
        if (Date.parse(session.expiresAt) <= Date.now() + refreshSkewSeconds * 1_000) {
          const refreshed = await translateNativeError(() =>
            service.refresh(realmId, session.refreshToken),
          )
          backend = nativeSession(refreshed)
        }
        const inspected = await translateNativeError(() =>
          service.inspectAccess(realmId, backend.accessToken),
        )
        return {
          backend,
          public: {
            userId: inspected.userId,
            email: inspected.email,
            assuranceLevel: parseAssurance(inspected.assuranceLevel),
            expiresAt: inspected.sessionExpiresAt,
          },
        }
      } catch (error) {
        if (error instanceof AuthenticationRejectedError) return null
        throw error
      }
    },

    async revoke(session): Promise<void> {
      await service.logout(realmId, session.accessToken)
    },
  }
}

function nativeSession(authentication: NodeAuthenticationLike): BackendSession {
  return {
    accessToken: authentication.accessToken,
    refreshToken: authentication.refreshToken,
    expiresAt: authentication.accessExpiresAt,
  }
}

function nativeManagementProof(proof: FederatedLinkProof): {
  kind: string
  password?: string
  secondFactorKind?: string
  secondFactor?: string
} {
  return {
    kind: proof.kind,
    ...(proof.password === undefined ? {} : { password: proof.password }),
    ...(proof.secondFactorMethod === undefined
      ? {}
      : { secondFactorKind: proof.secondFactorMethod, secondFactor: proof.secondFactor }),
  }
}

function parseMethods(methods: string[]): SecondFactorMethod[] {
  if (
    methods.length < 1 ||
    methods.length > 2 ||
    methods.some((method) => method !== 'totp' && method !== 'recovery_code')
  ) {
    throw new Error('invalid native second-factor methods')
  }
  return methods as SecondFactorMethod[]
}

function parseAssurance(value: string): AssuranceLevel {
  if (value !== 'aal1' && value !== 'aal2' && value !== 'aal3') {
    throw new Error('invalid native assurance level')
  }
  return value
}

async function translateNativeError<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation()
  } catch (error) {
    const code = error instanceof Error ? /^([A-Z_]+):/u.exec(error.message)?.[1] ?? '' : ''
    if (
      code === 'INVALID_CREDENTIALS' ||
      code === 'ACCOUNT_UNVERIFIED' ||
      code === 'SECOND_FACTOR_INVALID' ||
      code === 'TOKEN_INVALID' ||
      code === 'TOKEN_EXPIRED' ||
      code === 'TOKEN_REUSED' ||
      code === 'SESSION_REVOKED' ||
      code === 'PERMISSION_DENIED'
    ) {
      throw new AuthenticationRejectedError()
    }
    throw error
  }
}

export interface NativeVerifiedClaims {
  providerId: string
  issuer: string
  subject: string
  email?: string
  emailVerified: boolean
}

export interface NodePasskeyServiceLike {
  beginPasskeyLogin(
    realmId: string,
    email: string,
    rememberMe: boolean,
  ): Promise<{ ceremonyToken: string; publicOptionsJson: string; expiresAt: string }>
  finishPasskeyLogin(
    realmId: string,
    ceremonyToken: string,
    responseJson: string,
  ): Promise<NodeAuthenticationLike>
}

export interface NodePasskeyBackendOptions {
  realmId: string
  service: NodePasskeyServiceLike
}

/** Adapts native, UV-required WebAuthn login ceremonies to the BFF. */
export function createNodePasskeyBackend(options: NodePasskeyBackendOptions): PasskeyBackend {
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(options.realmId)) throw new Error('invalid realmId')
  return {
    async beginLogin(request) {
      const started = await translateNativeError(() =>
        options.service.beginPasskeyLogin(
          options.realmId,
          request.email,
          request.rememberMe,
        ),
      )
      const parsed: unknown = JSON.parse(started.publicOptionsJson)
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('invalid native passkey options')
      }
      return {
        ceremonyToken: started.ceremonyToken,
        publicKey: parsed as Record<string, unknown>,
        expiresAt: started.expiresAt,
      }
    },
    async finishLogin(request) {
      const authentication = await translateNativeError(() =>
        options.service.finishPasskeyLogin(
          options.realmId,
          request.ceremonyToken,
          request.responseJson,
        ),
      )
      return nativeSession(authentication)
    },
  }
}

export interface NativeOAuthProviderLike {
  authorizationUrl(state: string, nonce: string, pkceVerifier: string): string
  exchangeCode(code: string, nonce: string, pkceVerifier: string): Promise<NativeVerifiedClaims>
}

export interface NativeOAuthAdapterOptions {
  providerId: string
  issuer: string
  redirectUri: string
  provider: NativeOAuthProviderLike
}

/** Wraps `@sdk-auth/oauth-node` while keeping state, nonce and PKCE server-side. */
export function createNativeOAuthAdapter(options: NativeOAuthAdapterOptions): OAuthProviderAdapter {
  const { providerId, issuer, provider } = options
  const redirectUri = new URL(options.redirectUri).href
  return {
    issuer,
    async begin(request: OAuthBeginRequest) {
      assertRedirect(request.redirectUri, redirectUri)
      const transaction = {
        state: randomToken(32),
        nonce: randomToken(32),
        pkceVerifier: randomToken(64),
      }
      return {
        authorizationUrl: provider.authorizationUrl(
          transaction.state,
          transaction.nonce,
          transaction.pkceVerifier,
        ),
        transaction,
      }
    },
    async exchange(request: OAuthExchangeRequest): Promise<FederatedIdentity> {
      assertRedirect(request.redirectUri, redirectUri)
      const claims = await provider.exchangeCode(
        request.code,
        request.transaction.nonce,
        request.transaction.pkceVerifier,
      )
      if (claims.providerId !== providerId || claims.issuer !== issuer) {
        throw new Error('provider mix-up')
      }
      return {
        issuer: claims.issuer,
        subject: claims.subject,
        ...(claims.email === undefined ? {} : { email: claims.email }),
        emailVerified: claims.emailVerified,
      }
    },
  }
}

function assertRedirect(actual: string, expected: string): void {
  if (new URL(actual).href !== expected) throw new Error('redirect URI mismatch')
}

function randomToken(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength))
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}
