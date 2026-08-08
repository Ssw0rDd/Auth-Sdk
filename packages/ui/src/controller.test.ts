import { afterEach, describe, expect, it, vi } from 'vitest'

import { SdkAuthLogin } from './auth-login'
import { connectAuthLogin } from './controller'

afterEach(() => document.body.replaceChildren())

describe('connectAuthLogin', () => {
  it('connects password events without persisting the password in markup', async () => {
    const element = new SdkAuthLogin()
    document.body.append(element)
    const client = {
      password: vi.fn(async () => {}),
      startProvider: vi.fn(async () => 'https://accounts.example/authorize'),
    }
    const authenticated = vi.fn()
    const disconnect = connectAuthLogin(element, client, { onAuthenticated: authenticated })
    element.dispatchEvent(
      new CustomEvent('sdk-auth:password-submit', {
        detail: { email: 'owner@example.com', password: 'browser-only-secret' },
      }),
    )
    await vi.waitFor(() => {
      expect(client.password).toHaveBeenCalledOnce()
      expect(element.busy).toBe(false)
    })
    expect(authenticated).toHaveBeenCalledOnce()
    expect(element.outerHTML).not.toContain('browser-only-secret')
    disconnect()
  })

  it('shows a stable generic error instead of backend details', async () => {
    const element = new SdkAuthLogin()
    document.body.append(element)
    const client = {
      password: vi.fn(async () => {
        throw new Error('database secret.internal failed')
      }),
      startProvider: vi.fn(async () => 'https://accounts.example/authorize'),
    }
    connectAuthLogin(element, client)
    element.dispatchEvent(
      new CustomEvent('sdk-auth:password-submit', {
        detail: { email: 'owner@example.com', password: 'wrong' },
      }),
    )
    await vi.waitFor(() => expect(element.error).not.toBe(''))
    expect(element.error).toBe('Não foi possível entrar. Confira seus dados e tente novamente.')
    expect(element.error).not.toContain('secret.internal')
  })

  it('navigates only to the URL returned by the token-blind client', async () => {
    const element = new SdkAuthLogin()
    document.body.append(element)
    const client = {
      password: vi.fn(async () => {}),
      startProvider: vi.fn(async () => 'https://accounts.example/authorize?state=public'),
    }
    const navigate = vi.fn()
    connectAuthLogin(element, client, { navigate })
    element.dispatchEvent(
      new CustomEvent('sdk-auth:provider', { detail: { provider: 'google' } }),
    )
    await vi.waitFor(() => expect(navigate).toHaveBeenCalledOnce())
    expect(client.startProvider).toHaveBeenCalledWith('google')
  })
})
