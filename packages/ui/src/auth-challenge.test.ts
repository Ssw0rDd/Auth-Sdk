import { afterEach, describe, expect, it, vi } from 'vitest'

import { SdkAuthChallenge } from './auth-challenge'
import { connectAuthChallenge } from './controller'

afterEach(() => document.body.replaceChildren())

describe('SdkAuthChallenge', () => {
  it('submits a selected second factor without reflecting the proof into markup', async () => {
    const element = new SdkAuthChallenge()
    element.methods = ['totp', 'recovery_code']
    document.body.append(element)
    await element.updateComplete

    const received = vi.fn()
    element.addEventListener('sdk-auth:second-factor-submit', received)
    const input = element.shadowRoot?.querySelector<HTMLInputElement>('#proof')
    if (!input) throw new Error('missing proof input')
    input.value = 'browser-only-123456'
    element.shadowRoot?.querySelector<HTMLFormElement>('form')?.dispatchEvent(
      new SubmitEvent('submit', { bubbles: true, cancelable: true }),
    )

    expect(received).toHaveBeenCalledOnce()
    expect(received.mock.calls[0]?.[0].detail).toMatchObject({
      method: 'totp',
      proof: 'browser-only-123456',
    })
    expect(element.outerHTML).not.toContain('browser-only-123456')
  })

  it('connects to a token-blind client and reports completion', async () => {
    const element = new SdkAuthChallenge()
    document.body.append(element)
    const client = { completeSecondFactor: vi.fn(async () => {}) }
    const completed = vi.fn()
    connectAuthChallenge(element, client, { onAuthenticated: completed })
    element.dispatchEvent(
      new CustomEvent('sdk-auth:second-factor-submit', {
        detail: { method: 'totp', proof: '123456', trustDevice: true },
      }),
    )
    await vi.waitFor(() => expect(client.completeSecondFactor).toHaveBeenCalledOnce())
    expect(completed).toHaveBeenCalledOnce()
    await vi.waitFor(() => expect(element.busy).toBe(false))
  })
})
