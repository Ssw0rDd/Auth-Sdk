import { afterEach, describe, expect, it, vi } from 'vitest'

import { SdkAuthLogin, type PasswordSubmitDetail } from './auth-login'

afterEach(() => {
  document.body.replaceChildren()
})

describe('sdk-auth-login', () => {
  it('emits password data only through the explicit submit event', async () => {
    const element = new SdkAuthLogin()
    document.body.append(element)
    await element.updateComplete
    const listener = vi.fn((event: Event) => (event as CustomEvent<PasswordSubmitDetail>).detail)
    element.addEventListener('sdk-auth:password-submit', listener)
    const email = element.shadowRoot?.querySelector<HTMLInputElement>('#email')
    const password = element.shadowRoot?.querySelector<HTMLInputElement>('#password')
    const form = element.shadowRoot?.querySelector<HTMLFormElement>('form')
    expect(email).toBeTruthy()
    expect(password).toBeTruthy()
    expect(form).toBeTruthy()
    if (!email || !password || !form) return
    email.value = ' owner@example.com '
    password.value = 'correct horse battery staple'
    form.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }))
    expect(listener).toHaveBeenCalledOnce()
    expect(listener.mock.results[0]?.value).toEqual({
      email: 'owner@example.com',
      password: 'correct horse battery staple',
      rememberMe: false,
    })
    expect(element.outerHTML).not.toContain('correct horse battery staple')
  })

  it('exposes errors as alerts and blocks controls while busy', async () => {
    const element = new SdkAuthLogin()
    element.error = 'Confira seus dados e tente novamente.'
    element.busy = true
    document.body.append(element)
    await element.updateComplete
    expect(element.shadowRoot?.querySelector('[role="alert"]')?.textContent).toContain(
      'Confira seus dados',
    )
    const controls = element.shadowRoot?.querySelectorAll<HTMLInputElement | HTMLButtonElement>(
      'input, button',
    )
    expect(Array.from(controls ?? []).every((control) => control.disabled)).toBe(true)
  })

  it('emits a provider choice without navigating by itself', async () => {
    const element = new SdkAuthLogin()
    document.body.append(element)
    await element.updateComplete
    const listener = vi.fn()
    element.addEventListener('sdk-auth:provider', listener)
    element.shadowRoot?.querySelector<HTMLButtonElement>('.provider')?.click()
    expect(listener).toHaveBeenCalledOnce()
    expect(listener.mock.calls[0]?.[0].detail).toEqual({ provider: 'google', rememberMe: false })
  })

  it('does not duplicate the server password policy in the login form', async () => {
    const element = new SdkAuthLogin()
    document.body.append(element)
    await element.updateComplete
    const password = element.shadowRoot?.querySelector<HTMLInputElement>('#password')
    expect(password?.getAttribute('minlength')).toBeNull()
  })

  it('associates an asynchronous server error with both credentials', async () => {
    const element = new SdkAuthLogin()
    element.error = 'Confira seus dados e tente novamente.'
    document.body.append(element)
    await element.updateComplete
    const email = element.shadowRoot?.querySelector<HTMLInputElement>('#email')
    const password = element.shadowRoot?.querySelector<HTMLInputElement>('#password')
    expect(email?.getAttribute('aria-describedby')).toBe('auth-error')
    expect(password?.getAttribute('aria-describedby')).toBe('auth-error')
  })

  it('emits a username-first passkey request only when the optional control is enabled', async () => {
    const element = new SdkAuthLogin()
    element.showPasskey = true
    document.body.append(element)
    await element.updateComplete
    const email = element.shadowRoot?.querySelector<HTMLInputElement>('#email')
    if (!email) throw new Error('missing email input')
    email.value = 'owner@example.com'
    const listener = vi.fn()
    element.addEventListener('sdk-auth:passkey', listener)
    element.shadowRoot?.querySelector<HTMLButtonElement>('.passkey')?.click()
    expect(listener).toHaveBeenCalledOnce()
    expect(listener.mock.calls[0]?.[0].detail).toEqual({
      email: 'owner@example.com',
      rememberMe: false,
    })
  })
})
