import '@fontsource/manrope/latin-400.css'
import '@fontsource/manrope/latin-600.css'
import '@fontsource/syne/latin-700.css'
import '@fontsource/ibm-plex-mono/latin-500.css'

import { LitElement, css, html, nothing, type PropertyValues } from 'lit'

export type AuthProvider = 'google' | 'github' | 'microsoft'

export interface PasswordSubmitDetail {
  email: string
  password: string
  rememberMe: boolean
}

export interface ProviderSubmitDetail {
  provider: AuthProvider
  rememberMe: boolean
}

export interface PasskeySubmitDetail {
  email: string
  rememberMe: boolean
}

const providerLabels: Readonly<Record<AuthProvider, string>> = {
  google: 'Continuar com Google',
  github: 'Continuar com GitHub',
  microsoft: 'Continuar com Microsoft',
}

const providerMarks: Readonly<Record<AuthProvider, string>> = {
  google: 'G',
  github: 'GH',
  microsoft: 'MS',
}

export class SdkAuthLogin extends LitElement {
  static properties = {
    busy: { type: Boolean, reflect: true },
    error: { type: String },
    heading: { type: String },
    providers: { attribute: false },
    showPasskey: { type: Boolean, attribute: 'show-passkey' },
    showRememberMe: { type: Boolean, attribute: 'show-remember-me' },
  }

  declare busy: boolean
  declare error: string
  declare heading: string
  declare providers: AuthProvider[]
  declare showPasskey: boolean
  declare showRememberMe: boolean

  constructor() {
    super()
    this.busy = false
    this.error = ''
    this.heading = 'Entre sem perder o controle.'
    this.providers = ['google', 'github', 'microsoft']
    this.showPasskey = false
    this.showRememberMe = true
  }

  protected firstUpdated(changed: PropertyValues<this>): void {
    super.firstUpdated(changed)
    const hasPrecisePointer =
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(hover: hover) and (pointer: fine) and (min-width: 781px)').matches
    if (hasPrecisePointer) {
      this.renderRoot.querySelector<HTMLInputElement>('#email')?.focus({ preventScroll: true })
    }
  }

  protected updated(changed: PropertyValues<this>): void {
    super.updated(changed)
    if (changed.has('error') && this.error) {
      this.renderRoot.querySelector<HTMLElement>('#auth-error')?.focus({ preventScroll: true })
    }
  }

  private handleSubmit(event: SubmitEvent): void {
    event.preventDefault()
    if (this.busy) return
    const form = event.currentTarget
    if (!(form instanceof HTMLFormElement) || !form.reportValidity()) return
    const data = new FormData(form)
    this.dispatchEvent(
      new CustomEvent<PasswordSubmitDetail>('sdk-auth:password-submit', {
        bubbles: true,
        composed: true,
        detail: {
          email: String(data.get('email') ?? '').trim(),
          password: String(data.get('password') ?? ''),
          rememberMe: data.get('rememberMe') === 'on',
        },
      }),
    )
  }

  private handleProvider(provider: AuthProvider): void {
    if (this.busy) return
    this.dispatchEvent(
      new CustomEvent<ProviderSubmitDetail>('sdk-auth:provider', {
        bubbles: true,
        composed: true,
        detail: {
          provider,
          rememberMe:
            this.renderRoot.querySelector<HTMLInputElement>('input[name="rememberMe"]')?.checked ===
            true,
        },
      }),
    )
  }

  private handlePasskey(): void {
    if (this.busy) return
    const email = this.renderRoot.querySelector<HTMLInputElement>('#email')
    if (email === null || !email.reportValidity()) return
    this.dispatchEvent(
      new CustomEvent<PasskeySubmitDetail>('sdk-auth:passkey', {
        bubbles: true,
        composed: true,
        detail: {
          email: email.value.trim(),
          rememberMe:
            this.renderRoot.querySelector<HTMLInputElement>('input[name="rememberMe"]')?.checked ===
            true,
        },
      }),
    )
  }

  protected render() {
    const providerButtons = this.providers.map(
      (provider) => html`
        <button
          class="provider"
          type="button"
          ?disabled=${this.busy}
          @click=${() => this.handleProvider(provider)}
        >
          <span class="provider-mark" aria-hidden="true">${providerMarks[provider]}</span>
          <span>${providerLabels[provider]}</span>
          <span class="provider-arrow" aria-hidden="true">↗</span>
        </button>
      `,
    )

    return html`
      <div class="shell" aria-busy=${String(this.busy)}>
        <div class="shell-glow" aria-hidden="true"></div>
        <section class="manifest" aria-labelledby="sdk-auth-heading">
          <div class="brand-row">
            <span class="brand-mark" aria-hidden="true">
              <span class="brand-mark-inner">S/A</span>
            </span>
            <span class="eyebrow">SDK–AUTH / SECURE ENTRY</span>
          </div>
          <div class="statement">
            <p class="signal"><span></span> Canal verificado</p>
            <h1 id="sdk-auth-heading">${this.heading}</h1>
            <p class="lede">
              Uma identidade. Várias formas de provar que ela é sua. Seus tokens ficam no servidor.
            </p>
          </div>
          <div class="trust-line" aria-label="Propriedades de segurança">
            <span>PKCE S256</span><span>PASSKEY READY</span><span>NO AUTO-LINK</span>
          </div>
        </section>

        <div class="auth-cut" aria-hidden="true">
          <div class="auth-cut-aura"></div>
          <div class="auth-cut-core"></div>
        </div>

        <section class="entry" aria-label="Acessar conta">
          <div class="entry-head">
            <p class="step">PROVA / 01</p>
            <p class="hint">Use o método que você reconhece.</p>
          </div>

          <div class="providers">${providerButtons}</div>

          ${this.showPasskey
            ? html`<button class="passkey" type="button" ?disabled=${this.busy} @click=${this.handlePasskey}>
                <span class="passkey-mark" aria-hidden="true">◆</span>
                <span>Entrar com uma passkey</span>
                <span aria-hidden="true">→</span>
              </button>`
            : nothing}

          <div class="separator"><span>ou use sua senha</span></div>

          <form @submit=${this.handleSubmit} novalidate>
            <div class="field">
              <label for="email">E-mail</label>
              <input
                id="email"
                name="email"
                type="email"
                autocomplete="username"
                inputmode="email"
                autocapitalize="none"
                spellcheck="false"
                placeholder="voce@exemplo.com…"
                aria-describedby=${this.error ? 'auth-error' : nothing}
                ?disabled=${this.busy}
                required
              />
            </div>

            <div class="field">
              <div class="password-label">
                <label for="password">Senha</label>
                <slot name="forgot-password"></slot>
              </div>
              <input
                id="password"
                name="password"
                type="password"
                autocomplete="current-password"
                placeholder="Digite sua senha…"
                aria-describedby=${this.error ? 'auth-error' : nothing}
                ?disabled=${this.busy}
                required
              />
            </div>

            ${this.showRememberMe
              ? html`<label class="remember">
                  <input name="rememberMe" type="checkbox" ?disabled=${this.busy} />
                  <span>Lembrar este dispositivo</span>
                </label>`
              : nothing}

            ${this.error
              ? html`<p id="auth-error" class="error" role="alert" tabindex="-1">
                  <span aria-hidden="true">!</span>${this.error}
                </p>`
              : html`<p class="status" aria-live="polite">${this.busy ? 'Verificando…' : ''}</p>`}

            <button class="submit" type="submit" ?disabled=${this.busy}>
              <span>${this.busy ? 'Verificando' : 'Entrar com senha'}</span>
              <span class="submit-key" aria-hidden="true">→</span>
            </button>
          </form>

          <p class="register"><slot name="register">Ainda não tem conta?</slot></p>
        </section>
      </div>
    `
  }

  static styles = css`
    :host {
      --_void: var(--ska-void, #050608);
      --_void-lift: var(--ska-void-lift, #0b0d11);
      --_iron: var(--ska-iron, #12151b);
      --_steel: var(--ska-steel, #1c212b);
      --_ember: var(--ska-ember, #f23a4a);
      --_flare: var(--ska-flare, #ff6a5c);
      --_bone: var(--ska-bone, #f3efe8);
      --_ash: var(--ska-ash, #8b929e);
      --_mist: var(--ska-mist, #b6bcc6);
      --_danger: var(--ska-danger, #ff7a83);
      --_ease: var(--ska-ease-out, cubic-bezier(0.2, 0.8, 0.2, 1));
      display: block;
      min-width: 0;
      max-width: 100%;
      color: var(--_bone);
      font-family: var(--ska-font-body, 'Manrope', 'Segoe UI', sans-serif);
      color-scheme: dark;
    }

    * {
      box-sizing: border-box;
    }

    button,
    input {
      font: inherit;
      touch-action: manipulation;
      -webkit-tap-highlight-color: rgb(242 58 74 / 22%);
    }

    .shell {
      position: relative;
      display: grid;
      grid-template-columns: minmax(19rem, 1.12fr) minmax(20rem, 0.88fr);
      width: 100%;
      min-width: 0;
      max-width: 100%;
      min-height: min(50rem, calc(100dvh - 5.5rem));
      overflow: hidden;
      border: 1px solid color-mix(in srgb, var(--_ash) 26%, transparent);
      border-radius: var(--ska-radius, 1.15rem);
      background:
        linear-gradient(155deg, color-mix(in srgb, var(--_steel) 55%, var(--_void)) 0%, var(--_void) 48%),
        var(--_void);
      box-shadow:
        0 0 0 1px rgb(255 255 255 / 2.5%) inset,
        0 1.25rem 2.5rem rgb(0 0 0 / 35%),
        0 2.75rem 5.5rem rgb(0 0 0 / 45%);
      isolation: isolate;
    }

    .shell-glow {
      position: absolute;
      inset: -20% auto auto -12%;
      z-index: 0;
      width: 55%;
      height: 70%;
      background: radial-gradient(circle, color-mix(in srgb, var(--_ember) 22%, transparent), transparent 68%);
      pointer-events: none;
      filter: blur(0.5rem);
    }

    .shell::before {
      position: absolute;
      inset: 0;
      z-index: 0;
      background-image:
        linear-gradient(rgb(255 255 255 / 2.2%) 1px, transparent 1px),
        linear-gradient(90deg, rgb(255 255 255 / 2.2%) 1px, transparent 1px);
      background-size: 3rem 3rem;
      content: '';
      mask-image: linear-gradient(118deg, black 8%, transparent 68%);
      opacity: 0.85;
      pointer-events: none;
    }

    .shell::after {
      position: absolute;
      inset: 0;
      z-index: 0;
      background:
        linear-gradient(to right, transparent 54%, color-mix(in srgb, var(--_iron) 88%, transparent) 54%),
        radial-gradient(ellipse 40% 55% at 18% 88%, color-mix(in srgb, var(--_ember) 14%, transparent), transparent 70%);
      content: '';
      pointer-events: none;
    }

    .manifest,
    .entry {
      position: relative;
      z-index: 1;
      padding: clamp(1.85rem, 4.5vw, 4.75rem);
    }

    .manifest {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-width: 0;
      gap: 2.5rem;
    }

    .brand-row,
    .trust-line,
    .entry-head,
    .password-label {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }

    .brand-mark,
    .eyebrow,
    .signal,
    .step,
    .trust-line {
      font-family: var(--ska-font-data, 'IBM Plex Mono', monospace);
      letter-spacing: 0.09em;
    }

    .brand-mark {
      display: grid;
      width: 2.85rem;
      height: 2.85rem;
      place-items: center;
      border: 1px solid color-mix(in srgb, var(--_ember) 85%, var(--_flare));
      background:
        linear-gradient(145deg, color-mix(in srgb, var(--_ember) 18%, transparent), transparent 58%),
        var(--_void-lift);
      box-shadow:
        inset 0 0 0 1px rgb(255 106 92 / 8%),
        0 0 1.5rem color-mix(in srgb, var(--_ember) 18%, transparent);
    }

    .brand-mark-inner {
      color: var(--_flare);
      font-size: 0.72rem;
      font-weight: 500;
    }

    .eyebrow,
    .step,
    .trust-line {
      color: var(--_ash);
      font-size: 0.64rem;
      text-transform: uppercase;
    }

    .statement {
      max-width: 38rem;
      animation: reveal 700ms var(--_ease) both;
    }

    .signal {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      margin: 0;
      color: var(--_flare);
      font-size: 0.66rem;
      text-transform: uppercase;
    }

    .signal span {
      width: 0.42rem;
      height: 0.42rem;
      border-radius: 50%;
      background: var(--_ember);
      box-shadow: 0 0 0 0.32rem color-mix(in srgb, var(--_ember) 16%, transparent);
      animation: live 2.6s ease-in-out infinite;
    }

    h1 {
      max-width: 11ch;
      margin: 1.15rem 0 1.45rem;
      font-family: var(--ska-font-display, 'Syne', 'Arial Black', sans-serif);
      font-size: clamp(3.2rem, 6.8vw, 7.35rem);
      font-weight: 700;
      letter-spacing: -0.07em;
      line-height: 0.84;
      text-wrap: balance;
      overflow-wrap: anywhere;
      background: linear-gradient(180deg, #fff8f4 18%, color-mix(in srgb, var(--_bone) 88%, var(--_flare)) 100%);
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
    }

    .lede {
      max-width: 30rem;
      margin: 0;
      color: color-mix(in srgb, var(--_mist) 82%, var(--_ash));
      font-size: clamp(0.95rem, 1.45vw, 1.12rem);
      line-height: 1.7;
    }

    .trust-line {
      justify-content: flex-start;
      flex-wrap: wrap;
      gap: 0.35rem 0;
      padding-top: 0.25rem;
      border-top: 1px solid color-mix(in srgb, var(--_ash) 16%, transparent);
    }

    .trust-line span {
      padding: 0.65rem 0;
    }

    .trust-line span:not(:last-child)::after {
      margin-left: 0.95rem;
      margin-right: 0.95rem;
      color: var(--_ember);
      content: '◆';
      font-size: 0.42rem;
      vertical-align: middle;
    }

    .entry {
      display: flex;
      flex-direction: column;
      justify-content: center;
      min-width: 0;
      background:
        linear-gradient(180deg, color-mix(in srgb, var(--_iron) 70%, transparent), color-mix(in srgb, var(--_void) 55%, var(--_iron))),
        color-mix(in srgb, var(--_iron) 92%, transparent);
      backdrop-filter: blur(1.15rem) saturate(1.15);
      box-shadow: inset 1px 0 0 rgb(255 255 255 / 3.5%);
      animation: entry-in 780ms 60ms var(--_ease) both;
    }

    .entry-head {
      margin-bottom: 0.15rem;
    }

    .step {
      margin: 0;
    }

    .hint {
      margin: 0;
      color: var(--_ash);
      font-size: 0.8rem;
      line-height: 1.35;
    }

    .providers {
      display: grid;
      gap: 0.55rem;
      margin-top: 1.75rem;
    }

    .provider,
    .passkey,
    .submit {
      width: 100%;
      min-height: 3.3rem;
      border: 1px solid color-mix(in srgb, var(--_ash) 28%, transparent);
      color: var(--_bone);
      cursor: pointer;
      border-radius: var(--ska-radius-sm, 0.55rem);
    }

    .provider {
      display: grid;
      grid-template-columns: 2.15rem minmax(0, 1fr) 1rem;
      align-items: center;
      gap: 0.8rem;
      padding: 0.5rem 0.8rem;
      background: color-mix(in srgb, var(--_void-lift) 72%, transparent);
      text-align: left;
      transition:
        border-color 170ms ease,
        background 170ms ease,
        transform 170ms var(--_ease),
        box-shadow 170ms ease;
    }

    .passkey {
      display: grid;
      grid-template-columns: 2.15rem minmax(0, 1fr) 1rem;
      align-items: center;
      gap: 0.8rem;
      margin-top: 0.55rem;
      padding: 0.5rem 0.8rem;
      border-color: color-mix(in srgb, var(--_ember) 38%, var(--_ash));
      background:
        linear-gradient(120deg, color-mix(in srgb, var(--_ember) 12%, transparent), transparent 55%),
        color-mix(in srgb, var(--_ember) 7%, var(--_iron));
      text-align: left;
      transition:
        border-color 170ms ease,
        background 170ms ease,
        transform 170ms var(--_ease);
    }

    .passkey-mark {
      color: var(--_flare);
      text-align: center;
      font-size: 0.72rem;
    }

    .provider:hover:not(:disabled),
    .passkey:hover:not(:disabled) {
      border-color: color-mix(in srgb, var(--_ember) 68%, var(--_ash));
      background: color-mix(in srgb, var(--_ember) 11%, var(--_iron));
      transform: translateX(0.18rem);
      box-shadow: 0 0.4rem 1.25rem color-mix(in srgb, var(--_ember) 12%, transparent);
    }

    .provider-mark {
      display: grid;
      width: 2.15rem;
      height: 2.15rem;
      place-items: center;
      border: 1px solid color-mix(in srgb, var(--_ash) 32%, transparent);
      border-radius: 0.35rem;
      background: color-mix(in srgb, var(--_void) 55%, transparent);
      font-family: var(--ska-font-data, monospace);
      font-size: 0.6rem;
      letter-spacing: 0.04em;
    }

    .provider-arrow {
      color: var(--_flare);
      opacity: 0.85;
      transition: transform 170ms var(--_ease);
    }

    .provider:hover:not(:disabled) .provider-arrow {
      transform: translate(0.1rem, -0.1rem);
    }

    .separator {
      display: flex;
      align-items: center;
      gap: 0.85rem;
      margin: 1.4rem 0 1.25rem;
      color: var(--_ash);
      font-family: var(--ska-font-data, monospace);
      font-size: 0.66rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }

    .separator::before,
    .separator::after {
      height: 1px;
      flex: 1;
      background: linear-gradient(
        90deg,
        transparent,
        color-mix(in srgb, var(--_ash) 28%, transparent),
        transparent
      );
      content: '';
    }

    form {
      display: grid;
      gap: 0.85rem;
    }

    .field {
      display: grid;
      gap: 0.45rem;
    }

    form label:not(.remember),
    .password-label label {
      color: color-mix(in srgb, var(--_bone) 86%, var(--_ash));
      font-size: 0.74rem;
      font-weight: 600;
      letter-spacing: 0.01em;
    }

    input[type='email'],
    input[type='password'] {
      width: 100%;
      min-height: 3.2rem;
      border: 1px solid color-mix(in srgb, var(--_ash) 30%, transparent);
      border-radius: var(--ska-radius-sm, 0.55rem);
      outline: 0;
      background:
        linear-gradient(180deg, rgb(255 255 255 / 2%), transparent 40%),
        color-mix(in srgb, var(--_void) 78%, var(--_iron));
      color: var(--_bone);
      padding: 0 1rem;
      transition:
        border-color 150ms ease,
        box-shadow 150ms ease,
        background 150ms ease;
    }

    input::placeholder {
      color: color-mix(in srgb, var(--_ash) 78%, transparent);
    }

    input:focus-visible,
    button:focus-visible,
    ::slotted(a:focus-visible) {
      outline: 2px solid var(--_flare);
      outline-offset: 3px;
    }

    input[type='email']:focus,
    input[type='password']:focus {
      border-color: color-mix(in srgb, var(--_ember) 80%, var(--_ash));
      box-shadow:
        inset 0.18rem 0 0 var(--_ember),
        0 0 0 3px color-mix(in srgb, var(--_ember) 14%, transparent);
      background: color-mix(in srgb, var(--_void) 70%, var(--_iron));
    }

    .remember {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      width: fit-content;
      color: var(--_ash);
      cursor: pointer;
      font-size: 0.76rem;
      user-select: none;
    }

    .remember input {
      width: 1rem;
      height: 1rem;
      accent-color: var(--_ember);
    }

    .error,
    .status {
      min-height: 1.3rem;
      margin: 0.1rem 0 0;
      font-size: 0.76rem;
      line-height: 1.4;
    }

    .error {
      display: flex;
      align-items: flex-start;
      gap: 0.45rem;
      padding: 0.65rem 0.75rem;
      border: 1px solid color-mix(in srgb, var(--_danger) 35%, transparent);
      border-radius: var(--ska-radius-sm, 0.55rem);
      background: color-mix(in srgb, var(--_danger) 8%, transparent);
      color: var(--_danger);
      overflow-wrap: anywhere;
    }

    .error span {
      display: inline-grid;
      flex: 0 0 auto;
      width: 1.05rem;
      height: 1.05rem;
      place-items: center;
      border: 1px solid currentColor;
      border-radius: 0.2rem;
      font-family: var(--ska-font-data, monospace);
      font-size: 0.6rem;
    }

    .status {
      color: var(--_ash);
    }

    .submit {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-top: 0.15rem;
      padding: 0 0 0 1.15rem;
      border-color: color-mix(in srgb, var(--_ember) 90%, #fff);
      background:
        linear-gradient(180deg, color-mix(in srgb, var(--_flare) 55%, var(--_ember)), var(--_ember));
      color: #0a0506;
      font-weight: 700;
      letter-spacing: -0.01em;
      box-shadow:
        0 0.55rem 1.6rem color-mix(in srgb, var(--_ember) 28%, transparent),
        inset 0 1px 0 rgb(255 255 255 / 28%);
      transition:
        filter 160ms ease,
        transform 160ms var(--_ease),
        box-shadow 160ms ease;
    }

    .submit:hover:not(:disabled) {
      filter: brightness(1.08);
      transform: translateY(-0.12rem);
      box-shadow:
        0 0.75rem 1.9rem color-mix(in srgb, var(--_ember) 36%, transparent),
        inset 0 1px 0 rgb(255 255 255 / 32%);
    }

    .submit:active:not(:disabled) {
      transform: translateY(0);
    }

    .submit-key {
      display: grid;
      width: 3.2rem;
      align-self: stretch;
      place-items: center;
      border-left: 1px solid rgb(10 5 6 / 22%);
      font-size: 1.2rem;
      background: rgb(10 5 6 / 8%);
    }

    button:disabled,
    input:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }

    .register {
      min-height: 1rem;
      margin: 1.25rem 0 0;
      color: var(--_ash);
      font-size: 0.76rem;
      text-align: center;
    }

    ::slotted(a) {
      color: var(--_flare);
      text-decoration-thickness: 1px;
      text-underline-offset: 0.22em;
      transition: color 140ms ease;
    }

    ::slotted(a:hover) {
      color: var(--_bone);
    }

    .auth-cut {
      position: absolute;
      top: -12%;
      bottom: -12%;
      left: 55.5%;
      z-index: 3;
      width: 0.38rem;
      pointer-events: none;
      transform: rotate(6.5deg);
      transform-origin: center;
      animation: cut-in 900ms var(--_ease) both;
    }

    .auth-cut-aura {
      position: absolute;
      inset: 8% -1.4rem;
      background: radial-gradient(closest-side, color-mix(in srgb, var(--_ember) 45%, transparent), transparent 78%);
      filter: blur(0.35rem);
      opacity: 0.85;
    }

    .auth-cut-core {
      position: relative;
      width: 100%;
      height: 100%;
      background: linear-gradient(
        180deg,
        transparent 2%,
        var(--_flare) 18%,
        var(--_ember) 52%,
        color-mix(in srgb, var(--_ember) 70%, #7a1020) 82%,
        transparent 98%
      );
      box-shadow:
        0 0 1.5rem color-mix(in srgb, var(--_ember) 55%, transparent),
        0 0 3rem color-mix(in srgb, var(--_ember) 22%, transparent);
      border-radius: 999px;
    }

    :host([busy]) .auth-cut-core {
      animation: pulse 900ms ease-in-out infinite alternate;
    }

    :host([busy]) .auth-cut-aura {
      animation: pulse-aura 900ms ease-in-out infinite alternate;
    }

    @keyframes reveal {
      from {
        opacity: 0;
        transform: translateY(1.15rem);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes entry-in {
      from {
        opacity: 0;
        transform: translateX(0.75rem);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }

    @keyframes cut-in {
      from {
        opacity: 0;
        transform: translateY(-16%) rotate(6.5deg) scaleY(0.85);
      }
      to {
        opacity: 1;
        transform: translateY(0) rotate(6.5deg) scaleY(1);
      }
    }

    @keyframes pulse {
      to {
        filter: brightness(1.4);
        transform: scaleX(1.75);
      }
    }

    @keyframes pulse-aura {
      to {
        opacity: 1;
        transform: scaleX(1.35);
      }
    }

    @keyframes live {
      0%,
      100% {
        box-shadow: 0 0 0 0.28rem color-mix(in srgb, var(--_ember) 14%, transparent);
      }
      50% {
        box-shadow: 0 0 0 0.4rem color-mix(in srgb, var(--_ember) 8%, transparent);
        opacity: 0.82;
      }
    }

    @media (max-width: 780px) {
      .shell {
        grid-template-columns: 1fr;
        min-height: auto;
      }

      .shell::after {
        background: radial-gradient(
          ellipse 80% 40% at 20% 0%,
          color-mix(in srgb, var(--_ember) 12%, transparent),
          transparent 70%
        );
      }

      .manifest {
        min-height: 17.5rem;
        padding-bottom: 2.75rem;
        gap: 1.75rem;
      }

      h1 {
        max-width: 9ch;
        margin-top: 1.65rem;
        font-size: clamp(2.65rem, 12.5vw, 4.35rem);
      }

      .lede {
        display: none;
      }

      .trust-line {
        margin-top: 0;
      }

      .entry {
        padding-top: 2.35rem;
        box-shadow: inset 0 1px 0 rgb(255 255 255 / 4%);
        animation-name: reveal;
      }

      .entry-head {
        align-items: flex-start;
      }

      .hint {
        max-width: 11.5rem;
        text-align: right;
      }

      .auth-cut {
        top: 16.5rem;
        right: -10%;
        bottom: auto;
        left: -10%;
        width: auto;
        height: 0.28rem;
        transform: rotate(-2.5deg);
        animation-name: none;
      }

      .auth-cut-aura {
        inset: -0.9rem 12%;
      }

      .auth-cut-core {
        width: 100%;
        height: 100%;
        background: linear-gradient(
          90deg,
          transparent,
          var(--_ember) 18%,
          var(--_flare) 55%,
          var(--_ember) 82%,
          transparent
        );
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *,
      *::before,
      *::after {
        scroll-behavior: auto !important;
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }

    @media (forced-colors: active) {
      .shell,
      .provider,
      .passkey,
      .submit,
      input {
        border: 1px solid CanvasText;
      }

      h1 {
        color: CanvasText;
        background: none;
        -webkit-background-clip: unset;
        background-clip: unset;
      }

      .auth-cut,
      .shell-glow {
        display: none;
      }
    }
  `
}

if (!customElements.get('sdk-auth-login')) {
  customElements.define('sdk-auth-login', SdkAuthLogin)
}

declare global {
  interface HTMLElementTagNameMap {
    'sdk-auth-login': SdkAuthLogin
  }
}
