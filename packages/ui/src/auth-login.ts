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
        <section class="manifest" aria-labelledby="sdk-auth-heading">
          <div class="brand-row">
            <span class="brand-mark" aria-hidden="true">S/A</span>
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
      --_void: var(--ska-void, #08090b);
      --_iron: var(--ska-iron, #15171c);
      --_ember: var(--ska-ember, #f43f4e);
      --_flare: var(--ska-flare, #ff6b5f);
      --_bone: var(--ska-bone, #f4efea);
      --_ash: var(--ska-ash, #8a909c);
      --_danger: var(--ska-danger, #ff7a83);
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
      -webkit-tap-highlight-color: rgb(244 63 78 / 22%);
    }

    .shell {
      position: relative;
      display: grid;
      grid-template-columns: minmax(19rem, 1.08fr) minmax(20rem, 0.92fr);
      width: 100%;
      min-width: 0;
      max-width: 100%;
      min-height: min(48rem, calc(100dvh - 2rem));
      overflow: hidden;
      border: 1px solid color-mix(in srgb, var(--_ash) 23%, transparent);
      border-radius: var(--ska-radius, 1.25rem);
      background: var(--_void);
      box-shadow: 0 2rem 6rem rgb(0 0 0 / 48%);
      isolation: isolate;
    }

    .shell::before {
      position: absolute;
      inset: 0;
      z-index: -1;
      background-image:
        linear-gradient(rgb(255 255 255 / 2.5%) 1px, transparent 1px),
        linear-gradient(90deg, rgb(255 255 255 / 2.5%) 1px, transparent 1px);
      background-size: 3.25rem 3.25rem;
      content: '';
      mask-image: linear-gradient(115deg, black, transparent 72%);
    }

    .manifest,
    .entry {
      padding: clamp(2rem, 4.8vw, 5rem);
    }

    .manifest {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-width: 0;
      background:
        radial-gradient(circle at 8% 92%, color-mix(in srgb, var(--_ember) 22%, transparent), transparent 30%),
        linear-gradient(140deg, transparent 58%, rgb(255 255 255 / 3%));
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
      letter-spacing: 0.08em;
    }

    .brand-mark {
      display: grid;
      width: 2.75rem;
      height: 2.75rem;
      place-items: center;
      border: 1px solid var(--_ember);
      color: var(--_flare);
      font-size: 0.72rem;
    }

    .eyebrow,
    .step,
    .trust-line {
      color: var(--_ash);
      font-size: 0.66rem;
    }

    .statement {
      max-width: 38rem;
      animation: reveal 650ms cubic-bezier(0.2, 0.75, 0.2, 1) both;
    }

    .signal {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      color: var(--_flare);
      font-size: 0.68rem;
      text-transform: uppercase;
    }

    .signal span {
      width: 0.45rem;
      height: 0.45rem;
      border-radius: 50%;
      background: var(--_ember);
      box-shadow: 0 0 0 0.35rem color-mix(in srgb, var(--_ember) 16%, transparent);
    }

    h1 {
      max-width: 11ch;
      margin: 1.2rem 0 1.5rem;
      font-family: var(--ska-font-display, 'Syne', 'Arial Black', sans-serif);
      font-size: clamp(3.4rem, 7vw, 7.7rem);
      font-weight: 760;
      letter-spacing: -0.065em;
      line-height: 0.86;
      text-wrap: balance;
      overflow-wrap: anywhere;
    }

    .lede {
      max-width: 31rem;
      margin: 0;
      color: color-mix(in srgb, var(--_bone) 72%, var(--_ash));
      font-size: clamp(0.95rem, 1.5vw, 1.15rem);
      line-height: 1.65;
    }

    .trust-line {
      justify-content: flex-start;
      flex-wrap: wrap;
    }

    .trust-line span:not(:last-child)::after {
      margin-left: 1rem;
      color: var(--_ember);
      content: '◆';
      font-size: 0.45rem;
    }

    .entry {
      display: flex;
      flex-direction: column;
      justify-content: center;
      min-width: 0;
      background: color-mix(in srgb, var(--_iron) 96%, transparent);
      backdrop-filter: blur(1rem);
    }

    .hint {
      margin: 0;
      color: var(--_ash);
      font-size: 0.8rem;
    }

    .providers {
      display: grid;
      gap: 0.65rem;
      margin-top: 2rem;
    }

    .provider,
    .passkey,
    .submit {
      width: 100%;
      min-height: 3.35rem;
      border: 1px solid color-mix(in srgb, var(--_ash) 28%, transparent);
      color: var(--_bone);
      cursor: pointer;
    }

    .provider {
      display: grid;
      grid-template-columns: 2rem minmax(0, 1fr) 1rem;
      align-items: center;
      gap: 0.8rem;
      padding: 0.55rem 0.85rem;
      background: rgb(255 255 255 / 2.5%);
      text-align: left;
      transition: border-color 160ms ease, background 160ms ease, transform 160ms ease;
    }

    .passkey {
      display: grid;
      grid-template-columns: 2rem minmax(0, 1fr) 1rem;
      align-items: center;
      gap: 0.8rem;
      margin-top: 0.65rem;
      padding: 0.55rem 0.85rem;
      background: color-mix(in srgb, var(--_ember) 9%, var(--_iron));
      text-align: left;
    }

    .passkey-mark {
      color: var(--_flare);
      text-align: center;
    }

    .provider:hover:not(:disabled) {
      border-color: color-mix(in srgb, var(--_ember) 62%, var(--_ash));
      background: color-mix(in srgb, var(--_ember) 8%, var(--_iron));
      transform: translateX(0.2rem);
    }

    .provider-mark {
      display: grid;
      width: 2rem;
      height: 2rem;
      place-items: center;
      border: 1px solid color-mix(in srgb, var(--_ash) 35%, transparent);
      font-family: var(--ska-font-data, monospace);
      font-size: 0.62rem;
    }

    .provider-arrow {
      color: var(--_flare);
    }

    .separator {
      display: flex;
      align-items: center;
      gap: 0.8rem;
      margin: 1.5rem 0;
      color: var(--_ash);
      font-size: 0.72rem;
    }

    .separator::before,
    .separator::after {
      height: 1px;
      flex: 1;
      background: color-mix(in srgb, var(--_ash) 22%, transparent);
      content: '';
    }

    form {
      display: grid;
      gap: 0.65rem;
    }

    form > label,
    .password-label label {
      color: color-mix(in srgb, var(--_bone) 82%, var(--_ash));
      font-size: 0.76rem;
      font-weight: 680;
    }

    input[type='email'],
    input[type='password'] {
      width: 100%;
      min-height: 3.25rem;
      margin-bottom: 0.5rem;
      border: 1px solid color-mix(in srgb, var(--_ash) 30%, transparent);
      border-radius: 0;
      outline: 0;
      background: color-mix(in srgb, var(--_void) 58%, transparent);
      color: var(--_bone);
      padding: 0 1rem;
      transition: border-color 150ms ease, box-shadow 150ms ease;
    }

    input::placeholder {
      color: color-mix(in srgb, var(--_ash) 72%, transparent);
    }

    input:focus-visible,
    button:focus-visible,
    ::slotted(a:focus-visible) {
      outline: 2px solid var(--_flare);
      outline-offset: 3px;
    }

    input[type='email']:focus,
    input[type='password']:focus {
      border-color: var(--_ember);
      box-shadow: inset 0.2rem 0 0 var(--_ember);
    }

    .remember {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      width: fit-content;
      color: var(--_ash);
      cursor: pointer;
      font-size: 0.76rem;
    }

    .remember input {
      accent-color: var(--_ember);
    }

    .error,
    .status {
      min-height: 1.3rem;
      margin: 0.35rem 0 0;
      font-size: 0.76rem;
    }

    .error {
      color: var(--_danger);
      overflow-wrap: anywhere;
    }

    .error span {
      display: inline-grid;
      width: 1rem;
      height: 1rem;
      margin-right: 0.45rem;
      place-items: center;
      border: 1px solid currentColor;
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
      margin-top: 0.25rem;
      padding: 0 0 0 1.15rem;
      border-color: var(--_ember);
      background: var(--_ember);
      color: #09090b;
      font-weight: 760;
      transition: filter 150ms ease, transform 150ms ease;
    }

    .submit:hover:not(:disabled) {
      filter: brightness(1.12);
      transform: translateY(-0.1rem);
    }

    .submit-key {
      display: grid;
      width: 3.25rem;
      align-self: stretch;
      place-items: center;
      border-left: 1px solid rgb(9 9 11 / 32%);
      font-size: 1.25rem;
    }

    button:disabled,
    input:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }

    .register {
      min-height: 1rem;
      margin: 1.2rem 0 0;
      color: var(--_ash);
      font-size: 0.76rem;
      text-align: center;
    }

    ::slotted(a) {
      color: var(--_flare);
      text-decoration-thickness: 1px;
      text-underline-offset: 0.2em;
    }

    .auth-cut {
      position: absolute;
      top: -10%;
      bottom: -10%;
      left: 54%;
      z-index: 2;
      width: 0.45rem;
      pointer-events: none;
      transform: rotate(7deg);
      transform-origin: center;
      animation: cut-in 800ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
    }

    .auth-cut-core {
      width: 100%;
      height: 100%;
      background: linear-gradient(180deg, transparent, var(--_flare) 20%, var(--_ember) 80%, transparent);
      box-shadow: 0 0 2rem color-mix(in srgb, var(--_ember) 48%, transparent);
    }

    :host([busy]) .auth-cut-core {
      animation: pulse 900ms ease-in-out infinite alternate;
    }

    @keyframes reveal {
      from { opacity: 0; transform: translateY(1.25rem); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes cut-in {
      from { opacity: 0; transform: translateY(-18%) rotate(7deg); }
      to { opacity: 1; transform: translateY(0) rotate(7deg); }
    }

    @keyframes pulse {
      to { filter: brightness(1.45); transform: scaleX(1.8); }
    }

    @media (max-width: 780px) {
      .shell {
        grid-template-columns: 1fr;
        min-height: auto;
      }

      .manifest {
        min-height: 19rem;
        padding-bottom: 3rem;
      }

      h1 {
        max-width: 8.5ch;
        margin-top: 2rem;
        font-size: clamp(2.75rem, 13vw, 4.6rem);
      }

      .lede {
        display: none;
      }

      .trust-line {
        margin-top: 2.5rem;
      }

      .entry {
        padding-top: 2.5rem;
      }

      .entry-head {
        align-items: flex-start;
      }

      .hint {
        max-width: 12rem;
        text-align: right;
      }

      .auth-cut {
        top: 17.5rem;
        right: -10%;
        bottom: auto;
        left: -10%;
        width: auto;
        height: 0.3rem;
        transform: rotate(-3deg);
        animation-name: none;
      }

      .auth-cut-core {
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, var(--_ember) 20%, var(--_flare) 80%, transparent);
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

      .auth-cut {
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
