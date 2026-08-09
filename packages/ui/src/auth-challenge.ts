import '@fontsource/manrope/latin-400.css'
import '@fontsource/manrope/latin-600.css'
import '@fontsource/syne/latin-700.css'
import '@fontsource/ibm-plex-mono/latin-500.css'

import { LitElement, css, html, nothing, type PropertyValues } from 'lit'

export type ChallengeMethod = 'totp' | 'recovery_code'

export interface SecondFactorSubmitDetail {
  method: ChallengeMethod
  proof: string
  trustDevice: boolean
}

const labels: Readonly<Record<ChallengeMethod, string>> = {
  totp: 'Aplicativo autenticador',
  recovery_code: 'Código de recuperação',
}

export class SdkAuthChallenge extends LitElement {
  static properties = {
    busy: { type: Boolean, reflect: true },
    error: { type: String },
    heading: { type: String },
    methods: { attribute: false },
    selectedMethod: { state: true },
    showTrustDevice: { type: Boolean, attribute: 'show-trust-device' },
  }

  declare busy: boolean
  declare error: string
  declare heading: string
  declare methods: ChallengeMethod[]
  declare selectedMethod: ChallengeMethod
  declare showTrustDevice: boolean

  constructor() {
    super()
    this.busy = false
    this.error = ''
    this.heading = 'Confirme a segunda prova.'
    this.methods = ['totp']
    this.selectedMethod = 'totp'
    this.showTrustDevice = true
  }

  protected updated(changed: PropertyValues<this>): void {
    super.updated(changed)
    if (changed.has('methods') && !this.methods.includes(this.selectedMethod)) {
      this.selectedMethod = this.methods[0] ?? 'totp'
    }
    if (changed.has('error') && this.error) {
      this.renderRoot.querySelector<HTMLElement>('#challenge-error')?.focus({ preventScroll: true })
    }
  }

  private submit(event: SubmitEvent): void {
    event.preventDefault()
    if (this.busy) return
    const form = event.currentTarget
    if (!(form instanceof HTMLFormElement) || !form.reportValidity()) return
    const data = new FormData(form)
    this.dispatchEvent(
      new CustomEvent<SecondFactorSubmitDetail>('sdk-auth:second-factor-submit', {
        bubbles: true,
        composed: true,
        detail: {
          method: this.selectedMethod,
          proof: String(data.get('proof') ?? '').trim(),
          trustDevice: data.get('trustDevice') === 'on',
        },
      }),
    )
  }

  protected render() {
    const recovery = this.selectedMethod === 'recovery_code'
    return html`
      <section class="challenge" aria-busy=${String(this.busy)} aria-labelledby="challenge-heading">
        <div class="glow" aria-hidden="true"></div>
        <div class="edge" aria-hidden="true"></div>
        <div class="mesh" aria-hidden="true"></div>
        <header>
          <span class="index">PROVA / 02</span>
          <span class="signal"><i></i> Canal verificado</span>
        </header>
        <h2 id="challenge-heading">${this.heading}</h2>
        <p class="lede">A senha passou. Falta uma prova curta que nunca sai deste navegador.</p>

        ${this.methods.length > 1
          ? html`<div class="methods" role="radiogroup" aria-label="Método de verificação">
              ${this.methods.map(
                (method) => html`<button
                  type="button"
                  role="radio"
                  aria-checked=${String(method === this.selectedMethod)}
                  class=${method === this.selectedMethod ? 'active' : ''}
                  ?disabled=${this.busy}
                  @click=${() => {
                    this.selectedMethod = method
                  }}
                >
                  ${labels[method]}
                </button>`,
              )}
            </div>`
          : nothing}

        <form @submit=${this.submit} novalidate>
          <div class="field">
            <label for="proof">${labels[this.selectedMethod]}</label>
            <input
              id="proof"
              name="proof"
              type="text"
              inputmode=${recovery ? 'text' : 'numeric'}
              autocomplete="one-time-code"
              autocapitalize="characters"
              spellcheck="false"
              placeholder=${recovery ? 'XXXX-XXXX-XXXX' : '000 000'}
              aria-describedby=${this.error ? 'challenge-error' : nothing}
              ?disabled=${this.busy}
              required
            />
          </div>
          ${this.showTrustDevice
            ? html`<label class="trust">
                <input name="trustDevice" type="checkbox" ?disabled=${this.busy} />
                <span>Confiar neste dispositivo</span>
              </label>`
            : nothing}
          ${this.error
            ? html`<p id="challenge-error" class="error" role="alert" tabindex="-1">
                <span aria-hidden="true">!</span>${this.error}
              </p>`
            : html`<p class="status" aria-live="polite">${this.busy ? 'Verificando…' : ''}</p>`}
          <button class="submit" type="submit" ?disabled=${this.busy}>
            <span>${this.busy ? 'Verificando' : 'Confirmar prova'}</span>
            <span class="submit-key" aria-hidden="true">→</span>
          </button>
        </form>
        <div class="cancel-wrap">
          <slot name="cancel"></slot>
        </div>
      </section>
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
      color: var(--_bone);
      font-family: var(--ska-font-body, 'Manrope', sans-serif);
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

    .challenge {
      position: relative;
      width: min(100%, 36rem);
      overflow: hidden;
      border: 1px solid color-mix(in srgb, var(--_ash) 26%, transparent);
      border-radius: var(--ska-radius, 1.15rem);
      padding: clamp(2rem, 5.5vw, 3.75rem);
      background:
        linear-gradient(155deg, color-mix(in srgb, var(--_steel) 70%, var(--_void)) 0%, var(--_void) 72%),
        var(--_void);
      box-shadow:
        0 0 0 1px rgb(255 255 255 / 2.5%) inset,
        0 1.25rem 2.5rem rgb(0 0 0 / 35%),
        0 2.5rem 5rem rgb(0 0 0 / 45%);
      isolation: isolate;
      animation: panel-in 720ms var(--_ease) both;
    }

    .glow {
      position: absolute;
      top: -25%;
      right: -10%;
      z-index: 0;
      width: 55%;
      height: 55%;
      background: radial-gradient(circle, color-mix(in srgb, var(--_ember) 20%, transparent), transparent 70%);
      pointer-events: none;
    }

    .mesh {
      position: absolute;
      inset: 0;
      z-index: 0;
      background-image:
        linear-gradient(rgb(255 255 255 / 2%) 1px, transparent 1px),
        linear-gradient(90deg, rgb(255 255 255 / 2%) 1px, transparent 1px);
      background-size: 2.5rem 2.5rem;
      mask-image: linear-gradient(160deg, black, transparent 70%);
      opacity: 0.7;
      pointer-events: none;
    }

    .edge {
      position: absolute;
      inset: 0 auto 0 0;
      z-index: 1;
      width: 0.32rem;
      background: linear-gradient(
        180deg,
        var(--_flare),
        var(--_ember) 55%,
        color-mix(in srgb, var(--_ember) 40%, transparent)
      );
      box-shadow:
        0 0 1.25rem color-mix(in srgb, var(--_ember) 55%, transparent),
        0 0 2.5rem color-mix(in srgb, var(--_ember) 25%, transparent);
    }

    header,
    h2,
    .lede,
    .methods,
    form,
    .cancel-wrap {
      position: relative;
      z-index: 1;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      font-family: var(--ska-font-data, 'IBM Plex Mono', monospace);
      font-size: 0.64rem;
      font-weight: 500;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--_ash);
    }

    .signal {
      display: inline-flex;
      align-items: center;
      color: var(--_flare);
    }

    .signal i {
      display: inline-block;
      width: 0.4rem;
      height: 0.4rem;
      margin-right: 0.5rem;
      border-radius: 50%;
      background: var(--_ember);
      box-shadow: 0 0 0 0.28rem color-mix(in srgb, var(--_ember) 16%, transparent);
      animation: live 2.6s ease-in-out infinite;
    }

    h2 {
      max-width: 10ch;
      margin: 2.35rem 0 1rem;
      font-family: var(--ska-font-display, 'Syne', sans-serif);
      font-size: clamp(2.55rem, 8vw, 4.5rem);
      font-weight: 700;
      letter-spacing: -0.06em;
      line-height: 0.88;
      text-wrap: balance;
      background: linear-gradient(180deg, #fff8f4 18%, color-mix(in srgb, var(--_bone) 88%, var(--_flare)));
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
    }

    .lede {
      margin: 0 0 1.85rem;
      max-width: 32ch;
      color: color-mix(in srgb, var(--_mist) 78%, var(--_ash));
      font-size: 0.98rem;
      line-height: 1.7;
    }

    .methods {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.5rem;
      margin-bottom: 1.45rem;
    }

    .methods button {
      min-height: 2.75rem;
      border: 1px solid color-mix(in srgb, var(--_ash) 28%, transparent);
      border-radius: var(--ska-radius-sm, 0.55rem);
      background: color-mix(in srgb, var(--_void-lift) 70%, transparent);
      color: var(--_ash);
      cursor: pointer;
      font-size: 0.8rem;
      transition:
        border-color 160ms ease,
        background 160ms ease,
        color 160ms ease,
        box-shadow 160ms ease;
    }

    .methods button:hover:not(:disabled):not(.active) {
      border-color: color-mix(in srgb, var(--_ember) 40%, var(--_ash));
      color: var(--_bone);
    }

    .methods button.active {
      border-color: color-mix(in srgb, var(--_ember) 75%, var(--_ash));
      background: color-mix(in srgb, var(--_ember) 12%, var(--_iron));
      color: var(--_bone);
      box-shadow: 0 0 0 1px color-mix(in srgb, var(--_ember) 12%, transparent) inset;
    }

    form {
      display: grid;
      gap: 0.9rem;
    }

    .field {
      display: grid;
      gap: 0.5rem;
    }

    form > .field > label {
      color: color-mix(in srgb, var(--_bone) 86%, var(--_ash));
      font-size: 0.74rem;
      font-weight: 600;
    }

    input[type='text'] {
      width: 100%;
      min-height: 3.85rem;
      border: 1px solid color-mix(in srgb, var(--_ash) 30%, transparent);
      border-radius: var(--ska-radius-sm, 0.55rem);
      outline: 0;
      padding: 0 1.1rem;
      background:
        linear-gradient(180deg, rgb(255 255 255 / 2.5%), transparent 45%),
        color-mix(in srgb, var(--_void) 82%, var(--_iron));
      color: var(--_bone);
      font-family: var(--ska-font-data, 'IBM Plex Mono', monospace);
      font-size: 1.2rem;
      font-weight: 500;
      letter-spacing: 0.18em;
      text-align: center;
      transition:
        border-color 150ms ease,
        box-shadow 150ms ease;
    }

    input[type='text']::placeholder {
      color: color-mix(in srgb, var(--_ash) 55%, transparent);
      letter-spacing: 0.22em;
    }

    input[type='text']:focus {
      border-color: color-mix(in srgb, var(--_ember) 80%, var(--_ash));
      box-shadow:
        inset 0.18rem 0 0 var(--_ember),
        0 0 0 3px color-mix(in srgb, var(--_ember) 14%, transparent);
    }

    button:focus-visible,
    input:focus-visible,
    ::slotted(a:focus-visible) {
      outline: 2px solid var(--_flare);
      outline-offset: 3px;
    }

    .trust {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      width: fit-content;
      color: var(--_ash);
      font-size: 0.76rem;
      cursor: pointer;
      user-select: none;
    }

    .trust input {
      width: 1rem;
      height: 1rem;
      accent-color: var(--_ember);
    }

    .error,
    .status {
      min-height: 1.2rem;
      margin: 0;
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
      min-height: 3.4rem;
      padding: 0 0 0 1.15rem;
      border: 1px solid color-mix(in srgb, var(--_ember) 90%, #fff);
      border-radius: var(--ska-radius-sm, 0.55rem);
      background: linear-gradient(
        180deg,
        color-mix(in srgb, var(--_flare) 55%, var(--_ember)),
        var(--_ember)
      );
      color: #0a0506;
      cursor: pointer;
      font-family: var(--ska-font-body, 'Manrope', sans-serif);
      font-size: 0.92rem;
      font-weight: 700;
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
      width: 3.15rem;
      align-self: stretch;
      place-items: center;
      border-left: 1px solid rgb(10 5 6 / 22%);
      font-size: 1.15rem;
      background: rgb(10 5 6 / 8%);
    }

    button:disabled,
    input:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }

    .cancel-wrap {
      margin-top: 1.2rem;
    }

    ::slotted(a) {
      display: inline-block;
      color: var(--_flare);
      font-size: 0.76rem;
      text-decoration-thickness: 1px;
      text-underline-offset: 0.22em;
      transition: color 140ms ease;
    }

    ::slotted(a:hover) {
      color: var(--_bone);
    }

    @keyframes panel-in {
      from {
        opacity: 0;
        transform: translateY(0.9rem) scale(0.985);
      }
      to {
        opacity: 1;
        transform: translateY(0) scale(1);
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

    @media (max-width: 430px) {
      .challenge {
        padding: 1.85rem 1.35rem;
      }

      header {
        align-items: flex-start;
        flex-direction: column;
        gap: 0.55rem;
      }

      .methods {
        grid-template-columns: 1fr;
      }

      h2 {
        font-size: clamp(2.35rem, 12vw, 3.4rem);
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *,
      *::before,
      *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }

    @media (forced-colors: active) {
      .challenge,
      button,
      input {
        border: 1px solid CanvasText;
      }

      h2 {
        color: CanvasText;
        background: none;
        -webkit-background-clip: unset;
        background-clip: unset;
      }

      .edge,
      .glow,
      .mesh {
        display: none;
      }
    }
  `
}

if (!customElements.get('sdk-auth-challenge')) {
  customElements.define('sdk-auth-challenge', SdkAuthChallenge)
}

declare global {
  interface HTMLElementTagNameMap {
    'sdk-auth-challenge': SdkAuthChallenge
  }
}
