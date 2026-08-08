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
        <div class="edge" aria-hidden="true"></div>
        <header>
          <span class="index">PROVA / 02</span>
          <span class="signal"><i></i> CANAL VERIFICADO</span>
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
                  @click=${() => { this.selectedMethod = method }}
                >${labels[method]}</button>`,
              )}
            </div>`
          : nothing}

        <form @submit=${this.submit} novalidate>
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
          ${this.showTrustDevice
            ? html`<label class="trust"><input name="trustDevice" type="checkbox" ?disabled=${this.busy} />
                <span>Confiar neste dispositivo</span></label>`
            : nothing}
          ${this.error
            ? html`<p id="challenge-error" class="error" role="alert" tabindex="-1">${this.error}</p>`
            : html`<p class="status" aria-live="polite">${this.busy ? 'Verificando…' : ''}</p>`}
          <button class="submit" type="submit" ?disabled=${this.busy}>
            <span>${this.busy ? 'Verificando' : 'Confirmar prova'}</span><span aria-hidden="true">→</span>
          </button>
        </form>
        <slot name="cancel"></slot>
      </section>
    `
  }

  static styles = css`
    :host { display: block; min-width: 0; color: var(--ska-bone, #f4efea); font-family: var(--ska-font-body, 'Manrope', sans-serif); color-scheme: dark; }
    * { box-sizing: border-box; }
    .challenge { position: relative; width: min(100%, 34rem); overflow: hidden; border: 1px solid rgb(138 144 156 / 28%); border-radius: var(--ska-radius, 1.25rem); padding: clamp(2rem, 6vw, 4rem); background: linear-gradient(145deg, #15171c, #08090b 74%); box-shadow: 0 2rem 6rem rgb(0 0 0 / 48%); }
    .edge { position: absolute; inset: 0 auto 0 0; width: .35rem; background: linear-gradient(#ff6b5f, #f43f4e 60%, transparent); box-shadow: 0 0 2rem #f43f4e; }
    header { display: flex; justify-content: space-between; gap: 1rem; font: 500 .64rem/1 'IBM Plex Mono', monospace; letter-spacing: .09em; color: #8a909c; }
    .signal { color: #ff6b5f; }
    .signal i { display: inline-block; width: .42rem; height: .42rem; margin-right: .45rem; border-radius: 50%; background: #f43f4e; box-shadow: 0 0 0 .3rem rgb(244 63 78 / 16%); }
    h2 { max-width: 9ch; margin: 2.5rem 0 1rem; font: 700 clamp(2.7rem, 9vw, 4.8rem)/.9 'Syne', sans-serif; letter-spacing: -.055em; text-wrap: balance; }
    .lede { margin: 0 0 2rem; color: #a5a9b2; line-height: 1.65; }
    .methods { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; margin-bottom: 1.5rem; }
    .methods button { min-height: 2.7rem; border: 1px solid rgb(138 144 156 / 28%); background: transparent; color: #a5a9b2; cursor: pointer; }
    .methods button.active { border-color: #f43f4e; background: rgb(244 63 78 / 10%); color: #f4efea; }
    form { display: grid; gap: .7rem; }
    form > label:not(.trust) { font-size: .76rem; font-weight: 600; }
    input[type='text'] { width: 100%; min-height: 3.7rem; border: 1px solid rgb(138 144 156 / 32%); border-radius: 0; outline: 0; padding: 0 1rem; background: rgb(8 9 11 / 72%); color: #f4efea; font: 500 1.1rem/1 'IBM Plex Mono', monospace; letter-spacing: .12em; }
    input:focus { border-color: #f43f4e; box-shadow: inset .2rem 0 #f43f4e; }
    button:focus-visible, input:focus-visible, ::slotted(a:focus-visible) { outline: 2px solid #ff6b5f; outline-offset: 3px; }
    .trust { display: flex; align-items: center; gap: .55rem; width: fit-content; color: #a5a9b2; font-size: .76rem; }
    .trust input { accent-color: #f43f4e; }
    .error, .status { min-height: 1.2rem; margin: .25rem 0; font-size: .76rem; }
    .error { color: #ff7a83; overflow-wrap: anywhere; }
    .status { color: #8a909c; }
    .submit { display: flex; align-items: center; justify-content: space-between; min-height: 3.45rem; border: 1px solid #f43f4e; padding: 0 1.1rem; background: #f43f4e; color: #09090b; cursor: pointer; font: 700 .9rem/1 'Manrope', sans-serif; }
    button:disabled, input:disabled { cursor: not-allowed; opacity: .55; }
    ::slotted(a) { display: inline-block; margin-top: 1.2rem; color: #ff6b5f; font-size: .76rem; }
    @media (max-width: 430px) { .challenge { padding: 2rem 1.4rem; } header { align-items: flex-start; } .methods { grid-template-columns: 1fr; } }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; } }
    @media (forced-colors: active) { .challenge, button, input { border: 1px solid CanvasText; } .edge { display: none; } }
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
