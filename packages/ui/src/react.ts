import React from 'react'
import { createComponent } from '@lit/react'

import { SdkAuthLogin } from './auth-login'
import { SdkAuthChallenge } from './auth-challenge'

export const AuthLogin = createComponent({
  tagName: 'sdk-auth-login',
  elementClass: SdkAuthLogin,
  react: React,
  events: {
    onPasswordSubmit: 'sdk-auth:password-submit',
    onPasskeySubmit: 'sdk-auth:passkey',
    onProviderSubmit: 'sdk-auth:provider',
  },
})

export const AuthChallenge = createComponent({
  tagName: 'sdk-auth-challenge',
  elementClass: SdkAuthChallenge,
  react: React,
  events: {
    onSecondFactorSubmit: 'sdk-auth:second-factor-submit',
  },
})
