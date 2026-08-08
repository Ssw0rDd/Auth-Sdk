//! Authentication and MFA use-case orchestration.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sdk_auth_crypto::{
    PasswordEngine, SecretVault, TokenGenerator, digest_token, digest_token_text,
};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_mfa::{
    generate_recovery_codes, generate_totp_enrollment, matching_totp_counter,
    normalize_recovery_code,
};
use sdk_auth_types::{
    AuditRecord, AuthEvent, AuthEventKind, AuthenticationMethod, DeviceContext, EmailAddress,
    EventId, MfaEnrollmentId, MfaFactorId, OpaqueToken, RealmId, SecretString, Session, SessionId,
    TokenFamilyId, TokenPair, TrustedDevice, TrustedDeviceId, User, UserId,
};
use sdk_auth_validation::Validator as _;

use crate::{
    AccessTokenRecord, AccessValidation, AuthConfig, Authentication, BeginTotpEnrollmentRequest,
    BeginTotpReplacementRequest, ChallengeDispatch, ChallengeKind, CompleteLoginRequest,
    ConfirmTotpEnrollmentRequest, LoginAttemptPolicy, LoginOutcome, LoginRequest, ManageMfaRequest,
    MfaLoginChallenge, MfaManagementProof, RefreshRequest, RegisterRequest, Registration,
    ResetPasswordRequest, RevokeTrustedDeviceRequest, SecondFactorMethod, SecondFactorProof,
    TotpActivation, TotpEnrollment, TrustedDeviceGrant,
    ports::{
        ActivateTotp, AttemptDecision, AuthStore, Clock, CompleteMfaLogin, CreateSession,
        CreateTrustedDevice, CreateUser, MfaChallengeLookup, MfaCompletionOutcome,
        MfaEnrollmentOutcome, OneTimeChallenge, OneTimeOutcome, PendingTotpEnrollment,
        RateLimitStore, RefreshRotation, RotateTrustedLogin, StoredMfaLoginChallenge,
        StoredTotpFactor, SystemClock, TrustedLoginOutcome, VerifiedMfaProof, validate_device,
    },
};

/// Authentication application service.
pub struct AuthService {
    store: Arc<dyn AuthStore>,
    rate_limit_store: Option<Arc<dyn RateLimitStore>>,
    password_engine: Arc<dyn PasswordEngine>,
    token_generator: Arc<dyn TokenGenerator>,
    secret_vault: Arc<dyn SecretVault>,
    clock: Arc<dyn Clock>,
    config: AuthConfig,
}

impl AuthService {
    /// Starts a builder that requires every security-sensitive dependency.
    #[must_use]
    pub fn builder() -> AuthServiceBuilder {
        AuthServiceBuilder::default()
    }

    /// Registers a unique email and returns a verification secret to the trusted host.
    #[tracing::instrument(name = "sdk_auth.register", skip_all)]
    pub async fn register(&self, request: RegisterRequest) -> Result<Registration, AuthError> {
        let email = EmailAddress::parse(request.email)?;
        self.config
            .password_policy
            .validate("password", request.password.expose_secret())
            .map_err(|_| AuthError::invalid_input())?;
        let now = self.clock.now();
        let password_hash = self.password_engine.hash(&request.password)?;
        let token = self.token_generator.generate()?;
        let challenge = OneTimeChallenge {
            digest: digest_token(&token),
            kind: ChallengeKind::EmailVerification,
            user_id: UserId::new(),
            expires_at: now + self.config.email_verification_ttl,
        };
        let user = User {
            realm_id: request.realm_id,
            id: challenge.user_id,
            email,
            email_verified: false,
            created_at: now,
            updated_at: now,
        };
        self.store
            .create_user(CreateUser {
                user: user.clone(),
                password_hash,
                challenge,
                event: event(
                    request.realm_id,
                    user.id,
                    AuthEventKind::EmailVerificationRequested,
                    now,
                ),
            })
            .await?;
        Ok(Registration {
            user,
            verification: ChallengeDispatch {
                token,
                expires_at: now + self.config.email_verification_ttl,
            },
        })
    }

    /// Verifies the password and either authenticates or creates an MFA challenge.
    #[tracing::instrument(name = "sdk_auth.login", skip_all)]
    pub async fn login(&self, request: LoginRequest) -> Result<LoginOutcome, AuthError> {
        let email = EmailAddress::parse(request.email)?;
        let device = validate_device(
            request.device,
            self.config.max_device_name_chars,
            self.config.max_device_metadata_bytes,
        )?;
        let now = self.clock.now();
        let decision = self
            .record_attempt(
                request.realm_id,
                email.normalized(),
                device.network_hash.as_deref(),
                now,
                self.config.login_attempts,
            )
            .await?;
        if matches!(decision, AttemptDecision::BlockedUntil(_)) {
            return Err(rate_limited());
        }
        let stored = self
            .store
            .find_user_by_email(request.realm_id, email.normalized())
            .await?;
        let Some(stored) = stored else {
            self.password_engine.fake_verify(&request.password)?;
            return Err(AuthError::invalid_credentials());
        };
        if !self
            .password_engine
            .verify(&request.password, &stored.password_hash)?
        {
            return Err(AuthError::invalid_credentials());
        }
        self.clear_attempts(request.realm_id, email.normalized())
            .await?;
        if self.config.require_verified_email && !stored.user.email_verified {
            return Err(AuthError::new(
                ErrorCode::AccountUnverified,
                "email verification is required",
                false,
            ));
        }
        if self.password_engine.needs_rehash(&stored.password_hash) {
            let replacement = self.password_engine.hash(&request.password)?;
            self.store
                .update_password_hash(request.realm_id, stored.user.id, replacement, now)
                .await?;
        }
        let factor = self
            .store
            .find_totp_factor(request.realm_id, stored.user.id)
            .await?;
        if factor.is_none() {
            return self
                .issue_session(
                    stored.user,
                    device,
                    request.remember_me,
                    AuthenticationMethod::Password,
                    None,
                    now,
                )
                .await
                .map(|authentication| LoginOutcome::Authenticated(Box::new(authentication)));
        }
        if let Some(presented) = request
            .trusted_device_token
            .as_ref()
            .filter(|token| !token.is_empty())
        {
            let prepared = self.prepare_session(
                &stored.user,
                device.clone(),
                request.remember_me,
                AuthenticationMethod::PasswordTrustedDevice,
                Some(now),
                now,
            )?;
            let replacement = self.token_generator.generate()?;
            let outcome = self
                .store
                .rotate_trusted_and_create_session(RotateTrustedLogin {
                    realm_id: request.realm_id,
                    user_id: stored.user.id,
                    presented: digest_token_text(presented),
                    replacement: digest_token(&replacement),
                    session: prepared.command,
                    now,
                    replay_event: event(
                        request.realm_id,
                        stored.user.id,
                        AuthEventKind::TrustedDeviceReplayDetected,
                        now,
                    ),
                })
                .await?;
            if let TrustedLoginOutcome::Authenticated {
                session,
                trusted_device,
            } = outcome
            {
                return Ok(LoginOutcome::Authenticated(Box::new(Authentication {
                    user: stored.user,
                    session: *session,
                    tokens: prepared.tokens,
                    trusted_device_grant: Some(TrustedDeviceGrant {
                        device: *trusted_device,
                        token: replacement,
                    }),
                })));
            }
        }
        let challenge_token = self.token_generator.generate()?;
        let expires_at = now + self.config.mfa_login_ttl;
        self.store
            .create_mfa_login_challenge(StoredMfaLoginChallenge {
                digest: digest_token(&challenge_token),
                realm_id: request.realm_id,
                user_id: stored.user.id,
                device,
                remember_me: request.remember_me,
                attempts: 0,
                max_attempts: self.config.max_mfa_attempts,
                expires_at,
                created_at: now,
            })
            .await?;
        Ok(LoginOutcome::SecondFactorRequired(MfaLoginChallenge {
            token: challenge_token,
            methods: vec![SecondFactorMethod::Totp, SecondFactorMethod::RecoveryCode],
            expires_at,
        }))
    }

    /// Completes a post-password login without creating partial sessions.
    #[tracing::instrument(name = "sdk_auth.complete_login", skip_all)]
    pub async fn complete_login(
        &self,
        request: CompleteLoginRequest,
    ) -> Result<Authentication, AuthError> {
        if request.challenge_token.is_empty() {
            return Err(second_factor_invalid());
        }
        let now = self.clock.now();
        let challenge_digest = digest_token_text(&request.challenge_token);
        let (challenge, factor) = match self
            .store
            .load_mfa_login_challenge(request.realm_id, challenge_digest, now)
            .await?
        {
            MfaChallengeLookup::Active { challenge, factor } => (challenge, factor),
            MfaChallengeLookup::Invalid => return Err(second_factor_invalid()),
            MfaChallengeLookup::Expired => return Err(token_expired("MFA challenge expired")),
            MfaChallengeLookup::RateLimited => return Err(rate_limited()),
        };
        let challenge = *challenge;
        let factor = *factor;
        let (verified_proof, method, recovery_used) = match request.proof {
            SecondFactorProof::Totp(code) => {
                let seed = self.open_factor_seed(&factor)?;
                let Some(counter) = matching_totp_counter(
                    seed.expose_secret(),
                    code.expose_secret(),
                    unix_seconds(now)?,
                    factor.last_accepted_counter,
                )?
                else {
                    self.record_mfa_failure(request.realm_id, challenge_digest, now)
                        .await?;
                    return Err(second_factor_invalid());
                };
                (
                    VerifiedMfaProof::Totp {
                        factor_id: factor.id,
                        counter,
                    },
                    AuthenticationMethod::PasswordTotp,
                    false,
                )
            }
            SecondFactorProof::RecoveryCode(code) => {
                let normalized = normalize_recovery_code(code.expose_secret())?;
                (
                    VerifiedMfaProof::RecoveryCode(digest_token_text(&normalized)),
                    AuthenticationMethod::PasswordRecoveryCode,
                    true,
                )
            }
        };
        let stored = self
            .store
            .find_user_by_id(request.realm_id, challenge.user_id)
            .await?
            .ok_or_else(AuthError::invalid_credentials)?;
        let prepared = self.prepare_session(
            &stored.user,
            challenge.device.clone(),
            challenge.remember_me,
            method,
            Some(now),
            now,
        )?;
        let (trusted_command, trusted_token) = if request.trust_device {
            let (command, token) = self.prepare_trusted_device(
                request.realm_id,
                stored.user.id,
                challenge.device,
                now,
            )?;
            (Some(command), Some(token))
        } else {
            (None, None)
        };
        let mut events = Vec::with_capacity(2);
        if recovery_used {
            events.push(event(
                request.realm_id,
                stored.user.id,
                AuthEventKind::RecoveryCodeUsed,
                now,
            ));
        }
        if trusted_command.is_some() {
            events.push(event(
                request.realm_id,
                stored.user.id,
                AuthEventKind::TrustedDeviceCreated,
                now,
            ));
        }
        let outcome = self
            .store
            .complete_mfa_login(CompleteMfaLogin {
                challenge_digest,
                proof: verified_proof,
                session: prepared.command,
                trusted_device: trusted_command,
                events,
                now,
            })
            .await?;
        match outcome {
            MfaCompletionOutcome::Completed {
                session,
                trusted_device,
            } => Ok(Authentication {
                user: stored.user,
                session: *session,
                tokens: prepared.tokens,
                trusted_device_grant: trusted_device.zip(trusted_token).map(|(device, token)| {
                    TrustedDeviceGrant {
                        device: *device,
                        token,
                    }
                }),
            }),
            MfaCompletionOutcome::Invalid => {
                self.record_mfa_failure(request.realm_id, challenge_digest, now)
                    .await?;
                Err(second_factor_invalid())
            }
            MfaCompletionOutcome::Expired => Err(token_expired("MFA challenge expired")),
            MfaCompletionOutcome::RateLimited => Err(rate_limited()),
            MfaCompletionOutcome::Reused => Err(AuthError::new(
                ErrorCode::TokenReused,
                "second-factor proof was already used",
                false,
            )),
        }
    }

    /// Begins a password-reauthenticated TOTP enrollment.
    #[tracing::instrument(name = "sdk_auth.begin_totp_enrollment", skip_all)]
    pub async fn begin_totp_enrollment(
        &self,
        request: BeginTotpEnrollmentRequest,
    ) -> Result<TotpEnrollment, AuthError> {
        let validated = self
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        self.verify_current_password(&validated, &request.password)
            .await?;
        if self
            .store
            .find_totp_factor(request.realm_id, validated.user.id)
            .await?
            .is_some()
        {
            return Err(AuthError::new(
                ErrorCode::Conflict,
                "MFA is already enrolled",
                false,
            ));
        }
        self.create_pending_enrollment(validated.user, request.issuer, false)
            .await
    }

    /// Begins replacement after password and current-factor verification.
    #[tracing::instrument(name = "sdk_auth.begin_totp_replacement", skip_all)]
    pub async fn begin_totp_replacement(
        &self,
        request: BeginTotpReplacementRequest,
    ) -> Result<TotpEnrollment, AuthError> {
        let validated = self
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        self.verify_management_proof(&validated, &request.proof)
            .await?;
        self.create_pending_enrollment(validated.user, request.issuer, true)
            .await
    }

    /// Confirms a pending TOTP enrollment and returns recovery codes once.
    #[tracing::instrument(name = "sdk_auth.confirm_totp_enrollment", skip_all)]
    pub async fn confirm_totp_enrollment(
        &self,
        request: ConfirmTotpEnrollmentRequest,
    ) -> Result<TotpActivation, AuthError> {
        let validated = self
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        let now = self.clock.now();
        let Some(enrollment) = self
            .store
            .find_totp_enrollment(request.realm_id, validated.user.id, request.enrollment_id)
            .await?
        else {
            return Err(second_factor_invalid());
        };
        if enrollment.expires_at <= now {
            return Err(token_expired("MFA enrollment expired"));
        }
        if enrollment.attempts >= enrollment.max_attempts {
            return Err(rate_limited());
        }
        let seed = self.secret_vault.open(
            &enrollment.sealed_seed,
            &enrollment_aad(enrollment.realm_id, enrollment.user_id, enrollment.id),
        )?;
        let Some(counter) = matching_totp_counter(
            seed.expose_secret(),
            request.code.expose_secret(),
            unix_seconds(now)?,
            None,
        )?
        else {
            let decision = self
                .store
                .record_totp_enrollment_failure(
                    request.realm_id,
                    validated.user.id,
                    request.enrollment_id,
                    now,
                )
                .await?;
            return if matches!(decision, AttemptDecision::BlockedUntil(_)) {
                Err(rate_limited())
            } else {
                Err(second_factor_invalid())
            };
        };
        let factor_id = MfaFactorId::new();
        let sealed_seed = self.secret_vault.seal(
            seed.expose_secret(),
            &factor_aad(request.realm_id, validated.user.id, factor_id),
        )?;
        let recovery = generate_recovery_codes(self.config.recovery_code_count)?;
        let mut raw_codes = Vec::with_capacity(recovery.len());
        let mut recovery_digests = Vec::with_capacity(recovery.len());
        for code in recovery {
            let raw = SecretString::new(code.expose_secret());
            let normalized = normalize_recovery_code(raw.expose_secret())?;
            recovery_digests.push(digest_token_text(&normalized));
            raw_codes.push(raw);
        }
        let (trusted_command, trusted_token) = if request.trust_current_device {
            let (command, token) = self.prepare_trusted_device(
                request.realm_id,
                validated.user.id,
                validated.session.device.clone(),
                now,
            )?;
            (Some(command), Some(token))
        } else {
            (None, None)
        };
        let mut events = vec![event(
            request.realm_id,
            validated.user.id,
            if enrollment.replacing {
                AuthEventKind::MfaReplaced
            } else {
                AuthEventKind::MfaEnabled
            },
            now,
        )];
        if trusted_command.is_some() {
            events.push(event(
                request.realm_id,
                validated.user.id,
                AuthEventKind::TrustedDeviceCreated,
                now,
            ));
        }
        let trusted_public = trusted_command.as_ref().map(|value| value.device.clone());
        let outcome = self
            .store
            .activate_totp(ActivateTotp {
                enrollment_id: request.enrollment_id,
                factor: StoredTotpFactor {
                    id: factor_id,
                    realm_id: request.realm_id,
                    user_id: validated.user.id,
                    sealed_seed,
                    last_accepted_counter: Some(counter),
                    created_at: now,
                    updated_at: now,
                },
                current_session_id: validated.session.id,
                recovery_digests,
                trusted_device: trusted_command,
                events,
                now,
            })
            .await?;
        match outcome {
            MfaEnrollmentOutcome::Activated => Ok(TotpActivation {
                recovery_codes: raw_codes,
                trusted_device_grant: trusted_public
                    .zip(trusted_token)
                    .map(|(device, token)| TrustedDeviceGrant { device, token }),
            }),
            MfaEnrollmentOutcome::Invalid => Err(second_factor_invalid()),
            MfaEnrollmentOutcome::Expired => Err(token_expired("MFA enrollment expired")),
            MfaEnrollmentOutcome::RateLimited => Err(rate_limited()),
            MfaEnrollmentOutcome::Reused => Err(AuthError::new(
                ErrorCode::TokenReused,
                "TOTP counter was already used",
                false,
            )),
        }
    }

    /// Regenerates and returns a replacement recovery-code set once.
    #[tracing::instrument(name = "sdk_auth.regenerate_recovery_codes", skip_all)]
    pub async fn regenerate_recovery_codes(
        &self,
        request: ManageMfaRequest,
    ) -> Result<Vec<SecretString>, AuthError> {
        let validated = self
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        self.verify_management_proof(&validated, &request.proof)
            .await?;
        let codes = generate_recovery_codes(self.config.recovery_code_count)?;
        let mut raw = Vec::with_capacity(codes.len());
        let mut digests = Vec::with_capacity(codes.len());
        for code in codes {
            let value = SecretString::new(code.expose_secret());
            let normalized = normalize_recovery_code(value.expose_secret())?;
            digests.push(digest_token_text(&normalized));
            raw.push(value);
        }
        self.store
            .replace_recovery_codes(
                request.realm_id,
                validated.user.id,
                digests,
                event(
                    request.realm_id,
                    validated.user.id,
                    AuthEventKind::RecoveryCodesRegenerated,
                    self.clock.now(),
                ),
            )
            .await?;
        Ok(raw)
    }

    /// Disables MFA and revokes sessions, recovery codes, and trusted devices.
    #[tracing::instrument(name = "sdk_auth.disable_mfa", skip_all)]
    pub async fn disable_mfa(&self, request: ManageMfaRequest) -> Result<(), AuthError> {
        let validated = self
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        self.verify_management_proof(&validated, &request.proof)
            .await?;
        let now = self.clock.now();
        let disabled = self
            .store
            .disable_mfa(
                request.realm_id,
                validated.user.id,
                now,
                event(
                    request.realm_id,
                    validated.user.id,
                    AuthEventKind::MfaDisabled,
                    now,
                ),
            )
            .await?;
        if !disabled {
            return Err(mfa_not_enrolled());
        }
        Ok(())
    }

    /// Lists trusted-device grants owned by the authenticated user.
    #[tracing::instrument(name = "sdk_auth.list_trusted_devices", skip_all)]
    pub async fn list_trusted_devices(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
    ) -> Result<Vec<TrustedDevice>, AuthError> {
        let validated = self.validate_access(realm_id, access_token).await?;
        self.store
            .list_trusted_devices(realm_id, validated.user.id)
            .await
    }

    /// Revokes one trusted-device grant owned by the authenticated user.
    #[tracing::instrument(name = "sdk_auth.revoke_trusted_device", skip_all)]
    pub async fn revoke_trusted_device(
        &self,
        request: RevokeTrustedDeviceRequest,
    ) -> Result<bool, AuthError> {
        let validated = self
            .validate_access(request.realm_id, &request.access_token)
            .await?;
        let now = self.clock.now();
        self.store
            .revoke_trusted_device(
                request.realm_id,
                validated.user.id,
                request.trusted_device_id,
                now,
                event(
                    request.realm_id,
                    validated.user.id,
                    AuthEventKind::TrustedDeviceRevoked,
                    now,
                ),
            )
            .await
    }

    /// Re-encrypts a bounded batch of factors with the active vault key.
    #[tracing::instrument(name = "sdk_auth.rewrap_mfa_secrets", skip_all)]
    pub async fn rewrap_mfa_secrets(
        &self,
        realm_id: RealmId,
        limit: u32,
    ) -> Result<u32, AuthError> {
        if limit == 0 || limit > 1_000 {
            return Err(AuthError::invalid_input());
        }
        let factors = self
            .store
            .factors_needing_rewrap(realm_id, self.secret_vault.active_key_id(), limit)
            .await?;
        let mut updated = 0_u32;
        for mut factor in factors {
            let previous_key = factor.sealed_seed.key_id().to_owned();
            let aad = factor_aad(factor.realm_id, factor.user_id, factor.id);
            let seed = self.secret_vault.open(&factor.sealed_seed, &aad)?;
            factor.sealed_seed = self.secret_vault.seal(seed.expose_secret(), &aad)?;
            factor.updated_at = self.clock.now();
            if self
                .store
                .update_rewrapped_factor(factor, &previous_key)
                .await?
            {
                updated = updated.saturating_add(1);
            }
        }
        Ok(updated)
    }

    /// Rotates a single-use refresh token and detects replay.
    #[tracing::instrument(name = "sdk_auth.refresh", skip_all)]
    pub async fn refresh(&self, request: RefreshRequest) -> Result<Authentication, AuthError> {
        if request.refresh_token.is_empty() {
            return Err(AuthError::new(
                ErrorCode::TokenInvalid,
                "refresh token is invalid",
                false,
            ));
        }
        let now = self.clock.now();
        let access_token = self.token_generator.generate()?;
        let refresh_token = self.token_generator.generate()?;
        let access = AccessTokenRecord {
            digest: digest_token(&access_token),
            expires_at: now + self.config.access_token_ttl,
        };
        let rotation = self
            .store
            .rotate_refresh(
                request.realm_id,
                digest_token_text(&request.refresh_token),
                digest_token(&refresh_token),
                access.clone(),
                now,
                event(
                    request.realm_id,
                    UserId::from_uuid(uuid_nil()),
                    AuthEventKind::RefreshTokenReuseDetected,
                    now,
                ),
            )
            .await?;
        let session = match rotation {
            RefreshRotation::Rotated(session) => session,
            RefreshRotation::Reused => {
                return Err(AuthError::new(
                    ErrorCode::TokenReused,
                    "refresh token is invalid",
                    false,
                ));
            }
            RefreshRotation::Invalid => {
                return Err(AuthError::new(
                    ErrorCode::TokenInvalid,
                    "refresh token is invalid",
                    false,
                ));
            }
            RefreshRotation::Expired => return Err(token_expired("refresh token expired")),
            RefreshRotation::Revoked => {
                return Err(AuthError::new(
                    ErrorCode::SessionRevoked,
                    "session is revoked",
                    false,
                ));
            }
        };
        let stored = self
            .store
            .find_user_by_id(request.realm_id, session.user_id)
            .await?
            .ok_or_else(AuthError::invalid_credentials)?;
        Ok(Authentication {
            user: stored.user,
            tokens: TokenPair {
                access_token,
                refresh_token,
                access_expires_at: access.expires_at.min(session.expires_at),
                session_expires_at: session.expires_at,
            },
            session,
            trusted_device_grant: None,
        })
    }

    /// Validates an access token and resolves its user within one realm.
    #[tracing::instrument(name = "sdk_auth.validate_access", skip_all)]
    pub async fn validate_access(
        &self,
        realm_id: RealmId,
        token: &SecretString,
    ) -> Result<AccessValidation, AuthError> {
        if token.is_empty() {
            return Err(AuthError::new(
                ErrorCode::TokenInvalid,
                "access token is invalid",
                false,
            ));
        }
        let session = self
            .store
            .validate_access(realm_id, digest_token_text(token), self.clock.now())
            .await?
            .ok_or_else(|| {
                AuthError::new(ErrorCode::TokenInvalid, "access token is invalid", false)
            })?;
        let user = self
            .store
            .find_user_by_id(realm_id, session.user_id)
            .await?
            .ok_or_else(AuthError::invalid_credentials)?
            .user;
        Ok(AccessValidation { session, user })
    }

    /// Revokes the session associated with an access token.
    #[tracing::instrument(name = "sdk_auth.logout", skip_all)]
    pub async fn logout(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
    ) -> Result<(), AuthError> {
        let validated = self.validate_access(realm_id, access_token).await?;
        let now = self.clock.now();
        let _revoked = self
            .store
            .revoke_session(
                realm_id,
                validated.user.id,
                validated.session.id,
                now,
                AuditRecord::succeeded_user_action(
                    realm_id,
                    validated.user.id,
                    AuthEventKind::SessionRevoked,
                    now,
                ),
            )
            .await?;
        Ok(())
    }

    /// Lists sessions owned by the authenticated user.
    #[tracing::instrument(name = "sdk_auth.list_sessions", skip_all)]
    pub async fn list_sessions(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
    ) -> Result<Vec<Session>, AuthError> {
        let validated = self.validate_access(realm_id, access_token).await?;
        self.store.list_sessions(realm_id, validated.user.id).await
    }

    /// Revokes a selected session only when it belongs to the authenticated user.
    #[tracing::instrument(name = "sdk_auth.revoke_session", skip_all)]
    pub async fn revoke_session(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
        session_id: SessionId,
    ) -> Result<bool, AuthError> {
        let validated = self.validate_access(realm_id, access_token).await?;
        let now = self.clock.now();
        self.store
            .revoke_session(
                realm_id,
                validated.user.id,
                session_id,
                now,
                AuditRecord::succeeded_user_action(
                    realm_id,
                    validated.user.id,
                    AuthEventKind::SessionRevoked,
                    now,
                ),
            )
            .await
    }

    /// Revokes all sessions owned by the authenticated user.
    #[tracing::instrument(name = "sdk_auth.revoke_all_sessions", skip_all)]
    pub async fn revoke_all_sessions(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
    ) -> Result<u64, AuthError> {
        let validated = self.validate_access(realm_id, access_token).await?;
        let now = self.clock.now();
        self.store
            .revoke_all_sessions(
                realm_id,
                validated.user.id,
                now,
                AuditRecord::succeeded_user_action(
                    realm_id,
                    validated.user.id,
                    AuthEventKind::SessionsRevoked,
                    now,
                ),
            )
            .await
    }

    /// Creates a new email verification challenge for an existing account.
    #[tracing::instrument(name = "sdk_auth.request_email_verification", skip_all)]
    pub async fn request_email_verification(
        &self,
        realm_id: RealmId,
        email: String,
    ) -> Result<Option<ChallengeDispatch>, AuthError> {
        let email = EmailAddress::parse(email)?;
        let Some(stored) = self
            .store
            .find_user_by_email(realm_id, email.normalized())
            .await?
        else {
            return Ok(None);
        };
        if stored.user.email_verified {
            return Ok(None);
        }
        self.issue_challenge(
            realm_id,
            stored.user.id,
            ChallengeKind::EmailVerification,
            self.config.email_verification_ttl,
            AuthEventKind::EmailVerificationRequested,
        )
        .await
        .map(Some)
    }

    /// Consumes a single-use email verification token.
    #[tracing::instrument(name = "sdk_auth.verify_email", skip_all)]
    pub async fn verify_email(
        &self,
        realm_id: RealmId,
        token: &SecretString,
    ) -> Result<(), AuthError> {
        let now = self.clock.now();
        let outcome = self
            .store
            .consume_email_verification(
                realm_id,
                digest_token_text(token),
                now,
                AuditRecord::succeeded_system_action(
                    realm_id,
                    UserId::from_uuid(uuid_nil()),
                    AuthEventKind::EmailVerified,
                    now,
                ),
            )
            .await?;
        one_time_result(outcome)
    }

    /// Creates a password reset challenge without revealing account existence.
    #[tracing::instrument(name = "sdk_auth.request_password_reset", skip_all)]
    pub async fn request_password_reset(
        &self,
        realm_id: RealmId,
        email: String,
    ) -> Result<Option<ChallengeDispatch>, AuthError> {
        let email = EmailAddress::parse(email)?;
        let Some(stored) = self
            .store
            .find_user_by_email(realm_id, email.normalized())
            .await?
        else {
            return Ok(None);
        };
        self.issue_challenge(
            realm_id,
            stored.user.id,
            ChallengeKind::PasswordReset,
            self.config.password_reset_ttl,
            AuthEventKind::PasswordResetRequested,
        )
        .await
        .map(Some)
    }

    /// Changes a password, revokes sessions/trusted devices, and preserves MFA.
    #[tracing::instrument(name = "sdk_auth.reset_password", skip_all)]
    pub async fn reset_password(&self, request: ResetPasswordRequest) -> Result<(), AuthError> {
        self.config
            .password_policy
            .validate("new_password", request.new_password.expose_secret())
            .map_err(|_| AuthError::invalid_input())?;
        let now = self.clock.now();
        let hash = self.password_engine.hash(&request.new_password)?;
        let outcome = self
            .store
            .reset_password(
                request.realm_id,
                digest_token_text(&request.reset_token),
                hash,
                now,
                event(
                    request.realm_id,
                    UserId::from_uuid(uuid_nil()),
                    AuthEventKind::PasswordChanged,
                    now,
                ),
            )
            .await?;
        one_time_result(outcome)
    }

    /// Returns pending secret-free security and delivery events.
    #[tracing::instrument(name = "sdk_auth.pending_events", skip_all)]
    pub async fn pending_events(&self, limit: u32) -> Result<Vec<AuthEvent>, AuthError> {
        if limit == 0 || limit > 1_000 {
            return Err(AuthError::invalid_input());
        }
        self.store.pending_events(limit).await
    }

    /// Acknowledges one durable event idempotently.
    #[tracing::instrument(name = "sdk_auth.acknowledge_event", skip_all)]
    pub async fn acknowledge_event(&self, event_id: EventId) -> Result<bool, AuthError> {
        self.store
            .acknowledge_event(event_id, self.clock.now())
            .await
    }

    async fn create_pending_enrollment(
        &self,
        user: User,
        issuer: String,
        replacing: bool,
    ) -> Result<TotpEnrollment, AuthError> {
        let material = generate_totp_enrollment(&issuer, user.email.as_str())?;
        let now = self.clock.now();
        let id = MfaEnrollmentId::new();
        let expires_at = now + self.config.mfa_enrollment_ttl;
        let sealed_seed = self.secret_vault.seal(
            material.seed.expose_secret(),
            &enrollment_aad(user.realm_id, user.id, id),
        )?;
        self.store
            .replace_totp_enrollment(PendingTotpEnrollment {
                id,
                realm_id: user.realm_id,
                user_id: user.id,
                sealed_seed,
                replacing,
                attempts: 0,
                max_attempts: self.config.max_mfa_attempts,
                expires_at,
                created_at: now,
            })
            .await?;
        Ok(TotpEnrollment {
            id,
            base32_secret: material.base32_secret,
            provisioning_uri: material.provisioning_uri,
            expires_at,
        })
    }

    async fn verify_current_password(
        &self,
        validated: &AccessValidation,
        password: &SecretString,
    ) -> Result<(), AuthError> {
        let subject = format!("reauth:{}", validated.user.id);
        let decision = self
            .record_attempt(
                validated.user.realm_id,
                &subject,
                None,
                self.clock.now(),
                self.config.login_attempts,
            )
            .await?;
        if matches!(decision, AttemptDecision::BlockedUntil(_)) {
            return Err(rate_limited());
        }
        let stored = self
            .store
            .find_user_by_id(validated.user.realm_id, validated.user.id)
            .await?
            .ok_or_else(AuthError::invalid_credentials)?;
        if !self
            .password_engine
            .verify(password, &stored.password_hash)?
        {
            return Err(AuthError::invalid_credentials());
        }
        self.clear_attempts(validated.user.realm_id, &subject)
            .await?;
        Ok(())
    }

    async fn verify_management_proof(
        &self,
        validated: &AccessValidation,
        proof: &MfaManagementProof,
    ) -> Result<(), AuthError> {
        self.verify_current_password(validated, &proof.password)
            .await?;
        self.verify_management_second_factor(validated, &proof.second_factor)
            .await
    }

    async fn verify_management_second_factor(
        &self,
        validated: &AccessValidation,
        proof: &SecondFactorProof,
    ) -> Result<(), AuthError> {
        let subject = format!("mfa-proof:{}", validated.user.id);
        let decision = self
            .record_attempt(
                validated.user.realm_id,
                &subject,
                None,
                self.clock.now(),
                self.config.login_attempts,
            )
            .await?;
        if matches!(decision, AttemptDecision::BlockedUntil(_)) {
            return Err(rate_limited());
        }
        let Some(factor) = self
            .store
            .find_totp_factor(validated.user.realm_id, validated.user.id)
            .await?
        else {
            return Err(mfa_not_enrolled());
        };
        match proof {
            SecondFactorProof::Totp(code) => {
                let seed = self.open_factor_seed(&factor)?;
                let Some(counter) = matching_totp_counter(
                    seed.expose_secret(),
                    code.expose_secret(),
                    unix_seconds(self.clock.now())?,
                    factor.last_accepted_counter,
                )?
                else {
                    return Err(second_factor_invalid());
                };
                if !self
                    .store
                    .accept_management_totp(
                        validated.user.realm_id,
                        validated.user.id,
                        factor.id,
                        counter,
                    )
                    .await?
                {
                    return Err(second_factor_invalid());
                }
            }
            SecondFactorProof::RecoveryCode(code) => {
                let normalized = normalize_recovery_code(code.expose_secret())?;
                let now = self.clock.now();
                if !self
                    .store
                    .consume_management_recovery(
                        validated.user.realm_id,
                        validated.user.id,
                        digest_token_text(&normalized),
                        event(
                            validated.user.realm_id,
                            validated.user.id,
                            AuthEventKind::RecoveryCodeUsed,
                            now,
                        ),
                    )
                    .await?
                {
                    return Err(second_factor_invalid());
                }
            }
        }
        self.clear_attempts(validated.user.realm_id, &subject)
            .await?;
        Ok(())
    }

    pub(crate) async fn verify_authenticator_management(
        &self,
        validated: &AccessValidation,
        proof: &crate::AuthenticatorManagementProof,
        config: &AuthConfig,
    ) -> Result<(), AuthError> {
        match proof {
            crate::AuthenticatorManagementProof::CurrentPasskeySession => {
                let now = self.clock.now();
                if validated.session.authentication_method != AuthenticationMethod::Passkey
                    || validated.session.created_at + config.passkey_management_max_age < now
                {
                    return Err(AuthError::new(
                        ErrorCode::PermissionDenied,
                        "fresh authenticator proof is required",
                        false,
                    ));
                }
                Ok(())
            }
            crate::AuthenticatorManagementProof::Password {
                password,
                second_factor,
            } => {
                self.verify_current_password(validated, password).await?;
                let factor = self
                    .store
                    .find_totp_factor(validated.user.realm_id, validated.user.id)
                    .await?;
                match (factor.is_some(), second_factor.as_ref()) {
                    (true, Some(second_factor)) => {
                        self.verify_management_second_factor(validated, second_factor)
                            .await
                    }
                    (true, None) => Err(AuthError::new(
                        ErrorCode::SecondFactorInvalid,
                        "second-factor proof is invalid",
                        false,
                    )),
                    (false, None) => Ok(()),
                    (false, Some(_)) => Err(AuthError::invalid_input()),
                }
            }
        }
    }

    pub(crate) async fn find_user_by_email(
        &self,
        realm_id: RealmId,
        normalized_email: &str,
    ) -> Result<Option<crate::StoredUser>, AuthError> {
        self.store
            .find_user_by_email(realm_id, normalized_email)
            .await
    }

    pub(crate) async fn find_user_by_id(
        &self,
        realm_id: RealmId,
        user_id: UserId,
    ) -> Result<Option<crate::StoredUser>, AuthError> {
        self.store.find_user_by_id(realm_id, user_id).await
    }

    pub(crate) async fn record_authentication_attempt(
        &self,
        realm_id: RealmId,
        subject: &str,
        network_hash: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        if matches!(
            self.record_attempt(
                realm_id,
                subject,
                network_hash,
                now,
                self.config.login_attempts,
            )
            .await?,
            AttemptDecision::BlockedUntil(_)
        ) {
            return Err(rate_limited());
        }
        Ok(())
    }

    pub(crate) async fn clear_authentication_attempts(
        &self,
        realm_id: RealmId,
        subject: &str,
    ) -> Result<(), AuthError> {
        self.clear_attempts(realm_id, subject).await
    }

    async fn record_attempt(
        &self,
        realm_id: RealmId,
        subject: &str,
        network_hash: Option<&str>,
        now: DateTime<Utc>,
        policy: LoginAttemptPolicy,
    ) -> Result<AttemptDecision, AuthError> {
        if let Some(store) = &self.rate_limit_store {
            store
                .record_login_attempt(realm_id, subject, network_hash, now, policy)
                .await
        } else {
            self.store
                .record_login_attempt(realm_id, subject, network_hash, now, policy)
                .await
        }
    }

    async fn clear_attempts(&self, realm_id: RealmId, subject: &str) -> Result<(), AuthError> {
        if let Some(store) = &self.rate_limit_store {
            store.clear_login_attempts(realm_id, subject).await
        } else {
            self.store.clear_login_attempts(realm_id, subject).await
        }
    }

    pub(crate) async fn verify_iam_step_up(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
        proof: &MfaManagementProof,
    ) -> Result<UserId, AuthError> {
        let validated = self.validate_access(realm_id, access_token).await?;
        if !validated.user.email_verified {
            return Err(AuthError::new(
                ErrorCode::AccountUnverified,
                "the account must be verified",
                false,
            ));
        }
        self.verify_management_proof(&validated, proof).await?;
        Ok(validated.user.id)
    }

    fn open_factor_seed(
        &self,
        factor: &StoredTotpFactor,
    ) -> Result<sdk_auth_types::SecretBytes, AuthError> {
        self.secret_vault.open(
            &factor.sealed_seed,
            &factor_aad(factor.realm_id, factor.user_id, factor.id),
        )
    }

    async fn record_mfa_failure(
        &self,
        realm_id: RealmId,
        digest: sdk_auth_crypto::TokenDigest,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let decision = self
            .store
            .record_mfa_login_failure(realm_id, digest, now)
            .await?;
        if matches!(decision, AttemptDecision::BlockedUntil(_)) {
            return Err(rate_limited());
        }
        Ok(())
    }

    fn prepare_session(
        &self,
        user: &User,
        device: DeviceContext,
        remember_me: bool,
        authentication_method: AuthenticationMethod,
        second_factor_verified_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<PreparedSession, AuthError> {
        let access_token = self.token_generator.generate()?;
        let refresh_token = self.token_generator.generate()?;
        let session_expires_at = now
            + if remember_me {
                self.config.remember_me_ttl
            } else {
                self.config.session_ttl
            };
        let session = Session {
            realm_id: user.realm_id,
            id: SessionId::new(),
            user_id: user.id,
            device,
            authentication_method,
            second_factor_verified_at,
            created_at: now,
            last_seen_at: now,
            expires_at: session_expires_at,
            revoked_at: None,
        };
        let access = AccessTokenRecord {
            digest: digest_token(&access_token),
            expires_at: (now + self.config.access_token_ttl).min(session_expires_at),
        };
        Ok(PreparedSession {
            command: CreateSession {
                session,
                family_id: TokenFamilyId::new(),
                access: access.clone(),
                refresh_digest: digest_token(&refresh_token),
                audit: AuditRecord::succeeded_user_action(
                    user.realm_id,
                    user.id,
                    AuthEventKind::LoginSucceeded,
                    now,
                ),
            },
            tokens: TokenPair {
                access_token,
                refresh_token,
                access_expires_at: access.expires_at,
                session_expires_at,
            },
        })
    }

    pub(crate) fn prepare_external_session(
        &self,
        user: &User,
        device: DeviceContext,
        remember_me: bool,
        authentication_method: AuthenticationMethod,
        second_factor_verified_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<PreparedSession, AuthError> {
        self.prepare_session(
            user,
            device,
            remember_me,
            authentication_method,
            second_factor_verified_at,
            now,
        )
    }

    async fn issue_session(
        &self,
        user: User,
        device: DeviceContext,
        remember_me: bool,
        method: AuthenticationMethod,
        verified_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Authentication, AuthError> {
        let prepared =
            self.prepare_session(&user, device, remember_me, method, verified_at, now)?;
        let session = prepared.command.session.clone();
        self.store.create_session(prepared.command).await?;
        Ok(Authentication {
            user,
            session,
            tokens: prepared.tokens,
            trusted_device_grant: None,
        })
    }

    fn prepare_trusted_device(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        device: DeviceContext,
        now: DateTime<Utc>,
    ) -> Result<(CreateTrustedDevice, OpaqueToken), AuthError> {
        let token = self.token_generator.generate()?;
        Ok((
            CreateTrustedDevice {
                device: TrustedDevice {
                    realm_id,
                    id: TrustedDeviceId::new(),
                    user_id,
                    device,
                    created_at: now,
                    last_used_at: now,
                    expires_at: now + self.config.trusted_device_ttl,
                    revoked_at: None,
                },
                token_digest: digest_token(&token),
            },
            token,
        ))
    }

    async fn issue_challenge(
        &self,
        realm_id: RealmId,
        user_id: UserId,
        kind: ChallengeKind,
        ttl: chrono::Duration,
        event_kind: AuthEventKind,
    ) -> Result<ChallengeDispatch, AuthError> {
        let now = self.clock.now();
        let token = self.token_generator.generate()?;
        let expires_at = now + ttl;
        self.store
            .replace_challenge(
                realm_id,
                OneTimeChallenge {
                    digest: digest_token(&token),
                    kind,
                    user_id,
                    expires_at,
                },
                event(realm_id, user_id, event_kind, now),
            )
            .await?;
        Ok(ChallengeDispatch { token, expires_at })
    }
}

pub(crate) struct PreparedSession {
    pub(crate) command: CreateSession,
    pub(crate) tokens: TokenPair,
}

/// Builder for [`AuthService`].
#[derive(Default)]
pub struct AuthServiceBuilder {
    store: Option<Arc<dyn AuthStore>>,
    rate_limit_store: Option<Arc<dyn RateLimitStore>>,
    password_engine: Option<Arc<dyn PasswordEngine>>,
    token_generator: Option<Arc<dyn TokenGenerator>>,
    secret_vault: Option<Arc<dyn SecretVault>>,
    clock: Option<Arc<dyn Clock>>,
    config: Option<AuthConfig>,
}

impl AuthServiceBuilder {
    /// Supplies the composite persistence adapter.
    #[must_use]
    pub fn store(mut self, store: Arc<dyn AuthStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Overrides authentication throttling with a dedicated adapter.
    #[must_use]
    pub fn rate_limit_store(mut self, store: Arc<dyn RateLimitStore>) -> Self {
        self.rate_limit_store = Some(store);
        self
    }

    /// Supplies the password hashing engine.
    #[must_use]
    pub fn password_engine(mut self, engine: Arc<dyn PasswordEngine>) -> Self {
        self.password_engine = Some(engine);
        self
    }

    /// Supplies the cryptographically secure token generator.
    #[must_use]
    pub fn token_generator(mut self, generator: Arc<dyn TokenGenerator>) -> Self {
        self.token_generator = Some(generator);
        self
    }

    /// Supplies the versioned authenticated secret vault.
    #[must_use]
    pub fn secret_vault(mut self, vault: Arc<dyn SecretVault>) -> Self {
        self.secret_vault = Some(vault);
        self
    }

    /// Supplies a deterministic clock, primarily for tests.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Supplies validated authentication policy.
    #[must_use]
    pub fn config(mut self, config: AuthConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Validates dependencies and constructs the service.
    pub fn build(self) -> Result<AuthService, AuthError> {
        let config = self.config.unwrap_or_default();
        config.validate()?;
        Ok(AuthService {
            store: self.store.ok_or_else(misconfigured)?,
            rate_limit_store: self.rate_limit_store,
            password_engine: self.password_engine.ok_or_else(misconfigured)?,
            token_generator: self.token_generator.ok_or_else(misconfigured)?,
            secret_vault: self.secret_vault.ok_or_else(misconfigured)?,
            clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
            config,
        })
    }
}

pub(crate) fn event(
    realm_id: RealmId,
    user_id: UserId,
    kind: AuthEventKind,
    now: DateTime<Utc>,
) -> AuthEvent {
    AuthEvent {
        id: EventId::new(),
        realm_id,
        user_id,
        kind,
        payload: "{}".to_owned(),
        created_at: now,
    }
}

fn factor_aad(realm_id: RealmId, user_id: UserId, factor_id: MfaFactorId) -> Vec<u8> {
    format!("sdk-auth|totp-factor|{realm_id}|{user_id}|{factor_id}").into_bytes()
}

fn enrollment_aad(realm_id: RealmId, user_id: UserId, enrollment_id: MfaEnrollmentId) -> Vec<u8> {
    format!("sdk-auth|totp-enrollment|{realm_id}|{user_id}|{enrollment_id}").into_bytes()
}

fn unix_seconds(now: DateTime<Utc>) -> Result<u64, AuthError> {
    now.timestamp()
        .try_into()
        .map_err(|_| AuthError::crypto_failure())
}

fn one_time_result(outcome: OneTimeOutcome) -> Result<(), AuthError> {
    match outcome {
        OneTimeOutcome::Consumed(_) => Ok(()),
        OneTimeOutcome::Invalid => Err(AuthError::new(
            ErrorCode::TokenInvalid,
            "one-time token is invalid",
            false,
        )),
        OneTimeOutcome::Expired => Err(token_expired("one-time token expired")),
        OneTimeOutcome::Reused => Err(AuthError::new(
            ErrorCode::TokenReused,
            "one-time token was already used",
            false,
        )),
    }
}

fn second_factor_invalid() -> AuthError {
    AuthError::new(
        ErrorCode::SecondFactorInvalid,
        "second-factor verification failed",
        false,
    )
}

fn mfa_not_enrolled() -> AuthError {
    AuthError::new(ErrorCode::MfaNotEnrolled, "MFA is not enrolled", false)
}

fn rate_limited() -> AuthError {
    AuthError::new(
        ErrorCode::RateLimited,
        "authentication is temporarily rate limited",
        true,
    )
}

fn token_expired(message: &'static str) -> AuthError {
    AuthError::new(ErrorCode::TokenExpired, message, false)
}

fn misconfigured() -> AuthError {
    AuthError::new(
        ErrorCode::Misconfigured,
        "authentication service dependency is missing",
        false,
    )
}

const fn uuid_nil() -> uuid::Uuid {
    uuid::Uuid::nil()
}
