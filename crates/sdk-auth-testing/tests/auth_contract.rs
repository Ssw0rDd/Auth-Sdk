//! Cross-adapter authentication and security regression contract.

use std::sync::Arc;

use chrono::{Duration, TimeZone as _, Utc};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sdk_auth_core::{
    AuthConfig, AuthService, AuthStore, BeginTotpEnrollmentRequest, BeginTotpReplacementRequest,
    Clock, CompleteLoginRequest, ConfirmTotpEnrollmentRequest, LoginOutcome, LoginRequest,
    ManageMfaRequest, MfaManagementProof, RefreshRequest, RegisterRequest, ResetPasswordRequest,
    RevokeTrustedDeviceRequest, SecondFactorProof,
};
use sdk_auth_crypto::{Argon2PasswordEngine, OsTokenGenerator, VaultKey, XChaCha20Vault};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_memory::MemoryAuthStore;
use sdk_auth_sqlite::{SqliteAuthStore, SqliteMigrator};
use sdk_auth_testing::ManualClock;
use sdk_auth_types::{AuthenticationMethod, DeviceContext, RealmId, SecretBytes, SecretString};
use sha1::Sha1;

fn vault() -> Result<Arc<XChaCha20Vault>, AuthError> {
    Ok(Arc::new(XChaCha20Vault::new(
        "test-v1",
        vec![VaultKey::new("test-v1", SecretBytes::new(vec![0x5A; 32]))?],
    )?))
}

fn authenticated(outcome: LoginOutcome) -> Result<sdk_auth_core::Authentication, AuthError> {
    #[allow(unreachable_patterns)]
    match outcome {
        LoginOutcome::Authenticated(authentication) => Ok(*authentication),
        LoginOutcome::SecondFactorRequired(_) => Err(AuthError::storage_unavailable()),
        _ => Err(AuthError::storage_unavailable()),
    }
}

fn second_factor(outcome: LoginOutcome) -> Result<sdk_auth_core::MfaLoginChallenge, AuthError> {
    #[allow(unreachable_patterns)]
    match outcome {
        LoginOutcome::SecondFactorRequired(challenge) => Ok(challenge),
        LoginOutcome::Authenticated(_) => Err(AuthError::storage_unavailable()),
        _ => Err(AuthError::storage_unavailable()),
    }
}

fn test_totp(base32: &str, unix_seconds: i64) -> Result<String, AuthError> {
    let seed = decode_base32(base32)?;
    let counter = u64::try_from(unix_seconds).map_err(|_| AuthError::crypto_failure())? / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(&seed).map_err(|_| AuthError::crypto_failure())?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", binary % 1_000_000))
}

fn decode_base32(value: &str) -> Result<Vec<u8>, AuthError> {
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(AuthError::invalid_input()),
        };
        buffer = (buffer << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if output.len() == 20 {
        Ok(output)
    } else {
        Err(AuthError::invalid_input())
    }
}

pub(crate) fn service(store: Arc<dyn AuthStore>) -> Result<Arc<AuthService>, AuthError> {
    Ok(Arc::new(
        AuthService::builder()
            .store(store)
            .password_engine(Arc::new(Argon2PasswordEngine::recommended()?))
            .token_generator(Arc::new(OsTokenGenerator))
            .secret_vault(vault()?)
            .config(AuthConfig::default())
            .build()?,
    ))
}

fn service_with_clock(
    store: Arc<dyn AuthStore>,
    clock: Arc<ManualClock>,
) -> Result<Arc<AuthService>, AuthError> {
    Ok(Arc::new(
        AuthService::builder()
            .store(store)
            .password_engine(Arc::new(Argon2PasswordEngine::recommended()?))
            .token_generator(Arc::new(OsTokenGenerator))
            .secret_vault(vault()?)
            .clock(clock)
            .config(AuthConfig::default())
            .build()?,
    ))
}

fn service_with_vault(
    store: Arc<dyn AuthStore>,
    clock: Arc<ManualClock>,
    vault: Arc<XChaCha20Vault>,
) -> Result<Arc<AuthService>, AuthError> {
    Ok(Arc::new(
        AuthService::builder()
            .store(store)
            .password_engine(Arc::new(Argon2PasswordEngine::recommended()?))
            .token_generator(Arc::new(OsTokenGenerator))
            .secret_vault(vault)
            .clock(clock)
            .config(AuthConfig::default())
            .build()?,
    ))
}

fn rotating_vault(
    active_key_id: &str,
    keys: &[(&str, u8)],
) -> Result<Arc<XChaCha20Vault>, AuthError> {
    let mut vault_keys = Vec::with_capacity(keys.len());
    for (key_id, fill) in keys {
        vault_keys.push(VaultKey::new(
            (*key_id).to_owned(),
            SecretBytes::new(vec![*fill; 32]),
        )?);
    }
    Ok(Arc::new(XChaCha20Vault::new(active_key_id, vault_keys)?))
}

async fn register_verify_login(
    service: &AuthService,
    realm_id: RealmId,
) -> Result<sdk_auth_core::Authentication, AuthError> {
    let registration = service
        .register(RegisterRequest {
            realm_id,
            email: "User@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
        })
        .await?;
    service
        .verify_email(
            realm_id,
            &SecretString::new(registration.verification.token.expose_secret()),
        )
        .await?;
    let outcome = service
        .login(LoginRequest {
            realm_id,
            email: "user@EXAMPLE.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
            remember_me: false,
            trusted_device_token: None,
            device: DeviceContext {
                name: Some("test device".to_owned()),
                network_hash: Some("network:test".to_owned()),
                user_agent: Some("contract-test".to_owned()),
            },
        })
        .await?;
    authenticated(outcome)
}

pub(crate) async fn exercise_contract(service: Arc<AuthService>) -> Result<(), AuthError> {
    let realm_id = RealmId::new();
    let authentication = register_verify_login(&service, realm_id).await?;
    let user_id = authentication.user.id;
    let access = authentication
        .tokens
        .access_token
        .expose_secret()
        .to_owned();
    let refresh = authentication
        .tokens
        .refresh_token
        .expose_secret()
        .to_owned();

    let validated = service
        .validate_access(realm_id, &SecretString::new(access.clone()))
        .await?;
    assert_eq!(validated.user.id, user_id);
    assert_eq!(
        service
            .list_sessions(realm_id, &SecretString::new(access.clone()))
            .await?
            .len(),
        1
    );

    let rotated = service
        .refresh(RefreshRequest {
            realm_id,
            refresh_token: SecretString::new(refresh.clone()),
        })
        .await?;
    assert_eq!(rotated.user.id, user_id);
    assert_ne!(rotated.tokens.refresh_token.expose_secret(), refresh);

    let replay = service
        .refresh(RefreshRequest {
            realm_id,
            refresh_token: SecretString::new(refresh),
        })
        .await;
    assert_eq!(
        replay.err().map(|error| error.code()),
        Some(ErrorCode::TokenReused)
    );
    let revoked_access = service
        .validate_access(
            realm_id,
            &SecretString::new(rotated.tokens.access_token.expose_secret()),
        )
        .await;
    assert_eq!(
        revoked_access.err().map(|error| error.code()),
        Some(ErrorCode::TokenInvalid)
    );
    Ok(())
}

pub(crate) async fn exercise_mfa_contract(store: Arc<dyn AuthStore>) -> Result<(), AuthError> {
    let instant = Utc
        .with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
        .single()
        .ok_or_else(AuthError::storage_unavailable)?;
    let clock = Arc::new(ManualClock::new(instant));
    let service = service_with_clock(store, Arc::clone(&clock))?;
    let realm_id = RealmId::new();
    let initial = register_verify_login(&service, realm_id).await?;
    let initial_access = SecretString::new(initial.tokens.access_token.expose_secret());

    let enrollment = service
        .begin_totp_enrollment(BeginTotpEnrollmentRequest {
            realm_id,
            access_token: SecretString::new(initial_access.expose_secret()),
            password: SecretString::new("correct horse battery staple"),
            issuer: "SDK Auth Contract".to_owned(),
        })
        .await?;
    let enrollment_code = test_totp(
        enrollment.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    let activation = service
        .confirm_totp_enrollment(ConfirmTotpEnrollmentRequest {
            realm_id,
            access_token: SecretString::new(initial_access.expose_secret()),
            enrollment_id: enrollment.id,
            code: SecretString::new(enrollment_code),
            trust_current_device: false,
        })
        .await?;
    assert_eq!(activation.recovery_codes.len(), 10);
    let first_recovery = activation.recovery_codes[0].expose_secret().to_owned();
    let upgraded = service.validate_access(realm_id, &initial_access).await?;
    assert_eq!(
        upgraded.session.authentication_method,
        AuthenticationMethod::PasswordTotp
    );

    clock.advance(Duration::seconds(30))?;
    let challenge = second_factor(
        service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("correct horse battery staple"),
                remember_me: false,
                device: DeviceContext {
                    name: Some("mfa device".to_owned()),
                    network_hash: Some("network:mfa".to_owned()),
                    user_agent: Some("mfa-contract".to_owned()),
                },
                trusted_device_token: None,
            })
            .await?,
    )?;
    let challenge_token = challenge.token.expose_secret().to_owned();
    let login_code = test_totp(
        enrollment.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    let mfa_authentication = service
        .complete_login(CompleteLoginRequest {
            realm_id,
            challenge_token: SecretString::new(challenge_token.clone()),
            proof: SecondFactorProof::Totp(SecretString::new(login_code.clone())),
            trust_device: true,
        })
        .await?;
    assert_eq!(
        mfa_authentication.session.authentication_method,
        AuthenticationMethod::PasswordTotp
    );
    let grant = mfa_authentication
        .trusted_device_grant
        .as_ref()
        .ok_or_else(AuthError::storage_unavailable)?;
    let first_trusted_token = grant.token.expose_secret().to_owned();
    let trusted_device_id = grant.device.id;
    let replay = service
        .complete_login(CompleteLoginRequest {
            realm_id,
            challenge_token: SecretString::new(challenge_token),
            proof: SecondFactorProof::Totp(SecretString::new(login_code)),
            trust_device: false,
        })
        .await;
    assert_eq!(
        replay.err().map(|error| error.code()),
        Some(ErrorCode::SecondFactorInvalid)
    );

    let trusted_authentication = authenticated(
        service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("correct horse battery staple"),
                remember_me: true,
                device: DeviceContext::default(),
                trusted_device_token: Some(SecretString::new(first_trusted_token.clone())),
            })
            .await?,
    )?;
    assert_eq!(
        trusted_authentication.session.authentication_method,
        AuthenticationMethod::PasswordTrustedDevice
    );
    let rotated_grant = trusted_authentication
        .trusted_device_grant
        .as_ref()
        .ok_or_else(AuthError::storage_unavailable)?;
    assert_eq!(rotated_grant.device.id, trusted_device_id);
    assert_ne!(rotated_grant.token.expose_secret(), first_trusted_token);
    let trusted_access =
        SecretString::new(trusted_authentication.tokens.access_token.expose_secret());
    assert_eq!(
        service
            .list_trusted_devices(realm_id, &trusted_access)
            .await?
            .len(),
        1
    );
    let session_count = service
        .list_sessions(realm_id, &trusted_access)
        .await?
        .len();
    let replayed_trusted = second_factor(
        service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("correct horse battery staple"),
                remember_me: false,
                device: DeviceContext::default(),
                trusted_device_token: Some(SecretString::new(first_trusted_token)),
            })
            .await?,
    )?;
    assert_eq!(
        service
            .list_sessions(realm_id, &trusted_access)
            .await?
            .len(),
        session_count
    );
    let devices = service
        .list_trusted_devices(realm_id, &trusted_access)
        .await?;
    assert!(devices[0].revoked_at.is_some());
    drop(replayed_trusted);

    let recovery_challenge = second_factor(
        service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("correct horse battery staple"),
                remember_me: false,
                device: DeviceContext::default(),
                trusted_device_token: None,
            })
            .await?,
    )?;
    let recovery_authentication = service
        .complete_login(CompleteLoginRequest {
            realm_id,
            challenge_token: SecretString::new(recovery_challenge.token.expose_secret()),
            proof: SecondFactorProof::RecoveryCode(SecretString::new(first_recovery.clone())),
            trust_device: false,
        })
        .await?;
    assert_eq!(
        recovery_authentication.session.authentication_method,
        AuthenticationMethod::PasswordRecoveryCode
    );
    let reused_recovery_challenge = second_factor(
        service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("correct horse battery staple"),
                remember_me: false,
                device: DeviceContext::default(),
                trusted_device_token: None,
            })
            .await?,
    )?;
    let reused_recovery = service
        .complete_login(CompleteLoginRequest {
            realm_id,
            challenge_token: SecretString::new(reused_recovery_challenge.token.expose_secret()),
            proof: SecondFactorProof::RecoveryCode(SecretString::new(first_recovery)),
            trust_device: false,
        })
        .await;
    assert_eq!(
        reused_recovery.err().map(|error| error.code()),
        Some(ErrorCode::TokenReused)
    );

    let reset = service
        .request_password_reset(realm_id, "user@example.com".to_owned())
        .await?
        .ok_or_else(AuthError::storage_unavailable)?;
    service
        .reset_password(ResetPasswordRequest {
            realm_id,
            reset_token: SecretString::new(reset.token.expose_secret()),
            new_password: SecretString::new("new correct horse battery staple"),
        })
        .await?;
    let post_reset_challenge = second_factor(
        service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("new correct horse battery staple"),
                remember_me: false,
                device: DeviceContext::default(),
                trusted_device_token: None,
            })
            .await?,
    )?;
    clock.advance(Duration::seconds(30))?;
    let post_reset_code = test_totp(
        enrollment.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    let post_reset_authentication = service
        .complete_login(CompleteLoginRequest {
            realm_id,
            challenge_token: SecretString::new(post_reset_challenge.token.expose_secret()),
            proof: SecondFactorProof::Totp(SecretString::new(post_reset_code)),
            trust_device: false,
        })
        .await?;

    clock.advance(Duration::seconds(30))?;
    let disable_code = test_totp(
        enrollment.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    service
        .disable_mfa(ManageMfaRequest {
            realm_id,
            access_token: SecretString::new(
                post_reset_authentication
                    .tokens
                    .access_token
                    .expose_secret(),
            ),
            proof: MfaManagementProof {
                password: SecretString::new("new correct horse battery staple"),
                second_factor: SecondFactorProof::Totp(SecretString::new(disable_code)),
            },
        })
        .await?;
    let password_only = authenticated(
        service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("new correct horse battery staple"),
                remember_me: false,
                device: DeviceContext::default(),
                trusted_device_token: None,
            })
            .await?,
    )?;
    assert_eq!(
        password_only.session.authentication_method,
        AuthenticationMethod::Password
    );
    Ok(())
}

pub(crate) async fn exercise_vault_rewrap(store: Arc<dyn AuthStore>) -> Result<(), AuthError> {
    let instant = Utc
        .with_ymd_and_hms(2026, 7, 28, 15, 0, 0)
        .single()
        .ok_or_else(AuthError::storage_unavailable)?;
    let clock = Arc::new(ManualClock::new(instant));
    let old_service = service_with_vault(
        Arc::clone(&store),
        Arc::clone(&clock),
        rotating_vault("old-v1", &[("old-v1", 0x11)])?,
    )?;
    let realm_id = RealmId::new();
    let initial = register_verify_login(&old_service, realm_id).await?;
    let access_token = SecretString::new(initial.tokens.access_token.expose_secret());
    let enrollment = old_service
        .begin_totp_enrollment(BeginTotpEnrollmentRequest {
            realm_id,
            access_token: SecretString::new(access_token.expose_secret()),
            password: SecretString::new("correct horse battery staple"),
            issuer: "SDK Auth Rewrap".to_owned(),
        })
        .await?;
    let code = test_totp(
        enrollment.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    old_service
        .confirm_totp_enrollment(ConfirmTotpEnrollmentRequest {
            realm_id,
            access_token,
            enrollment_id: enrollment.id,
            code: SecretString::new(code),
            trust_current_device: false,
        })
        .await?;
    drop(old_service);

    let rotated_service = service_with_vault(
        store,
        Arc::clone(&clock),
        rotating_vault("new-v2", &[("old-v1", 0x11), ("new-v2", 0x22)])?,
    )?;
    assert_eq!(rotated_service.rewrap_mfa_secrets(realm_id, 10).await?, 1);
    assert_eq!(rotated_service.rewrap_mfa_secrets(realm_id, 10).await?, 0);
    clock.advance(Duration::seconds(30))?;
    let challenge = second_factor(
        rotated_service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("correct horse battery staple"),
                remember_me: false,
                device: DeviceContext::default(),
                trusted_device_token: None,
            })
            .await?,
    )?;
    let code = test_totp(
        enrollment.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    let authentication = rotated_service
        .complete_login(CompleteLoginRequest {
            realm_id,
            challenge_token: SecretString::new(challenge.token.expose_secret()),
            proof: SecondFactorProof::Totp(SecretString::new(code)),
            trust_device: false,
        })
        .await?;
    assert_eq!(
        authentication.session.authentication_method,
        AuthenticationMethod::PasswordTotp
    );
    Ok(())
}

pub(crate) async fn exercise_mfa_management(store: Arc<dyn AuthStore>) -> Result<(), AuthError> {
    let instant = Utc
        .with_ymd_and_hms(2026, 7, 28, 18, 0, 0)
        .single()
        .ok_or_else(AuthError::storage_unavailable)?;
    let clock = Arc::new(ManualClock::new(instant));
    let service = service_with_clock(store, Arc::clone(&clock))?;
    let realm_id = RealmId::new();
    let initial = register_verify_login(&service, realm_id).await?;
    let initial_access = SecretString::new(initial.tokens.access_token.expose_secret());
    let initial_refresh = initial.tokens.refresh_token.expose_secret().to_owned();
    let enrollment = service
        .begin_totp_enrollment(BeginTotpEnrollmentRequest {
            realm_id,
            access_token: SecretString::new(initial_access.expose_secret()),
            password: SecretString::new("correct horse battery staple"),
            issuer: "SDK Auth Management".to_owned(),
        })
        .await?;
    let code = test_totp(
        enrollment.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    let activation = service
        .confirm_totp_enrollment(ConfirmTotpEnrollmentRequest {
            realm_id,
            access_token: SecretString::new(initial_access.expose_secret()),
            enrollment_id: enrollment.id,
            code: SecretString::new(code),
            trust_current_device: false,
        })
        .await?;
    let old_recovery = activation.recovery_codes[0].expose_secret().to_owned();

    let mut last_failure = None;
    for _ in 0..6 {
        last_failure = Some(
            service
                .begin_totp_replacement(BeginTotpReplacementRequest {
                    realm_id,
                    access_token: SecretString::new(initial_access.expose_secret()),
                    proof: MfaManagementProof {
                        password: SecretString::new("correct horse battery staple"),
                        second_factor: SecondFactorProof::Totp(SecretString::new("invalid")),
                    },
                    issuer: "SDK Auth Replacement".to_owned(),
                })
                .await,
        );
    }
    assert_eq!(
        last_failure.and_then(Result::err).map(|error| error.code()),
        Some(ErrorCode::RateLimited)
    );

    clock.advance(Duration::minutes(16))?;
    let refreshed = service
        .refresh(RefreshRequest {
            realm_id,
            refresh_token: SecretString::new(initial_refresh),
        })
        .await?;
    let refreshed_access = SecretString::new(refreshed.tokens.access_token.expose_secret());
    let current_code = test_totp(
        enrollment.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    let replacement = service
        .begin_totp_replacement(BeginTotpReplacementRequest {
            realm_id,
            access_token: SecretString::new(refreshed_access.expose_secret()),
            proof: MfaManagementProof {
                password: SecretString::new("correct horse battery staple"),
                second_factor: SecondFactorProof::Totp(SecretString::new(current_code)),
            },
            issuer: "SDK Auth Replacement".to_owned(),
        })
        .await?;
    let replacement_code = test_totp(
        replacement.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    service
        .confirm_totp_enrollment(ConfirmTotpEnrollmentRequest {
            realm_id,
            access_token: SecretString::new(refreshed_access.expose_secret()),
            enrollment_id: replacement.id,
            code: SecretString::new(replacement_code),
            trust_current_device: false,
        })
        .await?;

    clock.advance(Duration::seconds(30))?;
    let management_code = test_totp(
        replacement.base32_secret.expose_secret(),
        clock.now().timestamp(),
    )?;
    let new_recovery_codes = service
        .regenerate_recovery_codes(ManageMfaRequest {
            realm_id,
            access_token: SecretString::new(refreshed_access.expose_secret()),
            proof: MfaManagementProof {
                password: SecretString::new("correct horse battery staple"),
                second_factor: SecondFactorProof::Totp(SecretString::new(management_code)),
            },
        })
        .await?;
    assert_eq!(new_recovery_codes.len(), 10);

    let old_code_challenge = second_factor(
        service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("correct horse battery staple"),
                remember_me: false,
                device: DeviceContext::default(),
                trusted_device_token: None,
            })
            .await?,
    )?;
    let old_code_result = service
        .complete_login(CompleteLoginRequest {
            realm_id,
            challenge_token: SecretString::new(old_code_challenge.token.expose_secret()),
            proof: SecondFactorProof::RecoveryCode(SecretString::new(old_recovery)),
            trust_device: false,
        })
        .await;
    assert_eq!(
        old_code_result.err().map(|error| error.code()),
        Some(ErrorCode::SecondFactorInvalid)
    );

    let recovery_challenge = second_factor(
        service
            .login(LoginRequest {
                realm_id,
                email: "user@example.com".to_owned(),
                password: SecretString::new("correct horse battery staple"),
                remember_me: false,
                device: DeviceContext::default(),
                trusted_device_token: None,
            })
            .await?,
    )?;
    let trusted_authentication = service
        .complete_login(CompleteLoginRequest {
            realm_id,
            challenge_token: SecretString::new(recovery_challenge.token.expose_secret()),
            proof: SecondFactorProof::RecoveryCode(SecretString::new(
                new_recovery_codes[0].expose_secret(),
            )),
            trust_device: true,
        })
        .await?;
    let trusted_device_id = trusted_authentication
        .trusted_device_grant
        .as_ref()
        .ok_or_else(AuthError::storage_unavailable)?
        .device
        .id;
    let trusted_access =
        SecretString::new(trusted_authentication.tokens.access_token.expose_secret());
    assert!(
        service
            .revoke_trusted_device(RevokeTrustedDeviceRequest {
                realm_id,
                access_token: SecretString::new(trusted_access.expose_secret()),
                trusted_device_id,
            })
            .await?
    );
    assert!(
        service
            .revoke_trusted_device(RevokeTrustedDeviceRequest {
                realm_id,
                access_token: trusted_access,
                trusted_device_id,
            })
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn memory_adapter_satisfies_auth_contract() -> Result<(), AuthError> {
    exercise_contract(service(Arc::new(MemoryAuthStore::new()))?).await
}

#[tokio::test]
async fn sqlite_adapter_satisfies_auth_contract() -> Result<(), AuthError> {
    exercise_contract(service(Arc::new(SqliteAuthStore::in_memory()?))?).await
}

#[tokio::test]
async fn memory_adapter_satisfies_mfa_contract() -> Result<(), AuthError> {
    exercise_mfa_contract(Arc::new(MemoryAuthStore::new())).await
}

#[tokio::test]
async fn sqlite_adapter_satisfies_mfa_contract() -> Result<(), AuthError> {
    exercise_mfa_contract(Arc::new(SqliteAuthStore::in_memory()?)).await
}

#[tokio::test]
async fn memory_adapter_rewraps_mfa_vault_keys() -> Result<(), AuthError> {
    exercise_vault_rewrap(Arc::new(MemoryAuthStore::new())).await
}

#[tokio::test]
async fn sqlite_adapter_rewraps_mfa_vault_keys() -> Result<(), AuthError> {
    exercise_vault_rewrap(Arc::new(SqliteAuthStore::in_memory()?)).await
}

#[tokio::test]
async fn memory_adapter_satisfies_mfa_management_contract() -> Result<(), AuthError> {
    exercise_mfa_management(Arc::new(MemoryAuthStore::new())).await
}

#[tokio::test]
async fn sqlite_adapter_satisfies_mfa_management_contract() -> Result<(), AuthError> {
    exercise_mfa_management(Arc::new(SqliteAuthStore::in_memory()?)).await
}

#[tokio::test]
async fn sqlite_state_survives_store_reopen() -> Result<(), AuthError> {
    let directory = tempfile::tempdir().map_err(|_| AuthError::storage_unavailable())?;
    let database = directory.path().join("auth.db");
    let realm_id = RealmId::new();

    SqliteMigrator::migrate(&database)?;
    let first = service(Arc::new(SqliteAuthStore::open(&database)?))?;
    let authentication = register_verify_login(&first, realm_id).await?;
    let user_id = authentication.user.id;
    let access_token = authentication
        .tokens
        .access_token
        .expose_secret()
        .to_owned();
    drop(authentication);
    drop(first);

    let reopened = service(Arc::new(SqliteAuthStore::open(&database)?))?;
    let validated = reopened
        .validate_access(realm_id, &SecretString::new(access_token))
        .await?;
    assert_eq!(validated.user.id, user_id);
    Ok(())
}

#[tokio::test]
async fn realms_are_strictly_isolated() -> Result<(), AuthError> {
    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let owner_realm = RealmId::new();
    let other_realm = RealmId::new();
    let authentication = register_verify_login(&service, owner_realm).await?;
    let result = service
        .validate_access(
            other_realm,
            &SecretString::new(authentication.tokens.access_token.expose_secret()),
        )
        .await;
    assert_eq!(
        result.err().map(|error| error.code()),
        Some(ErrorCode::TokenInvalid)
    );
    Ok(())
}

#[tokio::test]
async fn password_reset_revokes_sessions_and_is_single_use() -> Result<(), AuthError> {
    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let realm_id = RealmId::new();
    let authentication = register_verify_login(&service, realm_id).await?;
    let old_access = authentication
        .tokens
        .access_token
        .expose_secret()
        .to_owned();
    let dispatch = service
        .request_password_reset(realm_id, "user@example.com".to_owned())
        .await?
        .ok_or_else(AuthError::storage_unavailable)?;
    let reset_token = dispatch.token.expose_secret().to_owned();
    service
        .reset_password(ResetPasswordRequest {
            realm_id,
            reset_token: SecretString::new(reset_token.clone()),
            new_password: SecretString::new("a different secure passphrase"),
        })
        .await?;
    let old_session = service
        .validate_access(realm_id, &SecretString::new(old_access))
        .await;
    assert_eq!(
        old_session.err().map(|error| error.code()),
        Some(ErrorCode::TokenInvalid)
    );
    let replay = service
        .reset_password(ResetPasswordRequest {
            realm_id,
            reset_token: SecretString::new(reset_token),
            new_password: SecretString::new("another different passphrase"),
        })
        .await;
    assert_eq!(
        replay.err().map(|error| error.code()),
        Some(ErrorCode::TokenReused)
    );
    let login = service
        .login(LoginRequest {
            realm_id,
            email: "user@example.com".to_owned(),
            password: SecretString::new("a different secure passphrase"),
            remember_me: false,
            trusted_device_token: None,
            device: DeviceContext::default(),
        })
        .await?;
    let login = authenticated(login)?;
    assert_eq!(login.user.id, authentication.user.id);
    Ok(())
}

#[tokio::test]
async fn concurrent_refresh_allows_one_rotation_then_revokes_family() -> Result<(), AuthError> {
    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let realm_id = RealmId::new();
    let authentication = register_verify_login(&service, realm_id).await?;
    let refresh = authentication
        .tokens
        .refresh_token
        .expose_secret()
        .to_owned();
    let left_service = Arc::clone(&service);
    let right_service = Arc::clone(&service);
    let left_token = refresh.clone();
    let left = async move {
        left_service
            .refresh(RefreshRequest {
                realm_id,
                refresh_token: SecretString::new(left_token),
            })
            .await
    };
    let right = async move {
        right_service
            .refresh(RefreshRequest {
                realm_id,
                refresh_token: SecretString::new(refresh),
            })
            .await
    };
    let (left_result, right_result) = tokio::join!(left, right);
    let successes = usize::from(left_result.is_ok()) + usize::from(right_result.is_ok());
    let reuses = usize::from(
        left_result
            .as_ref()
            .err()
            .is_some_and(|error| error.code() == ErrorCode::TokenReused),
    ) + usize::from(
        right_result
            .as_ref()
            .err()
            .is_some_and(|error| error.code() == ErrorCode::TokenReused),
    );
    assert_eq!(successes, 1);
    assert_eq!(reuses, 1);
    Ok(())
}

#[tokio::test]
async fn duplicate_identity_and_event_secrets_are_handled_safely() -> Result<(), AuthError> {
    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let realm_id = RealmId::new();
    let registration = service
        .register(RegisterRequest {
            realm_id,
            email: "user@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
        })
        .await?;
    let duplicate = service
        .register(RegisterRequest {
            realm_id,
            email: "USER@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
        })
        .await;
    assert_eq!(
        duplicate.err().map(|error| error.code()),
        Some(ErrorCode::Conflict)
    );
    let events = service.pending_events(10).await?;
    assert_eq!(events.len(), 1);
    assert!(
        !events[0]
            .payload
            .contains(registration.verification.token.expose_secret())
    );
    assert!(service.acknowledge_event(events[0].id).await?);
    assert!(service.pending_events(10).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn login_rate_limit_blocks_repeated_unknown_credentials() -> Result<(), AuthError> {
    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let realm_id = RealmId::new();
    let mut last = None;
    for _ in 0..6 {
        last = Some(
            service
                .login(LoginRequest {
                    realm_id,
                    email: "unknown@example.com".to_owned(),
                    password: SecretString::new("an incorrect password"),
                    remember_me: false,
                    trusted_device_token: None,
                    device: DeviceContext {
                        name: None,
                        network_hash: Some("network:limited".to_owned()),
                        user_agent: None,
                    },
                })
                .await,
        );
    }
    let code = last
        .and_then(Result::err)
        .map(|error| error.code())
        .ok_or_else(AuthError::storage_unavailable)?;
    assert_eq!(code, ErrorCode::RateLimited);
    Ok(())
}

#[tokio::test]
async fn email_verification_lifecycle_is_single_use_and_non_enumerating() -> Result<(), AuthError> {
    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let realm_id = RealmId::new();
    let registration = service
        .register(RegisterRequest {
            realm_id,
            email: "verify@example.com".to_owned(),
            password: SecretString::new("a sufficiently long passphrase"),
        })
        .await?;
    let unverified_login = service
        .login(LoginRequest {
            realm_id,
            email: "verify@example.com".to_owned(),
            password: SecretString::new("a sufficiently long passphrase"),
            remember_me: false,
            trusted_device_token: None,
            device: DeviceContext::default(),
        })
        .await;
    assert_eq!(
        unverified_login.err().map(|error| error.code()),
        Some(ErrorCode::AccountUnverified)
    );
    assert!(
        service
            .request_email_verification(realm_id, "missing@example.com".to_owned())
            .await?
            .is_none()
    );
    let replacement = service
        .request_email_verification(realm_id, "verify@example.com".to_owned())
        .await?
        .ok_or_else(AuthError::storage_unavailable)?;
    let initial = service
        .verify_email(
            realm_id,
            &SecretString::new(registration.verification.token.expose_secret()),
        )
        .await;
    assert_eq!(
        initial.err().map(|error| error.code()),
        Some(ErrorCode::TokenInvalid)
    );
    let replacement_text = replacement.token.expose_secret().to_owned();
    service
        .verify_email(realm_id, &SecretString::new(replacement_text.clone()))
        .await?;
    let replay = service
        .verify_email(realm_id, &SecretString::new(replacement_text))
        .await;
    assert_eq!(
        replay.err().map(|error| error.code()),
        Some(ErrorCode::TokenReused)
    );
    assert!(
        service
            .request_email_verification(realm_id, "verify@example.com".to_owned())
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn session_management_revokes_only_owned_sessions() -> Result<(), AuthError> {
    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let realm_id = RealmId::new();
    let first = register_verify_login(&service, realm_id).await?;
    let second = service
        .login(LoginRequest {
            realm_id,
            email: "user@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
            remember_me: true,
            trusted_device_token: None,
            device: DeviceContext::default(),
        })
        .await?;
    let second = authenticated(second)?;
    let first_access = SecretString::new(first.tokens.access_token.expose_secret());
    assert!(
        !service
            .revoke_session(realm_id, &first_access, sdk_auth_types::SessionId::new())
            .await?
    );
    assert!(
        service
            .revoke_session(realm_id, &first_access, second.session.id)
            .await?
    );
    assert_eq!(
        service.revoke_all_sessions(realm_id, &first_access).await?,
        1
    );
    assert!(
        service
            .validate_access(realm_id, &first_access)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn logout_revokes_current_session() -> Result<(), AuthError> {
    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let realm_id = RealmId::new();
    let authentication = register_verify_login(&service, realm_id).await?;
    let token = SecretString::new(authentication.tokens.access_token.expose_secret());
    service.logout(realm_id, &token).await?;
    assert_eq!(
        service
            .validate_access(realm_id, &token)
            .await
            .err()
            .map(|error| error.code()),
        Some(ErrorCode::TokenInvalid)
    );
    Ok(())
}

#[tokio::test]
async fn expiration_paths_reject_old_access_and_challenges() -> Result<(), AuthError> {
    let instant = Utc
        .with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
        .single()
        .ok_or_else(AuthError::storage_unavailable)?;
    let clock = Arc::new(ManualClock::new(instant));
    let service = service_with_clock(Arc::new(MemoryAuthStore::new()), Arc::clone(&clock))?;
    let realm_id = RealmId::new();
    let registration = service
        .register(RegisterRequest {
            realm_id,
            email: "expired@example.com".to_owned(),
            password: SecretString::new("a sufficiently long passphrase"),
        })
        .await?;
    clock.advance(Duration::hours(25))?;
    let expired = service
        .verify_email(
            realm_id,
            &SecretString::new(registration.verification.token.expose_secret()),
        )
        .await;
    assert_eq!(
        expired.err().map(|error| error.code()),
        Some(ErrorCode::TokenExpired)
    );
    Ok(())
}

#[tokio::test]
async fn access_expiry_still_allows_active_refresh() -> Result<(), AuthError> {
    let instant = Utc
        .with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
        .single()
        .ok_or_else(AuthError::storage_unavailable)?;
    let clock = Arc::new(ManualClock::new(instant));
    let service = service_with_clock(Arc::new(MemoryAuthStore::new()), Arc::clone(&clock))?;
    let realm_id = RealmId::new();
    let authentication = register_verify_login(&service, realm_id).await?;
    let access = SecretString::new(authentication.tokens.access_token.expose_secret());
    let refresh = authentication
        .tokens
        .refresh_token
        .expose_secret()
        .to_owned();
    clock.advance(Duration::minutes(11))?;
    assert!(service.validate_access(realm_id, &access).await.is_err());
    assert!(
        service
            .refresh(RefreshRequest {
                realm_id,
                refresh_token: SecretString::new(refresh),
            })
            .await
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn invalid_input_and_builder_guards_are_enforced() -> Result<(), AuthError> {
    assert_eq!(
        AuthService::builder()
            .build()
            .err()
            .map(|error| error.code()),
        Some(ErrorCode::Misconfigured)
    );
    let invalid_config = AuthConfig {
        access_token_ttl: Duration::days(8),
        ..AuthConfig::default()
    };
    assert!(invalid_config.validate().is_err());

    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let realm_id = RealmId::new();
    let weak = service
        .register(RegisterRequest {
            realm_id,
            email: "weak@example.com".to_owned(),
            password: SecretString::new("short"),
        })
        .await;
    assert_eq!(
        weak.err().map(|error| error.code()),
        Some(ErrorCode::InvalidInput)
    );
    assert_eq!(
        service
            .validate_access(realm_id, &SecretString::new(""))
            .await
            .err()
            .map(|error| error.code()),
        Some(ErrorCode::TokenInvalid)
    );
    assert!(service.pending_events(0).await.is_err());
    assert!(service.pending_events(1_001).await.is_err());
    assert!(
        service
            .request_password_reset(realm_id, "missing@example.com".to_owned())
            .await?
            .is_none()
    );
    assert_eq!(
        service
            .refresh(RefreshRequest {
                realm_id,
                refresh_token: SecretString::new(""),
            })
            .await
            .err()
            .map(|error| error.code()),
        Some(ErrorCode::TokenInvalid)
    );
    assert_eq!(
        service
            .refresh(RefreshRequest {
                realm_id,
                refresh_token: SecretString::new("unknown-token"),
            })
            .await
            .err()
            .map(|error| error.code()),
        Some(ErrorCode::TokenInvalid)
    );
    Ok(())
}

#[tokio::test]
async fn wrong_and_unknown_accounts_share_public_error() -> Result<(), AuthError> {
    let service = service(Arc::new(MemoryAuthStore::new()))?;
    let realm_id = RealmId::new();
    let registration = service
        .register(RegisterRequest {
            realm_id,
            email: "known@example.com".to_owned(),
            password: SecretString::new("a sufficiently long passphrase"),
        })
        .await?;
    service
        .verify_email(
            realm_id,
            &SecretString::new(registration.verification.token.expose_secret()),
        )
        .await?;
    let wrong = service
        .login(LoginRequest {
            realm_id,
            email: "known@example.com".to_owned(),
            password: SecretString::new("an incorrect password"),
            remember_me: false,
            trusted_device_token: None,
            device: DeviceContext::default(),
        })
        .await;
    let unknown = service
        .login(LoginRequest {
            realm_id,
            email: "unknown@example.com".to_owned(),
            password: SecretString::new("an incorrect password"),
            remember_me: false,
            trusted_device_token: None,
            device: DeviceContext::default(),
        })
        .await;
    assert_eq!(
        wrong.err().map(|error| error.code()),
        unknown.err().map(|error| error.code())
    );
    Ok(())
}
