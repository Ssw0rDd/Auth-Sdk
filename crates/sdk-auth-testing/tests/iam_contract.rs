//! Cross-adapter IAM, API-key and authorization contract.

use std::sync::Arc;

use chrono::{Duration, TimeZone as _, Utc};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sdk_auth_authorization::{PermissionDefinition, PermissionKey, PrincipalId, Role, RoleKey};
use sdk_auth_core::{
    AuthConfig, AuthorizationCredential, AuthorizeRequest, BeginTotpEnrollmentRequest,
    BootstrapIam, ClaimEventsRequest, Clock, ConfirmTotpEnrollmentRequest, IamAdminProof,
    LoginOutcome, LoginRequest, MfaManagementProof, RegisterRequest, SdkAuth, SdkStore,
    SecondFactorProof,
};
use sdk_auth_crypto::{Argon2PasswordEngine, OsTokenGenerator, VaultKey, XChaCha20Vault};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_memory::MemoryAuthStore;
use sdk_auth_sqlite::SqliteAuthStore;
use sdk_auth_testing::ManualClock;
use sdk_auth_types::{
    AuthEvent, AuthEventKind, DeviceContext, EventId, PermissionId, RealmId, RoleId, SecretBytes,
    SecretString,
};
use sha1::Sha1;

struct AdminFixture {
    realm_id: RealmId,
    user_id: sdk_auth_types::UserId,
    access_token: String,
    totp_seed: String,
    clock: Arc<ManualClock>,
}

impl AdminFixture {
    fn proof(&self) -> Result<IamAdminProof, AuthError> {
        self.clock.advance(Duration::seconds(30))?;
        let code = test_totp(&self.totp_seed, self.clock.now().timestamp())?;
        Ok(IamAdminProof::new(
            self.realm_id,
            SecretString::new(&self.access_token),
            MfaManagementProof {
                password: SecretString::new("correct horse battery staple"),
                second_factor: SecondFactorProof::Totp(SecretString::new(code)),
            },
        ))
    }
}

fn sdk<T>(store: Arc<T>, clock: Arc<ManualClock>) -> Result<SdkAuth, AuthError>
where
    T: SdkStore + 'static,
{
    let auth_config = AuthConfig {
        access_token_ttl: Duration::hours(4),
        ..AuthConfig::default()
    };
    SdkAuth::builder()
        .store(store)
        .password_engine(Arc::new(Argon2PasswordEngine::recommended()?))
        .token_generator(Arc::new(OsTokenGenerator))
        .secret_vault(Arc::new(XChaCha20Vault::new(
            "test-v1",
            vec![VaultKey::new("test-v1", SecretBytes::new(vec![0xA5; 32]))?],
        )?))
        .clock(clock)
        .auth_config(auth_config)
        .build()
}

async fn enrolled_admin(sdk: &SdkAuth, clock: Arc<ManualClock>) -> Result<AdminFixture, AuthError> {
    let realm_id = RealmId::new();
    let registration = sdk
        .identity()
        .register(RegisterRequest {
            realm_id,
            email: "owner@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
        })
        .await?;
    sdk.identity()
        .verify_email(
            realm_id,
            &SecretString::new(registration.verification.token.expose_secret()),
        )
        .await?;
    let login = sdk
        .authentication()
        .login(LoginRequest {
            realm_id,
            email: "owner@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
            remember_me: false,
            device: DeviceContext::default(),
            trusted_device_token: None,
        })
        .await?;
    let authentication = match login {
        LoginOutcome::Authenticated(value) => *value,
        LoginOutcome::SecondFactorRequired(_) => return Err(AuthError::storage_unavailable()),
        _ => return Err(AuthError::storage_unavailable()),
    };
    let access_token = authentication
        .tokens
        .access_token
        .expose_secret()
        .to_owned();
    let enrollment = sdk
        .mfa()
        .begin_totp_enrollment(BeginTotpEnrollmentRequest {
            realm_id,
            access_token: SecretString::new(&access_token),
            password: SecretString::new("correct horse battery staple"),
            issuer: "SDK Auth Contract".to_owned(),
        })
        .await?;
    let totp_seed = enrollment.base32_secret.expose_secret().to_owned();
    let code = test_totp(&totp_seed, clock.now().timestamp())?;
    sdk.mfa()
        .confirm_totp_enrollment(ConfirmTotpEnrollmentRequest {
            realm_id,
            access_token: SecretString::new(&access_token),
            enrollment_id: enrollment.id,
            code: SecretString::new(code),
            trust_current_device: false,
        })
        .await?;
    Ok(AdminFixture {
        realm_id,
        user_id: authentication.user.id,
        access_token,
        totp_seed,
        clock,
    })
}

pub(crate) async fn exercise<T>(store: Arc<T>) -> Result<(), AuthError>
where
    T: SdkStore + 'static,
{
    let instant = Utc
        .with_ymd_and_hms(2026, 7, 29, 12, 0, 0)
        .single()
        .ok_or_else(AuthError::storage_unavailable)?;
    let clock = Arc::new(ManualClock::new(instant));
    let audit_store = Arc::clone(&store);
    let sdk = sdk(store, Arc::clone(&clock))?;
    let admin = enrolled_admin(&sdk, Arc::clone(&clock)).await?;

    let before_bootstrap = sdk
        .authorization()
        .authorize(AuthorizeRequest::new(
            admin.realm_id,
            AuthorizationCredential::UserAccessToken(SecretString::new(&admin.access_token)),
            PermissionKey::parse("iam.roles:manage")?,
        ))
        .await;
    assert_eq!(
        before_bootstrap.err().map(|error| error.code()),
        Some(ErrorCode::RealmNotInitialized)
    );

    sdk.iam().bootstrap_realm(admin.proof()?).await?;
    let duplicate = sdk.iam().bootstrap_realm(admin.proof()?).await;
    assert_eq!(
        duplicate.err().map(|error| error.code()),
        Some(ErrorCode::Conflict)
    );

    let application_permission = sdk
        .iam()
        .register_permission(
            admin.proof()?,
            PermissionKey::parse("documents:read")?,
            "Read documents",
        )
        .await?;
    let role = sdk
        .iam()
        .create_role(
            admin.proof()?,
            RoleKey::parse("document_reader")?,
            "Document reader",
            "Read-only access",
        )
        .await?;
    assert!(
        sdk.iam()
            .set_role_permission(admin.proof()?, role.id(), application_permission.id(), true)
            .await?
    );

    let service_account = sdk
        .iam()
        .create_service_account(
            admin.proof()?,
            "reporting-worker",
            "Reads documents for reports",
        )
        .await?;
    assert!(
        sdk.iam()
            .set_principal_role(
                admin.proof()?,
                PrincipalId::ServiceAccount(service_account.id()),
                role.id(),
                true,
            )
            .await?
    );

    let issued = sdk
        .iam()
        .create_api_key(
            admin.proof()?,
            PrincipalId::ServiceAccount(service_account.id()),
            "worker-primary",
            vec![PermissionKey::parse("documents:read")?],
            None,
        )
        .await?;
    let raw_key = issued.credential.expose_secret().to_owned();
    assert!(!format!("{issued:?}").contains(&raw_key));

    let grant = sdk
        .authorization()
        .authorize(AuthorizeRequest::new(
            admin.realm_id,
            AuthorizationCredential::ApiKey(SecretString::new(&raw_key)),
            PermissionKey::parse("documents:read")?,
        ))
        .await?;
    assert_eq!(
        grant.principal(),
        PrincipalId::ServiceAccount(service_account.id())
    );

    let over_scope = sdk
        .iam()
        .create_api_key(
            admin.proof()?,
            PrincipalId::ServiceAccount(service_account.id()),
            "over-scoped",
            vec![PermissionKey::parse("documents:write")?],
            None,
        )
        .await;
    assert_eq!(
        over_scope.err().map(|error| error.code()),
        Some(ErrorCode::PermissionDenied)
    );

    let rotated = sdk
        .iam()
        .rotate_api_key(admin.proof()?, issued.key.id(), Duration::hours(1), None)
        .await?;
    let rotated_raw = rotated.credential.expose_secret().to_owned();
    sdk.authorization()
        .authorize(AuthorizeRequest::new(
            admin.realm_id,
            AuthorizationCredential::ApiKey(SecretString::new(&raw_key)),
            PermissionKey::parse("documents:read")?,
        ))
        .await?;
    clock.advance(Duration::hours(1) + Duration::seconds(1))?;
    assert!(
        sdk.authorization()
            .authorize(AuthorizeRequest::new(
                admin.realm_id,
                AuthorizationCredential::ApiKey(SecretString::new(&raw_key)),
                PermissionKey::parse("documents:read")?,
            ))
            .await
            .is_err()
    );
    sdk.authorization()
        .authorize(AuthorizeRequest::new(
            admin.realm_id,
            AuthorizationCredential::ApiKey(SecretString::new(&rotated_raw)),
            PermissionKey::parse("documents:read")?,
        ))
        .await?;

    let cross_realm = sdk
        .authorization()
        .authorize(AuthorizeRequest::new(
            RealmId::new(),
            AuthorizationCredential::ApiKey(SecretString::new(&rotated_raw)),
            PermissionKey::parse("documents:read")?,
        ))
        .await;
    assert_eq!(
        cross_realm.err().map(|error| error.code()),
        Some(ErrorCode::RealmNotInitialized)
    );

    assert!(
        sdk.iam()
            .set_principal_role(
                admin.proof()?,
                PrincipalId::ServiceAccount(service_account.id()),
                role.id(),
                false,
            )
            .await?
    );
    assert_eq!(
        sdk.authorization()
            .authorize(AuthorizeRequest::new(
                admin.realm_id,
                AuthorizationCredential::ApiKey(SecretString::new(&rotated_raw)),
                PermissionKey::parse("documents:read")?,
            ))
            .await
            .err()
            .map(|error| error.code()),
        Some(ErrorCode::PermissionDenied)
    );
    assert!(
        sdk.iam()
            .set_principal_role(
                admin.proof()?,
                PrincipalId::ServiceAccount(service_account.id()),
                role.id(),
                true,
            )
            .await?
    );
    assert!(
        sdk.iam()
            .set_service_account_enabled(admin.proof()?, service_account.id(), false)
            .await?
    );
    assert!(
        sdk.authorization()
            .authorize(AuthorizeRequest::new(
                admin.realm_id,
                AuthorizationCredential::ApiKey(SecretString::new(&rotated_raw)),
                PermissionKey::parse("documents:read")?,
            ))
            .await
            .is_err()
    );
    assert!(
        sdk.iam()
            .set_service_account_enabled(admin.proof()?, service_account.id(), true)
            .await?
    );
    assert!(
        sdk.iam()
            .revoke_api_key(admin.proof()?, rotated.key.id())
            .await?
    );
    assert!(
        sdk.authorization()
            .authorize(AuthorizeRequest::new(
                admin.realm_id,
                AuthorizationCredential::ApiKey(SecretString::new(&rotated_raw)),
                PermissionKey::parse("documents:read")?,
            ))
            .await
            .is_err()
    );

    let owner_role = sdk
        .iam()
        .list_roles(admin.proof()?)
        .await?
        .into_iter()
        .find(Role::reserved)
        .ok_or_else(AuthError::storage_unavailable)?;
    let last_owner = sdk
        .iam()
        .set_principal_role(
            admin.proof()?,
            PrincipalId::User(admin.user_id),
            owner_role.id(),
            false,
        )
        .await;
    assert_eq!(
        last_owner.err().map(|error| error.code()),
        Some(ErrorCode::Conflict)
    );

    assert_eq!(sdk.iam().list_permissions(admin.proof()?).await?.len(), 8);
    assert_eq!(sdk.iam().list_roles(admin.proof()?).await?.len(), 2);
    assert_eq!(
        sdk.iam().list_service_accounts(admin.proof()?).await?.len(),
        1
    );
    assert_eq!(
        sdk.iam()
            .list_api_keys(
                admin.proof()?,
                PrincipalId::ServiceAccount(service_account.id())
            )
            .await?
            .len(),
        2
    );
    assert!(
        sdk.outbox()
            .claim_events(ClaimEventsRequest {
                consumer_id: "iam-contract".to_owned(),
                limit: 100,
                lease_duration: Duration::seconds(60),
            })
            .await?
            .iter()
            .any(|claimed| claimed.event.kind == sdk_auth_types::AuthEventKind::IamApiKeyChanged)
    );
    let audit_records = sdk.audit().list_records(admin.proof()?, None, 100).await?;
    assert!(
        audit_records
            .iter()
            .any(|record| record.kind == sdk_auth_types::AuthEventKind::IamApiKeyChanged)
    );
    assert!(audit_records.iter().any(|record| record.kind
        == sdk_auth_types::AuthEventKind::LoginSucceeded
        && record.outbox_event_id.is_none()));
    assert!(audit_records.iter().any(|record| record.kind
        == sdk_auth_types::AuthEventKind::EmailVerified
        && record.outbox_event_id.is_none()));
    assert!(
        audit_records
            .iter()
            .filter(|record| record.kind == sdk_auth_types::AuthEventKind::IamApiKeyChanged)
            .all(|record| {
                record.outbox_event_id.map(|event_id| event_id.as_uuid())
                    == Some(record.id.as_uuid())
            })
    );
    sdk.sessions()
        .logout(admin.realm_id, &SecretString::new(&admin.access_token))
        .await?;
    let post_logout = audit_store
        .list_audit_records(admin.realm_id, None, 100)
        .await?;
    assert!(post_logout.iter().any(|record| {
        record.kind == sdk_auth_types::AuthEventKind::SessionRevoked
            && record.outbox_event_id.is_none()
    }));
    assert_ne!(admin.user_id, sdk_auth_types::UserId::new());
    Ok(())
}

#[tokio::test]
async fn memory_iam_contract() -> Result<(), AuthError> {
    exercise(Arc::new(MemoryAuthStore::new())).await
}

#[tokio::test]
async fn sqlite_iam_contract() -> Result<(), AuthError> {
    exercise(Arc::new(SqliteAuthStore::in_memory()?)).await
}

pub(crate) async fn bootstrap_race<T>(store: Arc<T>) -> Result<(), AuthError>
where
    T: SdkStore + 'static,
{
    let instant = Utc
        .with_ymd_and_hms(2026, 7, 29, 14, 0, 0)
        .single()
        .ok_or_else(AuthError::storage_unavailable)?;
    let realm_id = RealmId::new();
    let sdk = sdk(Arc::clone(&store), Arc::new(ManualClock::new(instant)))?;
    let registration = sdk
        .identity()
        .register(RegisterRequest {
            realm_id,
            email: "race@example.com".to_owned(),
            password: SecretString::new("correct horse battery staple"),
        })
        .await?;
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let candidate = Arc::clone(&store);
        let user_id = registration.user.id;
        tasks.push(tokio::spawn(async move {
            let permission = PermissionDefinition::from_parts(
                realm_id,
                PermissionId::new(),
                PermissionKey::parse("iam.roles:manage")?,
                "Manage roles",
                true,
                instant,
                instant,
            )?;
            let role = Role::from_parts(
                realm_id,
                RoleId::new(),
                RoleKey::parse("realm_owner")?,
                "Realm owner",
                "Reserved owner",
                true,
                true,
                instant,
                instant,
            )?;
            candidate
                .bootstrap_iam(BootstrapIam {
                    realm_id,
                    owner_user_id: user_id,
                    permissions: vec![permission],
                    owner_role: role,
                    event: AuthEvent {
                        id: EventId::new(),
                        realm_id,
                        user_id,
                        kind: AuthEventKind::IamRealmBootstrapped,
                        payload: "{}".to_owned(),
                        created_at: instant,
                    },
                })
                .await
        }));
    }
    let mut successes = 0;
    for task in tasks {
        if task
            .await
            .map_err(|_| AuthError::storage_unavailable())?
            .is_ok()
        {
            successes += 1;
        }
    }
    assert_eq!(successes, 1);
    Ok(())
}

#[tokio::test]
async fn memory_bootstrap_is_atomic_under_race() -> Result<(), AuthError> {
    bootstrap_race(Arc::new(MemoryAuthStore::new())).await
}

#[tokio::test]
async fn sqlite_bootstrap_is_atomic_under_race() -> Result<(), AuthError> {
    bootstrap_race(Arc::new(SqliteAuthStore::in_memory()?)).await
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
