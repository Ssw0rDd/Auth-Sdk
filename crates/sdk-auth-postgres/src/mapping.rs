use sdk_auth_core::{ChallengeKind, StoredUser};
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_types::{
    AuditActor, AuditId, AuditOutcome, AuditRecord, AuthEvent, AuthEventKind, AuthenticationMethod,
    EmailAddress, EventId, RealmId, User, UserId,
};
use sqlx::{Error, PgConnection, Row as _, postgres::PgRow};
use uuid::Uuid;

pub(crate) fn storage(error: Error) -> AuthError {
    match error {
        Error::PoolTimedOut => AuthError::pool_exhausted(),
        Error::PoolClosed | Error::Io(_) | Error::Tls(_) => AuthError::dependency_unavailable(),
        _ => AuthError::storage_unavailable(),
    }
}

pub(crate) fn conflict() -> AuthError {
    AuthError::new(ErrorCode::Conflict, "resource already exists", false)
}

pub(crate) fn permission_denied() -> AuthError {
    AuthError::new(ErrorCode::PermissionDenied, "permission denied", false)
}

pub(crate) fn is_unique_violation(error: &Error) -> bool {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .is_some_and(|code| code == "23505")
}

pub(crate) fn stored_user(row: &PgRow, realm_id: RealmId) -> Result<StoredUser, AuthError> {
    let id: Uuid = row.try_get("id").map_err(storage)?;
    let email: String = row.try_get("email").map_err(storage)?;
    Ok(StoredUser {
        user: User {
            realm_id,
            id: UserId::from_uuid(id),
            email: EmailAddress::parse(email).map_err(|_| AuthError::storage_unavailable())?,
            email_verified: row.try_get("email_verified").map_err(storage)?,
            created_at: row.try_get("created_at").map_err(storage)?,
            updated_at: row.try_get("updated_at").map_err(storage)?,
        },
        password_hash: row.try_get("password_hash").map_err(storage)?,
    })
}

pub(crate) async fn insert_event(
    connection: &mut PgConnection,
    event: &AuthEvent,
) -> Result<(), AuthError> {
    let payload: serde_json::Value =
        serde_json::from_str(&event.payload).map_err(|_| AuthError::storage_unavailable())?;
    sqlx::query(
        "INSERT INTO outbox(id,realm_id,user_id,kind,payload,created_at) VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(event.id.as_uuid())
    .bind(event.realm_id.as_uuid())
    .bind(event.user_id.as_uuid())
    .bind(event_name(event.kind)?)
    .bind(payload)
    .bind(event.created_at)
    .execute(&mut *connection)
    .await
    .map_err(storage)?;
    let audit = AuditRecord::from_outbox_event(event);
    insert_audit(connection, &audit).await
}

pub(crate) async fn insert_audit(
    connection: &mut PgConnection,
    audit: &AuditRecord,
) -> Result<(), AuthError> {
    let (actor_kind, actor_user_id) = match audit.actor {
        AuditActor::System => ("system", None),
        AuditActor::User(user_id) => ("user", Some(user_id.as_uuid())),
        _ => return Err(AuthError::storage_unavailable()),
    };
    let metadata: serde_json::Value =
        serde_json::from_str(&audit.metadata_json).map_err(|_| AuthError::storage_unavailable())?;
    sqlx::query(
        "INSERT INTO audit_log(id,realm_id,actor_kind,actor_user_id,subject_user_id,kind,outcome,metadata,occurred_at,outbox_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(audit.id.as_uuid())
    .bind(audit.realm_id.as_uuid())
    .bind(actor_kind)
    .bind(actor_user_id)
    .bind(audit.subject_user_id.map(UserId::as_uuid))
    .bind(event_name(audit.kind)?)
    .bind(audit_outcome_name(audit.outcome)?)
    .bind(metadata)
    .bind(audit.occurred_at)
    .bind(audit.outbox_event_id.map(EventId::as_uuid))
    .execute(connection)
    .await
    .map(|_| ())
    .map_err(storage)
}

pub(crate) fn stored_event(row: &PgRow) -> Result<AuthEvent, AuthError> {
    let payload: serde_json::Value = row.try_get("payload").map_err(storage)?;
    Ok(AuthEvent {
        id: EventId::from_uuid(row.try_get("id").map_err(storage)?),
        realm_id: RealmId::from_uuid(row.try_get("realm_id").map_err(storage)?),
        user_id: UserId::from_uuid(row.try_get("user_id").map_err(storage)?),
        kind: parse_event_name(&row.try_get::<String, _>("kind").map_err(storage)?)?,
        payload: serde_json::to_string(&payload).map_err(|_| AuthError::storage_unavailable())?,
        created_at: row.try_get("created_at").map_err(storage)?,
    })
}

pub(crate) fn stored_audit(row: &PgRow) -> Result<AuditRecord, AuthError> {
    let actor_kind: String = row.try_get("actor_kind").map_err(storage)?;
    let actor_user_id: Option<Uuid> = row.try_get("actor_user_id").map_err(storage)?;
    let actor = match (actor_kind.as_str(), actor_user_id) {
        ("system", None) => AuditActor::System,
        ("user", Some(user_id)) => AuditActor::User(UserId::from_uuid(user_id)),
        _ => return Err(AuthError::storage_unavailable()),
    };
    let outcome = match row
        .try_get::<String, _>("outcome")
        .map_err(storage)?
        .as_str()
    {
        "succeeded" => AuditOutcome::Succeeded,
        "denied" => AuditOutcome::Denied,
        _ => return Err(AuthError::storage_unavailable()),
    };
    let metadata: serde_json::Value = row.try_get("metadata").map_err(storage)?;
    Ok(AuditRecord {
        id: AuditId::from_uuid(row.try_get("id").map_err(storage)?),
        realm_id: RealmId::from_uuid(row.try_get("realm_id").map_err(storage)?),
        actor,
        subject_user_id: row
            .try_get::<Option<Uuid>, _>("subject_user_id")
            .map_err(storage)?
            .map(UserId::from_uuid),
        kind: parse_event_name(&row.try_get::<String, _>("kind").map_err(storage)?)?,
        outcome,
        metadata_json: serde_json::to_string(&metadata)
            .map_err(|_| AuthError::storage_unavailable())?,
        occurred_at: row.try_get("occurred_at").map_err(storage)?,
        outbox_event_id: row
            .try_get::<Option<Uuid>, _>("outbox_event_id")
            .map_err(storage)?
            .map(EventId::from_uuid),
    })
}

pub(crate) const fn challenge_name(kind: ChallengeKind) -> &'static str {
    match kind {
        ChallengeKind::EmailVerification => "email_verification",
        ChallengeKind::PasswordReset => "password_reset",
    }
}

pub(crate) fn authentication_method_name(
    value: AuthenticationMethod,
) -> Result<&'static str, AuthError> {
    #[allow(unreachable_patterns)]
    Ok(match value {
        AuthenticationMethod::Password => "password",
        AuthenticationMethod::PasswordTotp => "password_totp",
        AuthenticationMethod::PasswordRecoveryCode => "password_recovery_code",
        AuthenticationMethod::PasswordTrustedDevice => "password_trusted_device",
        AuthenticationMethod::Passkey => "passkey",
        _ => return Err(AuthError::storage_unavailable()),
    })
}

pub(crate) fn parse_authentication_method(value: &str) -> Result<AuthenticationMethod, AuthError> {
    match value {
        "password" => Ok(AuthenticationMethod::Password),
        "password_totp" => Ok(AuthenticationMethod::PasswordTotp),
        "password_recovery_code" => Ok(AuthenticationMethod::PasswordRecoveryCode),
        "password_trusted_device" => Ok(AuthenticationMethod::PasswordTrustedDevice),
        "passkey" => Ok(AuthenticationMethod::Passkey),
        _ => Err(AuthError::storage_unavailable()),
    }
}

fn audit_outcome_name(outcome: AuditOutcome) -> Result<&'static str, AuthError> {
    match outcome {
        AuditOutcome::Succeeded => Ok("succeeded"),
        AuditOutcome::Denied => Ok("denied"),
        _ => Err(AuthError::storage_unavailable()),
    }
}

pub(crate) fn event_name(kind: AuthEventKind) -> Result<&'static str, AuthError> {
    Ok(match kind {
        AuthEventKind::LoginSucceeded => "login_succeeded",
        AuthEventKind::SessionRevoked => "session_revoked",
        AuthEventKind::SessionsRevoked => "sessions_revoked",
        AuthEventKind::EmailVerified => "email_verified",
        AuthEventKind::EmailVerificationRequested => "email_verification_requested",
        AuthEventKind::PasswordResetRequested => "password_reset_requested",
        AuthEventKind::RefreshTokenReuseDetected => "refresh_token_reuse_detected",
        AuthEventKind::PasswordChanged => "password_changed",
        AuthEventKind::MfaEnabled => "mfa_enabled",
        AuthEventKind::MfaReplaced => "mfa_replaced",
        AuthEventKind::MfaDisabled => "mfa_disabled",
        AuthEventKind::RecoveryCodesRegenerated => "recovery_codes_regenerated",
        AuthEventKind::RecoveryCodeUsed => "recovery_code_used",
        AuthEventKind::TrustedDeviceCreated => "trusted_device_created",
        AuthEventKind::TrustedDeviceRevoked => "trusted_device_revoked",
        AuthEventKind::TrustedDeviceReplayDetected => "trusted_device_replay_detected",
        AuthEventKind::PasskeyRegistered => "passkey_registered",
        AuthEventKind::PasskeyRenamed => "passkey_renamed",
        AuthEventKind::PasskeyRevoked => "passkey_revoked",
        AuthEventKind::PasskeyCloneSuspected => "passkey_clone_suspected",
        AuthEventKind::IamRealmBootstrapped => "iam_realm_bootstrapped",
        AuthEventKind::IamPermissionChanged => "iam_permission_changed",
        AuthEventKind::IamRoleChanged => "iam_role_changed",
        AuthEventKind::IamAssignmentChanged => "iam_assignment_changed",
        AuthEventKind::IamServiceAccountChanged => "iam_service_account_changed",
        AuthEventKind::IamApiKeyChanged => "iam_api_key_changed",
        _ => return Err(AuthError::storage_unavailable()),
    })
}

pub(crate) fn parse_event_name(value: &str) -> Result<AuthEventKind, AuthError> {
    match value {
        "login_succeeded" => Ok(AuthEventKind::LoginSucceeded),
        "session_revoked" => Ok(AuthEventKind::SessionRevoked),
        "sessions_revoked" => Ok(AuthEventKind::SessionsRevoked),
        "email_verified" => Ok(AuthEventKind::EmailVerified),
        "email_verification_requested" => Ok(AuthEventKind::EmailVerificationRequested),
        "password_reset_requested" => Ok(AuthEventKind::PasswordResetRequested),
        "refresh_token_reuse_detected" => Ok(AuthEventKind::RefreshTokenReuseDetected),
        "password_changed" => Ok(AuthEventKind::PasswordChanged),
        "mfa_enabled" => Ok(AuthEventKind::MfaEnabled),
        "mfa_replaced" => Ok(AuthEventKind::MfaReplaced),
        "mfa_disabled" => Ok(AuthEventKind::MfaDisabled),
        "recovery_codes_regenerated" => Ok(AuthEventKind::RecoveryCodesRegenerated),
        "recovery_code_used" => Ok(AuthEventKind::RecoveryCodeUsed),
        "trusted_device_created" => Ok(AuthEventKind::TrustedDeviceCreated),
        "trusted_device_revoked" => Ok(AuthEventKind::TrustedDeviceRevoked),
        "trusted_device_replay_detected" => Ok(AuthEventKind::TrustedDeviceReplayDetected),
        "passkey_registered" => Ok(AuthEventKind::PasskeyRegistered),
        "passkey_renamed" => Ok(AuthEventKind::PasskeyRenamed),
        "passkey_revoked" => Ok(AuthEventKind::PasskeyRevoked),
        "passkey_clone_suspected" => Ok(AuthEventKind::PasskeyCloneSuspected),
        "iam_realm_bootstrapped" => Ok(AuthEventKind::IamRealmBootstrapped),
        "iam_permission_changed" => Ok(AuthEventKind::IamPermissionChanged),
        "iam_role_changed" => Ok(AuthEventKind::IamRoleChanged),
        "iam_assignment_changed" => Ok(AuthEventKind::IamAssignmentChanged),
        "iam_service_account_changed" => Ok(AuthEventKind::IamServiceAccountChanged),
        "iam_api_key_changed" => Ok(AuthEventKind::IamApiKeyChanged),
        _ => Err(AuthError::storage_unavailable()),
    }
}
