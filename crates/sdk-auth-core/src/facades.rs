//! Capability-oriented public facades over authentication use cases.
//!
//! The facades keep callers from depending on the historical monolithic
//! service surface while all rules continue to execute in the same core.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sdk_auth_error::AuthError;
use sdk_auth_types::{
    AuditRecord, AuthEvent, EventId, OutboxClaimId, RealmId, SecretString, Session, SessionId,
    TrustedDevice,
};

use crate::{
    AccessValidation, AuditStore, AuthService, Authentication, BeginTotpEnrollmentRequest,
    BeginTotpReplacementRequest, ChallengeDispatch, ClaimEventsRequest, ClaimedEvent, Clock,
    CompleteLoginRequest, ConfirmTotpEnrollmentRequest, IamAdminProof, IamService,
    LeasedEventStore, LoginOutcome, LoginRequest, ManageMfaRequest, RefreshRequest,
    RegisterRequest, Registration, ResetPasswordRequest, RevokeTrustedDeviceRequest,
    TotpActivation, TotpEnrollment,
};

macro_rules! facade {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        pub struct $name {
            service: Arc<AuthService>,
        }

        impl $name {
            pub(crate) fn new(service: Arc<AuthService>) -> Self {
                Self { service }
            }
        }
    };
}

facade!(
    IdentityService,
    "Identity lifecycle facade for registration and email ownership."
);
facade!(
    AuthenticationService,
    "Authentication facade for login, refresh and credential validation."
);
facade!(
    AuthenticatorService,
    "Authenticator lifecycle facade for MFA and trusted devices."
);
facade!(
    SessionService,
    "Session lifecycle facade for listing and revocation."
);
facade!(
    RecoveryService,
    "Account recovery facade for password-reset workflows."
);
/// Trusted-host facade for concurrent durable integration-event delivery.
pub struct OutboxService {
    store: Arc<dyn LeasedEventStore>,
    clock: Arc<dyn Clock>,
}

impl OutboxService {
    pub(crate) fn new(store: Arc<dyn LeasedEventStore>, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }
}
/// Append-only audit and durable outbox facade.
pub struct AuditService {
    audit_store: Arc<dyn AuditStore>,
    iam: IamService,
}

impl AuditService {
    pub(crate) fn new(audit_store: Arc<dyn AuditStore>, iam: IamService) -> Self {
        Self { audit_store, iam }
    }
}

impl IdentityService {
    /// Registers a unique identity and returns its email-verification dispatch.
    pub async fn register(&self, request: RegisterRequest) -> Result<Registration, AuthError> {
        self.service.register(request).await
    }

    /// Creates a new email-verification challenge without account enumeration.
    pub async fn request_email_verification(
        &self,
        realm_id: RealmId,
        email: String,
    ) -> Result<Option<ChallengeDispatch>, AuthError> {
        self.service
            .request_email_verification(realm_id, email)
            .await
    }

    /// Consumes a single-use email-verification token.
    pub async fn verify_email(
        &self,
        realm_id: RealmId,
        token: &SecretString,
    ) -> Result<(), AuthError> {
        self.service.verify_email(realm_id, token).await
    }
}

impl AuthenticationService {
    /// Verifies a primary credential and returns authentication or an MFA challenge.
    pub async fn login(&self, request: LoginRequest) -> Result<LoginOutcome, AuthError> {
        self.service.login(request).await
    }

    /// Completes a pending second-factor login.
    pub async fn complete_login(
        &self,
        request: CompleteLoginRequest,
    ) -> Result<Authentication, AuthError> {
        self.service.complete_login(request).await
    }

    /// Rotates a refresh token and returns a renewed authentication.
    pub async fn refresh(&self, request: RefreshRequest) -> Result<Authentication, AuthError> {
        self.service.refresh(request).await
    }

    /// Validates an access token and resolves the current session assurance.
    pub async fn validate_access(
        &self,
        realm_id: RealmId,
        token: &SecretString,
    ) -> Result<AccessValidation, AuthError> {
        self.service.validate_access(realm_id, token).await
    }
}

impl AuthenticatorService {
    /// Starts first-time TOTP enrollment after password reauthentication.
    pub async fn begin_totp_enrollment(
        &self,
        request: BeginTotpEnrollmentRequest,
    ) -> Result<TotpEnrollment, AuthError> {
        self.service.begin_totp_enrollment(request).await
    }

    /// Starts replacement of an active TOTP factor after step-up.
    pub async fn begin_totp_replacement(
        &self,
        request: BeginTotpReplacementRequest,
    ) -> Result<TotpEnrollment, AuthError> {
        self.service.begin_totp_replacement(request).await
    }

    /// Confirms and atomically activates a pending TOTP enrollment.
    pub async fn confirm_totp_enrollment(
        &self,
        request: ConfirmTotpEnrollmentRequest,
    ) -> Result<TotpActivation, AuthError> {
        self.service.confirm_totp_enrollment(request).await
    }

    /// Invalidates old recovery codes and returns a new one-time set.
    pub async fn regenerate_recovery_codes(
        &self,
        request: ManageMfaRequest,
    ) -> Result<Vec<SecretString>, AuthError> {
        self.service.regenerate_recovery_codes(request).await
    }

    /// Disables MFA after fresh management proof.
    pub async fn disable_mfa(&self, request: ManageMfaRequest) -> Result<(), AuthError> {
        self.service.disable_mfa(request).await
    }

    /// Lists trusted devices owned by the authenticated user.
    pub async fn list_trusted_devices(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
    ) -> Result<Vec<TrustedDevice>, AuthError> {
        self.service
            .list_trusted_devices(realm_id, access_token)
            .await
    }

    /// Revokes one trusted-device grant.
    pub async fn revoke_trusted_device(
        &self,
        request: RevokeTrustedDeviceRequest,
    ) -> Result<bool, AuthError> {
        self.service.revoke_trusted_device(request).await
    }

    /// Re-encrypts a bounded batch with the active vault key.
    pub async fn rewrap_mfa_secrets(
        &self,
        realm_id: RealmId,
        limit: u32,
    ) -> Result<u32, AuthError> {
        self.service.rewrap_mfa_secrets(realm_id, limit).await
    }
}

impl SessionService {
    /// Revokes the session associated with an access token.
    pub async fn logout(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
    ) -> Result<(), AuthError> {
        self.service.logout(realm_id, access_token).await
    }

    /// Lists sessions owned by the authenticated user.
    pub async fn list(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
    ) -> Result<Vec<Session>, AuthError> {
        self.service.list_sessions(realm_id, access_token).await
    }

    /// Revokes one session only when it belongs to the authenticated user.
    pub async fn revoke(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
        session_id: SessionId,
    ) -> Result<bool, AuthError> {
        self.service
            .revoke_session(realm_id, access_token, session_id)
            .await
    }

    /// Revokes all sessions owned by the authenticated user.
    pub async fn revoke_all(
        &self,
        realm_id: RealmId,
        access_token: &SecretString,
    ) -> Result<u64, AuthError> {
        self.service
            .revoke_all_sessions(realm_id, access_token)
            .await
    }
}

impl RecoveryService {
    /// Creates a password-reset challenge without account enumeration.
    pub async fn request_password_reset(
        &self,
        realm_id: RealmId,
        email: String,
    ) -> Result<Option<ChallengeDispatch>, AuthError> {
        self.service.request_password_reset(realm_id, email).await
    }

    /// Consumes a password-reset token and revokes authentication state.
    pub async fn reset_password(&self, request: ResetPasswordRequest) -> Result<(), AuthError> {
        self.service.reset_password(request).await
    }
}

impl AuditService {
    /// Lists append-only audit records after fresh administrative step-up.
    pub async fn list_records(
        &self,
        admin: IamAdminProof,
        before: Option<DateTime<Utc>>,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, AuthError> {
        if limit == 0 || limit > 1_000 {
            return Err(AuthError::invalid_input());
        }
        self.iam.authorize_audit_reader(&admin).await?;
        self.audit_store
            .list_audit_records(admin.realm_id(), before, limit)
            .await
    }
}

impl OutboxService {
    /// Returns pending secret-free outbox events for a single consumer.
    #[deprecated(
        since = "0.6.0",
        note = "use claim_events for safe concurrent delivery"
    )]
    pub async fn pending_events(&self, limit: u32) -> Result<Vec<AuthEvent>, AuthError> {
        validate_outbox_limit(limit)?;
        self.store.pending_events(limit).await
    }

    /// Acknowledges an unleased outbox event for a single consumer.
    #[deprecated(
        since = "0.6.0",
        note = "use acknowledge_claim for safe concurrent delivery"
    )]
    pub async fn acknowledge_event(&self, event_id: EventId) -> Result<bool, AuthError> {
        self.store
            .acknowledge_event(event_id, self.clock.now())
            .await
    }

    /// Atomically leases a bounded batch of events for one dispatcher.
    pub async fn claim_events(
        &self,
        request: ClaimEventsRequest,
    ) -> Result<Vec<ClaimedEvent>, AuthError> {
        validate_outbox_limit(request.limit)?;
        if request.consumer_id.trim().is_empty()
            || request.consumer_id.chars().count() > 128
            || request.lease_duration < chrono::Duration::seconds(5)
            || request.lease_duration > chrono::Duration::minutes(15)
        {
            return Err(AuthError::invalid_input());
        }
        let claim_id = OutboxClaimId::new();
        self.store
            .claim_events(request, claim_id, self.clock.now())
            .await
    }

    /// Acknowledges one event only while the supplied claim remains active.
    pub async fn acknowledge_claim(
        &self,
        event_id: EventId,
        claim_id: OutboxClaimId,
    ) -> Result<bool, AuthError> {
        self.store
            .acknowledge_claim(event_id, claim_id, self.clock.now())
            .await
    }

    /// Releases all undelivered events associated with one claim.
    pub async fn release_claim(&self, claim_id: OutboxClaimId) -> Result<u64, AuthError> {
        self.store.release_claim(claim_id).await
    }
}

fn validate_outbox_limit(limit: u32) -> Result<(), AuthError> {
    if limit == 0 || limit > 1_000 {
        return Err(AuthError::invalid_input());
    }
    Ok(())
}
