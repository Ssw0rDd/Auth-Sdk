//! Runtime-agnostic authentication domain and application services.
//!
//! Hosts provide storage and cryptographic adapters. The core owns validation,
//! state transitions, token rotation, realm isolation, and security events.

mod config;
mod facades;
mod federation;
mod iam;
mod model;
mod ports;
mod sdk;
mod service;
mod webauthn;

pub use config::{AuthConfig, LoginAttemptPolicy};
pub use facades::{
    AuditService, AuthenticationService, AuthenticatorService, IdentityService, OutboxService,
    RecoveryService, SessionService,
};
pub use federation::{
    BeginFederatedLoginRequest, CompleteFederatedLink, CompleteFederatedLinkRequest,
    FederatedIdentity, FederatedIdentityKey, FederatedLinkDispatch, FederatedLinkProof,
    FederatedLinkResolution, FederatedLoginOutcome, FederatedRegistrationResolution,
    FederatedResolution, FederationConfig, FederationService, FederationStore,
    PendingFederatedLink, RegisterFederatedUser, VerifiedFederatedClaims,
};
pub use iam::{
    ApiKeyAuthentication, ApiKeyGrant, AuthorizationConfig, AuthorizationCredential,
    AuthorizationService, AuthorizeRequest, BootstrapIam, CreateApiKey, CreatePermission,
    CreateRole, CreateServiceAccount, IamAdminProof, IamService, IamStore, RotateApiKey,
    StoredApiKey,
};
pub use model::{
    AccessTokenRecord, AccessValidation, Authentication, BeginTotpEnrollmentRequest,
    BeginTotpReplacementRequest, ChallengeDispatch, ChallengeKind, CompleteLoginRequest,
    ConfirmTotpEnrollmentRequest, LoginOutcome, LoginRequest, ManageMfaRequest, MfaLoginChallenge,
    MfaManagementProof, RefreshRequest, RegisterRequest, Registration, ResetPasswordRequest,
    RevokeTrustedDeviceRequest, SecondFactorMethod, SecondFactorProof, TotpActivation,
    TotpEnrollment, TrustedDeviceGrant,
};
pub use ports::{
    ActivateTotp, AttemptDecision, AuditStore, AuthStore, ChallengeStore, ClaimEventsRequest,
    ClaimedEvent, Clock, CompleteMfaLogin, CreateSession, CreateTrustedDevice, CreateUser,
    EventStore, IdentityStore, LeasedEventStore, MfaChallengeLookup, MfaCompletionOutcome,
    MfaEnrollmentOutcome, MfaStore, OneTimeChallenge, OneTimeOutcome, PendingTotpEnrollment,
    RateLimitStore, RefreshRotation, RotateTrustedLogin, SessionStore, StoredMfaLoginChallenge,
    StoredTotpFactor, StoredUser, SystemClock, TrustedLoginOutcome, UnitOfWorkCapabilities,
    UnitOfWorkStore, VerifiedMfaProof,
};
pub use sdk::{SdkAuth, SdkAuthBuilder, SdkStore};
pub use service::{AuthService, AuthServiceBuilder};
pub use webauthn::{
    AuthenticatorManagementProof, BeginPasskeyLoginRequest, BeginPasskeyRegistrationRequest,
    CompletePasskeyAuthentication, CompletePasskeyRegistration, FinishPasskeyLoginRequest,
    FinishPasskeyRegistrationRequest, MAX_CREDENTIAL_ID_BYTES, PasskeyAuthenticationOutcome,
    PasskeyCeremonyKind, PasskeyCeremonyLookup, PasskeyLoginChallenge,
    PasskeyRegistrationChallenge, PasskeyRegistrationOutcome, PasskeyService, PasskeyStore,
    PendingPasskeyCeremony, RenamePasskeyRequest, RevokePasskeyRequest, StoredPasskey,
    VersionedPasskeyCredential, WebAuthnAuthenticationResult, WebAuthnCeremony, WebAuthnEngine,
    WebAuthnProviderMetadata, WebAuthnRegistrationResult,
};
