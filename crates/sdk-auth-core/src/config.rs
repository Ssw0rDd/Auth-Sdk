//! Security policy configuration.

use chrono::Duration;
use sdk_auth_error::{AuthError, ErrorCode};
use sdk_auth_validation::PasswordPolicy;

/// Sliding-window login attempt policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginAttemptPolicy {
    /// Maximum failures allowed in one window.
    pub max_failures: u32,
    /// Window after which failures no longer count.
    pub window: Duration,
    /// Cooldown applied after the limit is reached.
    pub lockout: Duration,
}

impl Default for LoginAttemptPolicy {
    fn default() -> Self {
        Self {
            max_failures: 5,
            window: Duration::minutes(15),
            lockout: Duration::minutes(15),
        }
    }
}

/// Security-sensitive behavior and lifetimes for [`crate::AuthService`].
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Access token lifetime.
    pub access_token_ttl: Duration,
    /// Absolute lifetime for a normal session.
    pub session_ttl: Duration,
    /// Absolute lifetime when remember-me is requested.
    pub remember_me_ttl: Duration,
    /// Email verification challenge lifetime.
    pub email_verification_ttl: Duration,
    /// Password reset challenge lifetime.
    pub password_reset_ttl: Duration,
    /// Lifetime of a pending second-factor login.
    pub mfa_login_ttl: Duration,
    /// Lifetime of a pending TOTP enrollment.
    pub mfa_enrollment_ttl: Duration,
    /// Lifetime of a pending WebAuthn ceremony.
    pub passkey_ceremony_ttl: Duration,
    /// Maximum age of a passkey session used as fresh management proof.
    pub passkey_management_max_age: Duration,
    /// Absolute trusted-device lifetime; rotations never extend it.
    pub trusted_device_ttl: Duration,
    /// Maximum invalid proofs accepted per MFA transaction.
    pub max_mfa_attempts: u32,
    /// Maximum invalid responses accepted per WebAuthn ceremony.
    pub max_passkey_attempts: u32,
    /// Number of recovery codes returned on activation or regeneration.
    pub recovery_code_count: usize,
    /// Maximum active passkeys owned by one user.
    pub max_passkeys_per_user: usize,
    /// Whether login requires a verified email.
    pub require_verified_email: bool,
    /// Login throttling policy.
    pub login_attempts: LoginAttemptPolicy,
    /// Password validation policy.
    pub password_policy: PasswordPolicy,
    /// Maximum number of Unicode characters in a device label.
    pub max_device_name_chars: usize,
    /// Maximum bytes accepted for each device fingerprint field.
    pub max_device_metadata_bytes: usize,
    /// Maximum Unicode characters accepted in a passkey label.
    pub max_passkey_label_chars: usize,
    /// Maximum browser WebAuthn JSON request size.
    pub max_webauthn_json_bytes: usize,
    /// Maximum opaque provider state or credential size.
    pub max_webauthn_state_bytes: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_ttl: Duration::minutes(10),
            session_ttl: Duration::days(7),
            remember_me_ttl: Duration::days(30),
            email_verification_ttl: Duration::hours(24),
            password_reset_ttl: Duration::minutes(30),
            mfa_login_ttl: Duration::minutes(5),
            mfa_enrollment_ttl: Duration::minutes(10),
            passkey_ceremony_ttl: Duration::minutes(5),
            passkey_management_max_age: Duration::minutes(5),
            trusted_device_ttl: Duration::days(30),
            max_mfa_attempts: 5,
            max_passkey_attempts: 5,
            recovery_code_count: 10,
            max_passkeys_per_user: 10,
            require_verified_email: true,
            login_attempts: LoginAttemptPolicy::default(),
            password_policy: PasswordPolicy::recommended(),
            max_device_name_chars: 80,
            max_device_metadata_bytes: 512,
            max_passkey_label_chars: 80,
            max_webauthn_json_bytes: 64 * 1024,
            max_webauthn_state_bytes: 64 * 1024,
        }
    }
}

impl AuthConfig {
    /// Rejects unsafe or nonsensical configuration.
    pub fn validate(&self) -> Result<(), AuthError> {
        let positive = [
            self.access_token_ttl,
            self.session_ttl,
            self.remember_me_ttl,
            self.email_verification_ttl,
            self.password_reset_ttl,
            self.mfa_login_ttl,
            self.mfa_enrollment_ttl,
            self.passkey_ceremony_ttl,
            self.passkey_management_max_age,
            self.trusted_device_ttl,
            self.login_attempts.window,
            self.login_attempts.lockout,
        ]
        .into_iter()
        .all(|duration| duration > Duration::zero());
        let lifetimes_are_ordered = self.access_token_ttl <= self.session_ttl
            && self.session_ttl <= self.remember_me_ttl
            && self.remember_me_ttl <= Duration::days(365);
        if !positive
            || !lifetimes_are_ordered
            || self.login_attempts.max_failures == 0
            || self.max_device_name_chars == 0
            || self.max_device_metadata_bytes < 64
            || self.max_mfa_attempts == 0
            || self.max_mfa_attempts > 10
            || self.max_passkey_attempts == 0
            || self.max_passkey_attempts > 10
            || !(1..=20).contains(&self.recovery_code_count)
            || !(1..=20).contains(&self.max_passkeys_per_user)
            || self.mfa_login_ttl > Duration::minutes(15)
            || self.mfa_enrollment_ttl > Duration::hours(1)
            || self.passkey_ceremony_ttl > Duration::minutes(10)
            || self.passkey_management_max_age > Duration::minutes(15)
            || self.trusted_device_ttl > Duration::days(90)
            || self.max_passkey_label_chars == 0
            || self.max_passkey_label_chars > 256
            || !(4_096..=1_048_576).contains(&self.max_webauthn_json_bytes)
            || !(4_096..=1_048_576).contains(&self.max_webauthn_state_bytes)
        {
            return Err(AuthError::new(
                ErrorCode::Misconfigured,
                "authentication configuration is outside supported bounds",
                false,
            ));
        }
        Ok(())
    }
}
