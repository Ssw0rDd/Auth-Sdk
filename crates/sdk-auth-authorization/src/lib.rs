//! Authorization value objects and a deterministic deny-by-default RBAC evaluator.
//!
//! This crate performs no I/O. Persistence and credential orchestration remain
//! behind ports owned by `sdk-auth-core`.

use std::{collections::HashSet, fmt};

use sdk_auth_error::AuthError;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Maximum encoded length of a canonical permission key.
pub const MAX_PERMISSION_KEY_BYTES: usize = 128;
/// Maximum Unicode characters accepted in a human-readable name.
pub const MAX_NAME_CHARS: usize = 80;
/// Maximum bytes accepted in a human-readable description.
pub const MAX_DESCRIPTION_BYTES: usize = 512;
/// Maximum permissions assignable to one role.
pub const MAX_PERMISSIONS_PER_ROLE: usize = 256;
/// Maximum roles assignable to one principal.
pub const MAX_ROLES_PER_PRINCIPAL: usize = 32;
/// Maximum permission scopes assignable to one API key.
pub const MAX_SCOPES_PER_API_KEY: usize = 128;

/// Canonical `resource:action` permission identifier.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PermissionKey(String);

impl PermissionKey {
    /// Parses a lowercase ASCII permission without wildcards.
    pub fn parse(value: impl Into<String>) -> Result<Self, AuthError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PERMISSION_KEY_BYTES
            || value.contains('*')
            || value.bytes().filter(|byte| *byte == b':').count() != 1
        {
            return Err(AuthError::invalid_input());
        }
        let (resource, action) = value.split_once(':').ok_or_else(AuthError::invalid_input)?;
        if !valid_segment(resource) || !valid_segment(action) {
            return Err(AuthError::invalid_input());
        }
        Ok(Self(value))
    }

    /// Returns the canonical external representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PermissionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PermissionKey")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for PermissionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for PermissionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PermissionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?)
            .map_err(|_| D::Error::custom("invalid permission key"))
    }
}

/// Canonical stable key for a role inside one realm.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleKey(String);

impl RoleKey {
    /// Parses a lowercase ASCII role key.
    pub fn parse(value: impl Into<String>) -> Result<Self, AuthError> {
        let value = value.into();
        if value.len() > 64 || !valid_segment(&value) {
            return Err(AuthError::invalid_input());
        }
        Ok(Self(value))
    }

    /// Returns the stable external representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RoleKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RoleKey").field(&self.0).finish()
    }
}

impl fmt::Display for RoleKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for RoleKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RoleKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?)
            .map_err(|_| D::Error::custom("invalid role key"))
    }
}

#[cfg(feature = "domain")]
mod domain {
    use super::*;
    use chrono::{DateTime, Utc};
    use sdk_auth_types::{ApiKeyId, PermissionId, RealmId, RoleId, ServiceAccountId, UserId};

    /// A human or workload identity that can receive roles.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(tag = "kind", content = "id", rename_all = "snake_case")]
    #[non_exhaustive]
    pub enum PrincipalId {
        /// Human identity authenticated through a user session.
        User(UserId),
        /// Non-human workload identity authenticated through API keys.
        ServiceAccount(ServiceAccountId),
    }

    /// Credential class that established an authorization grant.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    #[non_exhaustive]
    pub enum CredentialKind {
        /// Opaque access token for an authenticated user session.
        UserAccessToken,
        /// Revocable restricted API key.
        ApiKey,
    }

    /// Registered permission metadata.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PermissionDefinition {
        realm_id: RealmId,
        id: PermissionId,
        key: PermissionKey,
        description: String,
        enabled: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    }

    impl PermissionDefinition {
        /// Reconstructs validated permission metadata.
        pub fn from_parts(
            realm_id: RealmId,
            id: PermissionId,
            key: PermissionKey,
            description: impl Into<String>,
            enabled: bool,
            created_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
        ) -> Result<Self, AuthError> {
            let description = validate_description(description.into())?;
            Ok(Self {
                realm_id,
                id,
                key,
                description,
                enabled,
                created_at,
                updated_at,
            })
        }

        /// Owning realm.
        #[must_use]
        pub const fn realm_id(&self) -> RealmId {
            self.realm_id
        }
        /// Stable identifier.
        #[must_use]
        pub const fn id(&self) -> PermissionId {
            self.id
        }
        /// Canonical permission key.
        #[must_use]
        pub const fn key(&self) -> &PermissionKey {
            &self.key
        }
        /// Human-readable description.
        #[must_use]
        pub fn description(&self) -> &str {
            &self.description
        }
        /// Whether grants of this permission can authorize access.
        #[must_use]
        pub const fn enabled(&self) -> bool {
            self.enabled
        }
        /// Creation time.
        #[must_use]
        pub const fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        /// Last mutation time.
        #[must_use]
        pub const fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    /// Role metadata. Permissions are stored through explicit assignments.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Role {
        realm_id: RealmId,
        id: RoleId,
        key: RoleKey,
        name: String,
        description: String,
        reserved: bool,
        enabled: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    }

    impl Role {
        /// Reconstructs a validated role.
        #[allow(clippy::too_many_arguments)]
        pub fn from_parts(
            realm_id: RealmId,
            id: RoleId,
            key: RoleKey,
            name: impl Into<String>,
            description: impl Into<String>,
            reserved: bool,
            enabled: bool,
            created_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
        ) -> Result<Self, AuthError> {
            let name = validate_name(name.into())?;
            let description = validate_description(description.into())?;
            Ok(Self {
                realm_id,
                id,
                key,
                name,
                description,
                reserved,
                enabled,
                created_at,
                updated_at,
            })
        }

        /// Owning realm.
        #[must_use]
        pub const fn realm_id(&self) -> RealmId {
            self.realm_id
        }
        /// Stable identifier.
        #[must_use]
        pub const fn id(&self) -> RoleId {
            self.id
        }
        /// Stable role key.
        #[must_use]
        pub const fn key(&self) -> &RoleKey {
            &self.key
        }
        /// Human-readable name.
        #[must_use]
        pub fn name(&self) -> &str {
            &self.name
        }
        /// Human-readable description.
        #[must_use]
        pub fn description(&self) -> &str {
            &self.description
        }
        /// Whether SDK invariants protect the role from removal.
        #[must_use]
        pub const fn reserved(&self) -> bool {
            self.reserved
        }
        /// Whether assignments through this role are active.
        #[must_use]
        pub const fn enabled(&self) -> bool {
            self.enabled
        }
        /// Creation time.
        #[must_use]
        pub const fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        /// Last mutation time.
        #[must_use]
        pub const fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    /// Non-human principal controlled by a realm administrator.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ServiceAccount {
        realm_id: RealmId,
        id: ServiceAccountId,
        name: String,
        description: String,
        enabled: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    }

    impl ServiceAccount {
        /// Reconstructs a validated service account.
        pub fn from_parts(
            realm_id: RealmId,
            id: ServiceAccountId,
            name: impl Into<String>,
            description: impl Into<String>,
            enabled: bool,
            created_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
        ) -> Result<Self, AuthError> {
            let name = validate_name(name.into())?;
            let description = validate_description(description.into())?;
            Ok(Self {
                realm_id,
                id,
                name,
                description,
                enabled,
                created_at,
                updated_at,
            })
        }

        /// Owning realm.
        #[must_use]
        pub const fn realm_id(&self) -> RealmId {
            self.realm_id
        }
        /// Stable identifier.
        #[must_use]
        pub const fn id(&self) -> ServiceAccountId {
            self.id
        }
        /// Human-readable name.
        #[must_use]
        pub fn name(&self) -> &str {
            &self.name
        }
        /// Human-readable description.
        #[must_use]
        pub fn description(&self) -> &str {
            &self.description
        }
        /// Whether credentials for this principal can authorize access.
        #[must_use]
        pub const fn enabled(&self) -> bool {
            self.enabled
        }
        /// Creation time.
        #[must_use]
        pub const fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        /// Last mutation time.
        #[must_use]
        pub const fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    /// Public metadata for an API key. The bearer secret is never part of this type.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ApiKey {
        realm_id: RealmId,
        id: ApiKeyId,
        principal: PrincipalId,
        name: String,
        scopes: Vec<PermissionKey>,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        grace_expires_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
    }

    impl ApiKey {
        /// Reconstructs validated public API-key metadata.
        #[allow(clippy::too_many_arguments)]
        pub fn from_parts(
            realm_id: RealmId,
            id: ApiKeyId,
            principal: PrincipalId,
            name: impl Into<String>,
            scopes: Vec<PermissionKey>,
            created_at: DateTime<Utc>,
            expires_at: DateTime<Utc>,
            grace_expires_at: Option<DateTime<Utc>>,
            revoked_at: Option<DateTime<Utc>>,
        ) -> Result<Self, AuthError> {
            let name = validate_name(name.into())?;
            let scopes = normalize_bounded(scopes, MAX_SCOPES_PER_API_KEY)?;
            if scopes.is_empty()
                || expires_at <= created_at
                || grace_expires_at.is_some_and(|value| value > expires_at)
            {
                return Err(AuthError::invalid_input());
            }
            Ok(Self {
                realm_id,
                id,
                principal,
                name,
                scopes,
                created_at,
                expires_at,
                grace_expires_at,
                revoked_at,
            })
        }

        /// Owning realm.
        #[must_use]
        pub const fn realm_id(&self) -> RealmId {
            self.realm_id
        }
        /// Stable public identifier.
        #[must_use]
        pub const fn id(&self) -> ApiKeyId {
            self.id
        }
        /// Principal constrained by this key.
        #[must_use]
        pub const fn principal(&self) -> PrincipalId {
            self.principal
        }
        /// Human-readable key name.
        #[must_use]
        pub fn name(&self) -> &str {
            &self.name
        }
        /// Explicit permission ceiling.
        #[must_use]
        pub fn scopes(&self) -> &[PermissionKey] {
            &self.scopes
        }
        /// Creation time.
        #[must_use]
        pub const fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        /// Absolute expiration.
        #[must_use]
        pub const fn expires_at(&self) -> DateTime<Utc> {
            self.expires_at
        }
        /// End of overlap for a rotated predecessor.
        #[must_use]
        pub const fn grace_expires_at(&self) -> Option<DateTime<Utc>> {
            self.grace_expires_at
        }
        /// Explicit revocation time.
        #[must_use]
        pub const fn revoked_at(&self) -> Option<DateTime<Utc>> {
            self.revoked_at
        }
    }

    /// Successful, credential-bound authorization result.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AuthorizationGrant {
        realm_id: RealmId,
        principal: PrincipalId,
        permission: PermissionKey,
        credential_kind: CredentialKind,
        api_key_id: Option<ApiKeyId>,
    }

    impl AuthorizationGrant {
        /// Creates a grant after the core authenticated and authorized a request.
        #[must_use]
        pub fn new(
            realm_id: RealmId,
            principal: PrincipalId,
            permission: PermissionKey,
            credential_kind: CredentialKind,
            api_key_id: Option<ApiKeyId>,
        ) -> Self {
            Self {
                realm_id,
                principal,
                permission,
                credential_kind,
                api_key_id,
            }
        }

        /// Owning realm.
        #[must_use]
        pub const fn realm_id(&self) -> RealmId {
            self.realm_id
        }
        /// Authorized principal.
        #[must_use]
        pub const fn principal(&self) -> PrincipalId {
            self.principal
        }
        /// Permission checked by the core.
        #[must_use]
        pub const fn permission(&self) -> &PermissionKey {
            &self.permission
        }
        /// Credential class used for the check.
        #[must_use]
        pub const fn credential_kind(&self) -> CredentialKind {
            self.credential_kind
        }
        /// API-key identifier when an API key established the grant.
        #[must_use]
        pub const fn api_key_id(&self) -> Option<ApiKeyId> {
            self.api_key_id
        }
    }
}

#[cfg(feature = "domain")]
pub use domain::*;

/// Evaluates one permission with deny-by-default semantics.
///
/// When `scopes` is present, both a current role grant and an exact key scope
/// must match. Wildcards and negative permissions do not exist.
#[must_use]
pub fn is_allowed(
    granted: &[PermissionKey],
    scopes: Option<&[PermissionKey]>,
    requested: &PermissionKey,
) -> bool {
    granted.iter().any(|permission| permission == requested)
        && scopes.is_none_or(|values| values.iter().any(|permission| permission == requested))
}

/// Validates and deterministically deduplicates permission collections.
pub fn normalize_permissions(
    values: Vec<PermissionKey>,
    limit: usize,
) -> Result<Vec<PermissionKey>, AuthError> {
    normalize_bounded(values, limit)
}

fn normalize_bounded(
    mut values: Vec<PermissionKey>,
    limit: usize,
) -> Result<Vec<PermissionKey>, AuthError> {
    if values.len() > limit {
        return Err(AuthError::invalid_input());
    }
    let mut seen = HashSet::with_capacity(values.len());
    values.retain(|value| seen.insert(value.clone()));
    values.sort_unstable();
    Ok(values)
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

#[cfg(feature = "domain")]
fn validate_name(value: String) -> Result<String, AuthError> {
    let value = value.trim().to_owned();
    if value.is_empty()
        || value.chars().count() > MAX_NAME_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(AuthError::invalid_input());
    }
    Ok(value)
}

#[cfg(feature = "domain")]
fn validate_description(value: String) -> Result<String, AuthError> {
    let value = value.trim().to_owned();
    if value.len() > MAX_DESCRIPTION_BYTES || value.chars().any(char::is_control) {
        return Err(AuthError::invalid_input());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_is_canonical_and_has_no_wildcards() {
        assert!(PermissionKey::parse("documents:read").is_ok());
        assert!(PermissionKey::parse("Documents:read").is_err());
        assert!(PermissionKey::parse("documents:*").is_err());
        assert!(PermissionKey::parse("documents:read:all").is_err());
    }

    #[test]
    fn evaluator_requires_role_and_scope() -> Result<(), AuthError> {
        let read = PermissionKey::parse("documents:read")?;
        let write = PermissionKey::parse("documents:write")?;
        assert!(is_allowed(std::slice::from_ref(&read), None, &read));
        assert!(!is_allowed(
            std::slice::from_ref(&read),
            Some(std::slice::from_ref(&write)),
            &read
        ));
        assert!(!is_allowed(
            std::slice::from_ref(&write),
            Some(std::slice::from_ref(&read)),
            &read
        ));
        Ok(())
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_text_never_panics(value in ".{0,512}") {
            let _ = PermissionKey::parse(value);
        }
    }
}
