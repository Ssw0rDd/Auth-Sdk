use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdk_auth_authorization::{
    ApiKey, MAX_PERMISSIONS_PER_ROLE, MAX_ROLES_PER_PRINCIPAL, PermissionDefinition, PermissionKey,
    PrincipalId, Role, RoleKey, ServiceAccount,
};
use sdk_auth_core::{
    ApiKeyAuthentication, BootstrapIam, CreateApiKey, CreatePermission, CreateRole,
    CreateServiceAccount, IamStore, RotateApiKey, StoredApiKey,
};
use sdk_auth_crypto::{ParsedApiKey, TokenDigest};
use sdk_auth_error::AuthError;
use sdk_auth_types::{
    ApiKeyId, AuthEvent, PermissionId, RealmId, RoleId, ServiceAccountId, UserId,
};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::{
    PostgresAuthStore,
    mapping::{conflict, insert_event, is_unique_violation, permission_denied, storage},
};

#[async_trait]
impl IamStore for PostgresAuthStore {
    async fn iam_initialized(&self, realm_id: RealmId) -> Result<bool, AuthError> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM iam_realms WHERE realm_id=$1)")
            .bind(realm_id.as_uuid())
            .fetch_one(&self.pool)
            .await
            .map_err(storage)
    }

    async fn bootstrap_iam(&self, command: BootstrapIam) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, command.realm_id).await?;
        let initialized: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM iam_realms WHERE realm_id=$1)")
                .bind(command.realm_id.as_uuid())
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage)?;
        if initialized {
            return Err(conflict());
        }
        let user_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE realm_id=$1 AND id=$2)")
                .bind(command.realm_id.as_uuid())
                .bind(command.owner_user_id.as_uuid())
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage)?;
        if !user_exists
            || command.owner_role.realm_id() != command.realm_id
            || !command.owner_role.reserved()
            || command.permissions.is_empty()
            || command.permissions.len() > MAX_PERMISSIONS_PER_ROLE
        {
            return Err(AuthError::invalid_input());
        }
        sqlx::query("INSERT INTO iam_realms(realm_id,initialized_at) VALUES($1,$2)")
            .bind(command.realm_id.as_uuid())
            .bind(command.event.created_at)
            .execute(&mut *transaction)
            .await
            .map_err(storage)?;
        insert_role(&mut transaction, &command.owner_role).await?;
        for permission in &command.permissions {
            if permission.realm_id() != command.realm_id || !permission.enabled() {
                return Err(AuthError::invalid_input());
            }
            insert_permission(&mut transaction, permission).await?;
            sqlx::query(
                "INSERT INTO iam_role_permissions(realm_id,role_id,permission_id) VALUES($1,$2,$3)",
            )
            .bind(command.realm_id.as_uuid())
            .bind(command.owner_role.id().as_uuid())
            .bind(permission.id().as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(storage)?;
        }
        sqlx::query(
            "INSERT INTO iam_principal_roles(realm_id,principal_kind,principal_id,role_id,created_at) VALUES($1,'user',$2,$3,$4)",
        )
        .bind(command.realm_id.as_uuid())
        .bind(command.owner_user_id.as_uuid())
        .bind(command.owner_role.id().as_uuid())
        .bind(command.event.created_at)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        insert_event(&mut transaction, &command.event).await?;
        transaction.commit().await.map_err(storage)
    }

    async fn principal_permissions(
        &self,
        realm_id: RealmId,
        principal: PrincipalId,
    ) -> Result<Vec<PermissionKey>, AuthError> {
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        effective_permissions(&mut connection, realm_id, principal).await
    }

    async fn create_permission(&self, command: CreatePermission) -> Result<(), AuthError> {
        let realm_id = command.permission.realm_id();
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            command.actor_user_id,
            &command.required_permission,
        )
        .await?;
        insert_permission(&mut transaction, &command.permission).await?;
        insert_event(&mut transaction, &command.event).await?;
        transaction.commit().await.map_err(storage)
    }

    async fn set_permission_enabled(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        permission_id: PermissionId,
        enabled: bool,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            actor_user_id,
            &required_permission,
        )
        .await?;
        if !enabled && permission_is_reserved(&mut transaction, realm_id, permission_id).await? {
            return Err(conflict());
        }
        let changed = sqlx::query(
            "UPDATE iam_permissions SET enabled=$1,updated_at=$2 WHERE realm_id=$3 AND id=$4 AND enabled<>$1",
        )
        .bind(enabled)
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(permission_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(storage)?
        .rows_affected();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam_permissions WHERE realm_id=$1 AND id=$2)",
        )
        .bind(realm_id.as_uuid())
        .bind(permission_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage)?;
        if changed == 1 {
            insert_event(&mut transaction, &event).await?;
        }
        transaction.commit().await.map_err(storage)?;
        Ok(exists)
    }

    async fn list_permissions(
        &self,
        realm_id: RealmId,
    ) -> Result<Vec<PermissionDefinition>, AuthError> {
        let rows = sqlx::query(
            "SELECT id,key,description,enabled,created_at,updated_at FROM iam_permissions WHERE realm_id=$1 ORDER BY key",
        )
        .bind(realm_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.iter()
            .map(|row| stored_permission(row, realm_id))
            .collect()
    }

    async fn create_role(&self, command: CreateRole) -> Result<(), AuthError> {
        let realm_id = command.role.realm_id();
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            command.actor_user_id,
            &command.required_permission,
        )
        .await?;
        if command.role.reserved() {
            return Err(conflict());
        }
        insert_role(&mut transaction, &command.role).await?;
        insert_event(&mut transaction, &command.event).await?;
        transaction.commit().await.map_err(storage)
    }

    async fn set_role_enabled(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        role_id: RoleId,
        enabled: bool,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            actor_user_id,
            &required_permission,
        )
        .await?;
        let reserved = sqlx::query_scalar::<_, bool>(
            "SELECT reserved FROM iam_roles WHERE realm_id=$1 AND id=$2",
        )
        .bind(realm_id.as_uuid())
        .bind(role_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage)?;
        let Some(reserved) = reserved else {
            return Ok(false);
        };
        if reserved {
            return Err(conflict());
        }
        let changed = sqlx::query(
            "UPDATE iam_roles SET enabled=$1,updated_at=$2 WHERE realm_id=$3 AND id=$4 AND enabled<>$1",
        )
        .bind(enabled)
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(role_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(storage)?
        .rows_affected();
        if changed == 1 {
            insert_event(&mut transaction, &event).await?;
        }
        transaction.commit().await.map_err(storage)?;
        Ok(true)
    }

    async fn list_roles(&self, realm_id: RealmId) -> Result<Vec<Role>, AuthError> {
        let rows = sqlx::query(
            "SELECT id,key,name,description,reserved,enabled,created_at,updated_at FROM iam_roles WHERE realm_id=$1 ORDER BY key",
        )
        .bind(realm_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.iter().map(|row| stored_role(row, realm_id)).collect()
    }

    async fn set_role_permission(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        role_id: RoleId,
        permission_id: PermissionId,
        granted: bool,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            actor_user_id,
            &required_permission,
        )
        .await?;
        let reserved = sqlx::query_scalar::<_, bool>(
            "SELECT reserved FROM iam_roles WHERE realm_id=$1 AND id=$2",
        )
        .bind(realm_id.as_uuid())
        .bind(role_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage)?;
        let Some(reserved) = reserved else {
            return Ok(false);
        };
        if reserved {
            return Err(conflict());
        }
        let permission_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam_permissions WHERE realm_id=$1 AND id=$2)",
        )
        .bind(realm_id.as_uuid())
        .bind(permission_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage)?;
        if !permission_exists {
            return Ok(false);
        }
        let changed = if granted {
            enforce_role_permission_limit(&mut transaction, realm_id, role_id, permission_id)
                .await?;
            sqlx::query(
                "INSERT INTO iam_role_permissions(realm_id,role_id,permission_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
            )
            .bind(realm_id.as_uuid())
            .bind(role_id.as_uuid())
            .bind(permission_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(storage)?
            .rows_affected()
        } else {
            sqlx::query(
                "DELETE FROM iam_role_permissions WHERE realm_id=$1 AND role_id=$2 AND permission_id=$3",
            )
            .bind(realm_id.as_uuid())
            .bind(role_id.as_uuid())
            .bind(permission_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(storage)?
            .rows_affected()
        };
        if changed == 1 {
            insert_event(&mut transaction, &event).await?;
        }
        transaction.commit().await.map_err(storage)?;
        Ok(changed == 1)
    }

    async fn set_principal_role(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        principal: PrincipalId,
        role_id: RoleId,
        granted: bool,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            actor_user_id,
            &required_permission,
        )
        .await?;
        let reserved = sqlx::query_scalar::<_, bool>(
            "SELECT reserved FROM iam_roles WHERE realm_id=$1 AND id=$2",
        )
        .bind(realm_id.as_uuid())
        .bind(role_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage)?;
        let Some(reserved) = reserved else {
            return Ok(false);
        };
        if !principal_exists(&mut transaction, realm_id, principal).await? {
            return Ok(false);
        }
        let (kind, principal_id) = principal_parts(principal)?;
        if reserved && kind != "user" {
            return Err(permission_denied());
        }
        let changed = if granted {
            enforce_principal_role_limit(&mut transaction, realm_id, kind, principal_id, role_id)
                .await?;
            sqlx::query(
                "INSERT INTO iam_principal_roles(realm_id,principal_kind,principal_id,role_id,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            )
            .bind(realm_id.as_uuid())
            .bind(kind)
            .bind(principal_id)
            .bind(role_id.as_uuid())
            .bind(event.created_at)
            .execute(&mut *transaction)
            .await
            .map_err(storage)?
            .rows_affected()
        } else {
            if reserved {
                let owners: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM iam_principal_roles WHERE realm_id=$1 AND principal_kind='user' AND role_id=$2",
                )
                .bind(realm_id.as_uuid())
                .bind(role_id.as_uuid())
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage)?;
                if owners <= 1 {
                    return Err(conflict());
                }
            }
            sqlx::query(
                "DELETE FROM iam_principal_roles WHERE realm_id=$1 AND principal_kind=$2 AND principal_id=$3 AND role_id=$4",
            )
            .bind(realm_id.as_uuid())
            .bind(kind)
            .bind(principal_id)
            .bind(role_id.as_uuid())
            .execute(&mut *transaction)
            .await
            .map_err(storage)?
            .rows_affected()
        };
        if changed == 1 {
            insert_event(&mut transaction, &event).await?;
        }
        transaction.commit().await.map_err(storage)?;
        Ok(changed == 1)
    }

    async fn create_service_account(&self, command: CreateServiceAccount) -> Result<(), AuthError> {
        let realm_id = command.service_account.realm_id();
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            command.actor_user_id,
            &command.required_permission,
        )
        .await?;
        insert_service_account(&mut transaction, &command.service_account).await?;
        insert_event(&mut transaction, &command.event).await?;
        transaction.commit().await.map_err(storage)
    }

    async fn set_service_account_enabled(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        service_account_id: ServiceAccountId,
        enabled: bool,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            actor_user_id,
            &required_permission,
        )
        .await?;
        let changed = sqlx::query(
            "UPDATE iam_service_accounts SET enabled=$1,updated_at=$2 WHERE realm_id=$3 AND id=$4 AND enabled<>$1",
        )
        .bind(enabled)
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(service_account_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(storage)?
        .rows_affected();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam_service_accounts WHERE realm_id=$1 AND id=$2)",
        )
        .bind(realm_id.as_uuid())
        .bind(service_account_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage)?;
        if changed == 1 {
            insert_event(&mut transaction, &event).await?;
        }
        transaction.commit().await.map_err(storage)?;
        Ok(exists)
    }

    async fn list_service_accounts(
        &self,
        realm_id: RealmId,
    ) -> Result<Vec<ServiceAccount>, AuthError> {
        let rows = sqlx::query(
            "SELECT id,name,description,enabled,created_at,updated_at FROM iam_service_accounts WHERE realm_id=$1 ORDER BY created_at,id",
        )
        .bind(realm_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.iter()
            .map(|row| stored_service_account(row, realm_id))
            .collect()
    }

    async fn create_api_key(&self, command: CreateApiKey) -> Result<(), AuthError> {
        let realm_id = command.stored.key.realm_id();
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            command.actor_user_id,
            &command.required_permission,
        )
        .await?;
        validate_api_key_scope(&mut transaction, &command.stored.key).await?;
        insert_api_key(&mut transaction, &command.stored).await?;
        insert_event(&mut transaction, &command.event).await?;
        transaction.commit().await.map_err(storage)
    }

    async fn find_api_key(
        &self,
        realm_id: RealmId,
        id: ApiKeyId,
    ) -> Result<Option<ApiKey>, AuthError> {
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        Ok(load_api_key(&mut connection, realm_id, id, false)
            .await?
            .map(|stored| stored.key))
    }

    async fn list_api_keys(
        &self,
        realm_id: RealmId,
        principal: PrincipalId,
    ) -> Result<Vec<ApiKey>, AuthError> {
        let (kind, principal_id) = principal_parts(principal)?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        let rows = sqlx::query(
            "SELECT k.id,k.principal_kind,k.principal_id,k.name,k.created_at,k.expires_at,k.grace_expires_at,k.revoked_at,p.key AS scope_key FROM iam_api_keys k JOIN iam_api_key_scopes s ON s.realm_id=k.realm_id AND s.api_key_id=k.id JOIN iam_permissions p ON p.realm_id=s.realm_id AND p.id=s.permission_id WHERE k.realm_id=$1 AND k.principal_kind=$2 AND k.principal_id=$3 ORDER BY k.created_at,k.id,p.key",
        )
        .bind(realm_id.as_uuid())
        .bind(kind)
        .bind(principal_id)
        .fetch_all(&mut *connection)
        .await
        .map_err(storage)?;
        let mut keys = Vec::new();
        let mut index = 0;
        while index < rows.len() {
            let row = &rows[index];
            let id: Uuid = row.try_get("id").map_err(storage)?;
            let mut scopes = Vec::new();
            while index < rows.len() && rows[index].try_get::<Uuid, _>("id").map_err(storage)? == id
            {
                scopes.push(PermissionKey::parse(
                    rows[index]
                        .try_get::<String, _>("scope_key")
                        .map_err(storage)?,
                )?);
                index += 1;
            }
            let principal_kind: String = row.try_get("principal_kind").map_err(storage)?;
            let key_principal_id: Uuid = row.try_get("principal_id").map_err(storage)?;
            keys.push(ApiKey::from_parts(
                realm_id,
                ApiKeyId::from_uuid(id),
                parse_principal(&principal_kind, key_principal_id)?,
                row.try_get::<String, _>("name").map_err(storage)?,
                scopes,
                row.try_get("created_at").map_err(storage)?,
                row.try_get("expires_at").map_err(storage)?,
                row.try_get("grace_expires_at").map_err(storage)?,
                row.try_get("revoked_at").map_err(storage)?,
            )?);
        }
        Ok(keys)
    }

    async fn rotate_api_key(&self, command: RotateApiKey) -> Result<(), AuthError> {
        let realm_id = command.replacement.key.realm_id();
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            command.actor_user_id,
            &command.required_permission,
        )
        .await?;
        validate_api_key_scope(&mut transaction, &command.replacement.key).await?;
        let previous = load_api_key(&mut transaction, realm_id, command.previous_id, true)
            .await?
            .ok_or_else(AuthError::invalid_credentials)?;
        if previous.key.principal() != command.replacement.key.principal()
            || previous.key.scopes() != command.replacement.key.scopes()
            || previous.key.revoked_at().is_some()
        {
            return Err(AuthError::invalid_credentials());
        }
        let grace = command
            .previous_grace_expires_at
            .min(previous.key.expires_at());
        sqlx::query(
            "UPDATE iam_api_keys SET grace_expires_at=$1 WHERE realm_id=$2 AND id=$3 AND revoked_at IS NULL",
        )
        .bind(grace)
        .bind(realm_id.as_uuid())
        .bind(command.previous_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;
        insert_api_key(&mut transaction, &command.replacement).await?;
        insert_event(&mut transaction, &command.event).await?;
        transaction.commit().await.map_err(storage)
    }

    async fn revoke_api_key(
        &self,
        realm_id: RealmId,
        actor_user_id: UserId,
        required_permission: PermissionKey,
        api_key_id: ApiKeyId,
        now: DateTime<Utc>,
        event: AuthEvent,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        lock_realm(&mut transaction, realm_id).await?;
        ensure_actor(
            &mut transaction,
            realm_id,
            actor_user_id,
            &required_permission,
        )
        .await?;
        let changed = sqlx::query(
            "UPDATE iam_api_keys SET revoked_at=$1 WHERE realm_id=$2 AND id=$3 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(realm_id.as_uuid())
        .bind(api_key_id.as_uuid())
        .execute(&mut *transaction)
        .await
        .map_err(storage)?
        .rows_affected();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam_api_keys WHERE realm_id=$1 AND id=$2)",
        )
        .bind(realm_id.as_uuid())
        .bind(api_key_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage)?;
        if changed == 1 {
            insert_event(&mut transaction, &event).await?;
        }
        transaction.commit().await.map_err(storage)?;
        Ok(exists)
    }

    async fn authenticate_api_key(
        &self,
        realm_id: RealmId,
        parsed: ParsedApiKey,
        now: DateTime<Utc>,
    ) -> Result<Option<ApiKeyAuthentication>, AuthError> {
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        let Some(stored) = load_api_key(&mut connection, realm_id, parsed.id, false).await? else {
            return Ok(None);
        };
        if !stored.digest.constant_time_eq(&parsed.digest)
            || stored.key.revoked_at().is_some()
            || stored.key.expires_at() <= now
            || stored
                .key
                .grace_expires_at()
                .is_some_and(|value| value <= now)
            || !principal_active(&mut connection, realm_id, stored.key.principal()).await?
        {
            return Ok(None);
        }
        Ok(Some(ApiKeyAuthentication {
            permissions: effective_permissions(&mut connection, realm_id, stored.key.principal())
                .await?,
            key: stored.key,
        }))
    }
}

async fn lock_realm(connection: &mut PgConnection, realm_id: RealmId) -> Result<(), AuthError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text,0))")
        .bind(realm_id.as_uuid())
        .execute(connection)
        .await
        .map(|_| ())
        .map_err(storage)
}

async fn effective_permissions(
    connection: &mut PgConnection,
    realm_id: RealmId,
    principal: PrincipalId,
) -> Result<Vec<PermissionKey>, AuthError> {
    if !principal_active(connection, realm_id, principal).await? {
        return Ok(Vec::new());
    }
    let (kind, principal_id) = principal_parts(principal)?;
    let values = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT p.key FROM iam_principal_roles pr JOIN iam_roles r ON r.realm_id=pr.realm_id AND r.id=pr.role_id JOIN iam_role_permissions rp ON rp.realm_id=r.realm_id AND rp.role_id=r.id JOIN iam_permissions p ON p.realm_id=rp.realm_id AND p.id=rp.permission_id WHERE pr.realm_id=$1 AND pr.principal_kind=$2 AND pr.principal_id=$3 AND r.enabled=TRUE AND p.enabled=TRUE ORDER BY p.key",
    )
    .bind(realm_id.as_uuid())
    .bind(kind)
    .bind(principal_id)
    .fetch_all(connection)
    .await
    .map_err(storage)?;
    values.into_iter().map(PermissionKey::parse).collect()
}

async fn ensure_actor(
    connection: &mut PgConnection,
    realm_id: RealmId,
    actor: UserId,
    required: &PermissionKey,
) -> Result<(), AuthError> {
    if effective_permissions(connection, realm_id, PrincipalId::User(actor))
        .await?
        .iter()
        .any(|permission| permission == required)
    {
        Ok(())
    } else {
        Err(permission_denied())
    }
}

fn principal_parts(principal: PrincipalId) -> Result<(&'static str, Uuid), AuthError> {
    #[allow(unreachable_patterns)]
    match principal {
        PrincipalId::User(id) => Ok(("user", id.as_uuid())),
        PrincipalId::ServiceAccount(id) => Ok(("service_account", id.as_uuid())),
        _ => Err(AuthError::invalid_input()),
    }
}

fn parse_principal(kind: &str, id: Uuid) -> Result<PrincipalId, AuthError> {
    match kind {
        "user" => Ok(PrincipalId::User(UserId::from_uuid(id))),
        "service_account" => Ok(PrincipalId::ServiceAccount(ServiceAccountId::from_uuid(id))),
        _ => Err(AuthError::storage_unavailable()),
    }
}

async fn principal_exists(
    connection: &mut PgConnection,
    realm_id: RealmId,
    principal: PrincipalId,
) -> Result<bool, AuthError> {
    match principal {
        PrincipalId::User(id) => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE realm_id=$1 AND id=$2)")
                .bind(realm_id.as_uuid())
                .bind(id.as_uuid())
                .fetch_one(connection)
                .await
                .map_err(storage)
        }
        PrincipalId::ServiceAccount(id) => sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam_service_accounts WHERE realm_id=$1 AND id=$2)",
        )
        .bind(realm_id.as_uuid())
        .bind(id.as_uuid())
        .fetch_one(connection)
        .await
        .map_err(storage),
        #[allow(unreachable_patterns)]
        _ => Ok(false),
    }
}

async fn principal_active(
    connection: &mut PgConnection,
    realm_id: RealmId,
    principal: PrincipalId,
) -> Result<bool, AuthError> {
    match principal {
        PrincipalId::User(id) => sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE realm_id=$1 AND id=$2)",
        )
        .bind(realm_id.as_uuid())
        .bind(id.as_uuid())
        .fetch_one(connection)
        .await
        .map_err(storage),
        PrincipalId::ServiceAccount(id) => sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam_service_accounts WHERE realm_id=$1 AND id=$2 AND enabled=TRUE)",
        )
        .bind(realm_id.as_uuid())
        .bind(id.as_uuid())
        .fetch_one(connection)
        .await
        .map_err(storage),
        #[allow(unreachable_patterns)]
        _ => Ok(false),
    }
}

async fn permission_is_reserved(
    connection: &mut PgConnection,
    realm_id: RealmId,
    permission_id: PermissionId,
) -> Result<bool, AuthError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM iam_role_permissions rp JOIN iam_roles r ON r.realm_id=rp.realm_id AND r.id=rp.role_id WHERE rp.realm_id=$1 AND rp.permission_id=$2 AND r.reserved=TRUE)",
    )
    .bind(realm_id.as_uuid())
    .bind(permission_id.as_uuid())
    .fetch_one(connection)
    .await
    .map_err(storage)
}

async fn insert_permission(
    connection: &mut PgConnection,
    permission: &PermissionDefinition,
) -> Result<(), AuthError> {
    let result = sqlx::query(
        "INSERT INTO iam_permissions(realm_id,id,key,description,enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(permission.realm_id().as_uuid())
    .bind(permission.id().as_uuid())
    .bind(permission.key().as_str())
    .bind(permission.description())
    .bind(permission.enabled())
    .bind(permission.created_at())
    .bind(permission.updated_at())
    .execute(connection)
    .await;
    map_unique(result)
}

async fn insert_role(connection: &mut PgConnection, role: &Role) -> Result<(), AuthError> {
    let result = sqlx::query(
        "INSERT INTO iam_roles(realm_id,id,key,name,description,reserved,enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(role.realm_id().as_uuid())
    .bind(role.id().as_uuid())
    .bind(role.key().as_str())
    .bind(role.name())
    .bind(role.description())
    .bind(role.reserved())
    .bind(role.enabled())
    .bind(role.created_at())
    .bind(role.updated_at())
    .execute(connection)
    .await;
    map_unique(result)
}

async fn insert_service_account(
    connection: &mut PgConnection,
    account: &ServiceAccount,
) -> Result<(), AuthError> {
    let result = sqlx::query(
        "INSERT INTO iam_service_accounts(realm_id,id,name,description,enabled,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(account.realm_id().as_uuid())
    .bind(account.id().as_uuid())
    .bind(account.name())
    .bind(account.description())
    .bind(account.enabled())
    .bind(account.created_at())
    .bind(account.updated_at())
    .execute(connection)
    .await;
    map_unique(result)
}

fn map_unique(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>) -> Result<(), AuthError> {
    match result {
        Ok(_) => Ok(()),
        Err(error) if is_unique_violation(&error) => Err(conflict()),
        Err(error) => Err(storage(error)),
    }
}

async fn enforce_role_permission_limit(
    connection: &mut PgConnection,
    realm_id: RealmId,
    role_id: RoleId,
    permission_id: PermissionId,
) -> Result<(), AuthError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam_role_permissions WHERE realm_id=$1 AND role_id=$2",
    )
    .bind(realm_id.as_uuid())
    .bind(role_id.as_uuid())
    .fetch_one(&mut *connection)
    .await
    .map_err(storage)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM iam_role_permissions WHERE realm_id=$1 AND role_id=$2 AND permission_id=$3)",
    )
    .bind(realm_id.as_uuid())
    .bind(role_id.as_uuid())
    .bind(permission_id.as_uuid())
    .fetch_one(connection)
    .await
    .map_err(storage)?;
    if count >= i64::try_from(MAX_PERMISSIONS_PER_ROLE).map_err(|_| AuthError::invalid_input())?
        && !exists
    {
        Err(AuthError::invalid_input())
    } else {
        Ok(())
    }
}

async fn enforce_principal_role_limit(
    connection: &mut PgConnection,
    realm_id: RealmId,
    kind: &str,
    principal_id: Uuid,
    role_id: RoleId,
) -> Result<(), AuthError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam_principal_roles WHERE realm_id=$1 AND principal_kind=$2 AND principal_id=$3",
    )
    .bind(realm_id.as_uuid())
    .bind(kind)
    .bind(principal_id)
    .fetch_one(&mut *connection)
    .await
    .map_err(storage)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM iam_principal_roles WHERE realm_id=$1 AND principal_kind=$2 AND principal_id=$3 AND role_id=$4)",
    )
    .bind(realm_id.as_uuid())
    .bind(kind)
    .bind(principal_id)
    .bind(role_id.as_uuid())
    .fetch_one(connection)
    .await
    .map_err(storage)?;
    if count >= i64::try_from(MAX_ROLES_PER_PRINCIPAL).map_err(|_| AuthError::invalid_input())?
        && !exists
    {
        Err(AuthError::invalid_input())
    } else {
        Ok(())
    }
}

async fn validate_api_key_scope(
    connection: &mut PgConnection,
    key: &ApiKey,
) -> Result<(), AuthError> {
    if !principal_active(connection, key.realm_id(), key.principal()).await? {
        return Err(permission_denied());
    }
    let granted = effective_permissions(connection, key.realm_id(), key.principal()).await?;
    if key
        .scopes()
        .iter()
        .all(|scope| granted.iter().any(|permission| permission == scope))
    {
        Ok(())
    } else {
        Err(permission_denied())
    }
}

async fn insert_api_key(
    connection: &mut PgConnection,
    stored: &StoredApiKey,
) -> Result<(), AuthError> {
    let key = &stored.key;
    let (kind, principal_id) = principal_parts(key.principal())?;
    let result = sqlx::query(
        "INSERT INTO iam_api_keys(realm_id,id,principal_kind,principal_id,name,digest,created_at,expires_at,grace_expires_at,revoked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(key.realm_id().as_uuid())
    .bind(key.id().as_uuid())
    .bind(kind)
    .bind(principal_id)
    .bind(key.name())
    .bind(stored.digest.as_bytes().as_slice())
    .bind(key.created_at())
    .bind(key.expires_at())
    .bind(key.grace_expires_at())
    .bind(key.revoked_at())
    .execute(&mut *connection)
    .await;
    map_unique(result)?;
    for scope in key.scopes() {
        let permission_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM iam_permissions WHERE realm_id=$1 AND key=$2 AND enabled=TRUE",
        )
        .bind(key.realm_id().as_uuid())
        .bind(scope.as_str())
        .fetch_optional(&mut *connection)
        .await
        .map_err(storage)?
        .ok_or_else(permission_denied)?;
        sqlx::query(
            "INSERT INTO iam_api_key_scopes(realm_id,api_key_id,permission_id) VALUES($1,$2,$3)",
        )
        .bind(key.realm_id().as_uuid())
        .bind(key.id().as_uuid())
        .bind(permission_id)
        .execute(&mut *connection)
        .await
        .map_err(storage)?;
    }
    Ok(())
}

async fn load_api_key(
    connection: &mut PgConnection,
    realm_id: RealmId,
    id: ApiKeyId,
    for_update: bool,
) -> Result<Option<StoredApiKey>, AuthError> {
    let row = if for_update {
        sqlx::query(
            "SELECT principal_kind,principal_id,name,digest,created_at,expires_at,grace_expires_at,revoked_at FROM iam_api_keys WHERE realm_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(realm_id.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
    } else {
        sqlx::query(
            "SELECT principal_kind,principal_id,name,digest,created_at,expires_at,grace_expires_at,revoked_at FROM iam_api_keys WHERE realm_id=$1 AND id=$2",
        )
        .bind(realm_id.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
    }
    .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let scope_values = sqlx::query_scalar::<_, String>(
        "SELECT p.key FROM iam_api_key_scopes s JOIN iam_permissions p ON p.realm_id=s.realm_id AND p.id=s.permission_id WHERE s.realm_id=$1 AND s.api_key_id=$2 ORDER BY p.key",
    )
    .bind(realm_id.as_uuid())
    .bind(id.as_uuid())
    .fetch_all(connection)
    .await
    .map_err(storage)?;
    let scopes = scope_values
        .into_iter()
        .map(PermissionKey::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let principal_kind: String = row.try_get("principal_kind").map_err(storage)?;
    let principal_id: Uuid = row.try_get("principal_id").map_err(storage)?;
    let digest: Vec<u8> = row.try_get("digest").map_err(storage)?;
    Ok(Some(StoredApiKey {
        key: ApiKey::from_parts(
            realm_id,
            id,
            parse_principal(&principal_kind, principal_id)?,
            row.try_get::<String, _>("name").map_err(storage)?,
            scopes,
            row.try_get("created_at").map_err(storage)?,
            row.try_get("expires_at").map_err(storage)?,
            row.try_get("grace_expires_at").map_err(storage)?,
            row.try_get("revoked_at").map_err(storage)?,
        )?,
        digest: TokenDigest::from_slice(&digest)?,
    }))
}

fn stored_permission(
    row: &sqlx::postgres::PgRow,
    realm_id: RealmId,
) -> Result<PermissionDefinition, AuthError> {
    PermissionDefinition::from_parts(
        realm_id,
        PermissionId::from_uuid(row.try_get("id").map_err(storage)?),
        PermissionKey::parse(row.try_get::<String, _>("key").map_err(storage)?)?,
        row.try_get::<String, _>("description").map_err(storage)?,
        row.try_get("enabled").map_err(storage)?,
        row.try_get("created_at").map_err(storage)?,
        row.try_get("updated_at").map_err(storage)?,
    )
}

fn stored_role(row: &sqlx::postgres::PgRow, realm_id: RealmId) -> Result<Role, AuthError> {
    Role::from_parts(
        realm_id,
        RoleId::from_uuid(row.try_get("id").map_err(storage)?),
        RoleKey::parse(row.try_get::<String, _>("key").map_err(storage)?)?,
        row.try_get::<String, _>("name").map_err(storage)?,
        row.try_get::<String, _>("description").map_err(storage)?,
        row.try_get("reserved").map_err(storage)?,
        row.try_get("enabled").map_err(storage)?,
        row.try_get("created_at").map_err(storage)?,
        row.try_get("updated_at").map_err(storage)?,
    )
}

fn stored_service_account(
    row: &sqlx::postgres::PgRow,
    realm_id: RealmId,
) -> Result<ServiceAccount, AuthError> {
    ServiceAccount::from_parts(
        realm_id,
        ServiceAccountId::from_uuid(row.try_get("id").map_err(storage)?),
        row.try_get::<String, _>("name").map_err(storage)?,
        row.try_get::<String, _>("description").map_err(storage)?,
        row.try_get("enabled").map_err(storage)?,
        row.try_get("created_at").map_err(storage)?,
        row.try_get("updated_at").map_err(storage)?,
    )
}
