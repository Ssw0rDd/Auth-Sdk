CREATE TABLE IF NOT EXISTS sdk_migrations (
    version INTEGER PRIMARY KEY,
    checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS sdk_schema_compatibility (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    schema_version INTEGER NOT NULL,
    min_reader_version INTEGER NOT NULL,
    min_writer_version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sdk_import_status (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    status TEXT NOT NULL CHECK (status IN ('in_progress', 'complete', 'failed')),
    source_schema_version INTEGER NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS users (
    realm_id UUID NOT NULL,
    id UUID NOT NULL,
    email TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, normalized_email)
);

CREATE TABLE IF NOT EXISTS sessions (
    realm_id UUID NOT NULL,
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    family_id UUID NOT NULL,
    device_name TEXT,
    network_hash TEXT,
    user_agent TEXT,
    authentication_method TEXT NOT NULL,
    second_factor_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (realm_id, user_id);

CREATE TABLE IF NOT EXISTS access_tokens (
    realm_id UUID NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    session_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_id, digest),
    FOREIGN KEY (realm_id, session_id) REFERENCES sessions (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS access_session_idx ON access_tokens (realm_id, session_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    realm_id UUID NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    session_id UUID NOT NULL,
    family_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, digest),
    FOREIGN KEY (realm_id, session_id) REFERENCES sessions (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS refresh_session_idx ON refresh_tokens (realm_id, session_id);

CREATE TABLE IF NOT EXISTS challenges (
    realm_id UUID NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    kind TEXT NOT NULL,
    user_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, digest, kind),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS challenge_user_idx ON challenges (realm_id, user_id, kind);

CREATE TABLE IF NOT EXISTS login_attempts (
    realm_id UUID NOT NULL,
    subject TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('account', 'network')),
    attempts TIMESTAMPTZ[] NOT NULL,
    blocked_until TIMESTAMPTZ,
    PRIMARY KEY (realm_id, subject, scope)
);

CREATE TABLE IF NOT EXISTS outbox (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    user_id UUID NOT NULL,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    claim_id UUID,
    consumer_id TEXT,
    lease_expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox (created_at, id) WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS outbox_claim_idx ON outbox (claim_id) WHERE delivered_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_user_id UUID,
    subject_user_id UUID,
    kind TEXT NOT NULL,
    outcome TEXT NOT NULL,
    metadata JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    outbox_event_id UUID UNIQUE
);
CREATE INDEX IF NOT EXISTS audit_log_realm_time_idx ON audit_log (realm_id, occurred_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS mfa_totp_factors (
    realm_id UUID NOT NULL,
    user_id UUID NOT NULL,
    id UUID NOT NULL,
    key_id TEXT NOT NULL,
    format_version SMALLINT NOT NULL,
    algorithm TEXT NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 24),
    ciphertext BYTEA NOT NULL,
    last_accepted_counter BIGINT CHECK (last_accepted_counter >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_id, user_id),
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mfa_enrollments (
    realm_id UUID NOT NULL,
    user_id UUID NOT NULL,
    id UUID NOT NULL,
    key_id TEXT NOT NULL,
    format_version SMALLINT NOT NULL,
    algorithm TEXT NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 24),
    ciphertext BYTEA NOT NULL,
    replacing BOOLEAN NOT NULL,
    attempts INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_id, user_id),
    UNIQUE (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mfa_login_challenges (
    realm_id UUID NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    user_id UUID NOT NULL,
    device_name TEXT,
    network_hash TEXT,
    user_agent TEXT,
    remember_me BOOLEAN NOT NULL,
    attempts INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, digest),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS mfa_login_user_idx ON mfa_login_challenges (realm_id, user_id, consumed_at);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    realm_id UUID NOT NULL,
    user_id UUID NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_id, user_id, digest),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trusted_devices (
    realm_id UUID NOT NULL,
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    device_name TEXT,
    network_hash TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS trusted_device_user_idx ON trusted_devices (realm_id, user_id, created_at);

CREATE TABLE IF NOT EXISTS trusted_device_tokens (
    realm_id UUID NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    device_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, digest),
    FOREIGN KEY (realm_id, device_id) REFERENCES trusted_devices (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS trusted_token_device_idx ON trusted_device_tokens (realm_id, device_id);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    realm_id UUID NOT NULL,
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    label TEXT NOT NULL,
    credential_id BYTEA NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    provider_id TEXT NOT NULL,
    credential_format SMALLINT NOT NULL,
    credential_blob BYTEA NOT NULL,
    signature_counter BIGINT NOT NULL CHECK (signature_counter >= 0),
    backup_eligible BOOLEAN NOT NULL,
    backed_up BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS passkey_user_idx ON passkey_credentials (realm_id, user_id, revoked_at, created_at DESC);

CREATE TABLE IF NOT EXISTS passkey_ceremonies (
    realm_id UUID NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    user_id UUID NOT NULL,
    session_id UUID,
    kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),
    label TEXT,
    login_subject TEXT,
    device_name TEXT,
    network_hash TEXT,
    user_agent TEXT,
    remember_me BOOLEAN NOT NULL,
    provider_id TEXT NOT NULL,
    state_format SMALLINT NOT NULL,
    state_blob BYTEA NOT NULL,
    attempts INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, digest),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, session_id) REFERENCES sessions (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS passkey_ceremony_user_idx ON passkey_ceremonies (realm_id, user_id, kind, consumed_at);

CREATE TABLE IF NOT EXISTS iam_realms (
    realm_id UUID PRIMARY KEY,
    initialized_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS iam_permissions (
    realm_id UUID NOT NULL,
    id UUID NOT NULL,
    key TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, key)
);

CREATE TABLE IF NOT EXISTS iam_roles (
    realm_id UUID NOT NULL,
    id UUID NOT NULL,
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    reserved BOOLEAN NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, key)
);

CREATE TABLE IF NOT EXISTS iam_role_permissions (
    realm_id UUID NOT NULL,
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    PRIMARY KEY (realm_id, role_id, permission_id),
    FOREIGN KEY (realm_id, role_id) REFERENCES iam_roles (realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, permission_id) REFERENCES iam_permissions (realm_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS iam_service_accounts (
    realm_id UUID NOT NULL,
    id UUID NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, name)
);

CREATE TABLE IF NOT EXISTS iam_principal_roles (
    realm_id UUID NOT NULL,
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('user', 'service_account')),
    principal_id UUID NOT NULL,
    role_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_id, principal_kind, principal_id, role_id),
    FOREIGN KEY (realm_id, role_id) REFERENCES iam_roles (realm_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS iam_principal_roles_lookup_idx ON iam_principal_roles (realm_id, principal_kind, principal_id);

CREATE TABLE IF NOT EXISTS iam_api_keys (
    realm_id UUID NOT NULL,
    id UUID NOT NULL,
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('user', 'service_account')),
    principal_id UUID NOT NULL,
    name TEXT NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    grace_expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, id)
);
CREATE INDEX IF NOT EXISTS iam_api_keys_principal_idx ON iam_api_keys (realm_id, principal_kind, principal_id, created_at);

CREATE TABLE IF NOT EXISTS iam_api_key_scopes (
    realm_id UUID NOT NULL,
    api_key_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    PRIMARY KEY (realm_id, api_key_id, permission_id),
    FOREIGN KEY (realm_id, api_key_id) REFERENCES iam_api_keys (realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, permission_id) REFERENCES iam_permissions (realm_id, id) ON DELETE RESTRICT
);

INSERT INTO sdk_schema_compatibility(singleton, schema_version, min_reader_version, min_writer_version)
VALUES(TRUE, 6, 6, 6)
ON CONFLICT(singleton) DO UPDATE SET
    schema_version = EXCLUDED.schema_version,
    min_reader_version = EXCLUDED.min_reader_version,
    min_writer_version = EXCLUDED.min_writer_version;
