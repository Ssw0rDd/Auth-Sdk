ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

CREATE TABLE federated_identities (
    realm_id UUID NOT NULL,
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    provider_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    verified_email TEXT NOT NULL,
    normalized_verified_email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, issuer, subject),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX federated_identity_user_idx
    ON federated_identities (realm_id, user_id, revoked_at, created_at DESC);

CREATE TABLE federated_link_challenges (
    realm_id UUID NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    user_id UUID NOT NULL,
    identity_id UUID NOT NULL,
    provider_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    verified_email TEXT NOT NULL,
    normalized_verified_email TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (realm_id, digest),
    FOREIGN KEY (realm_id, user_id) REFERENCES users (realm_id, id) ON DELETE CASCADE
);
CREATE INDEX federated_link_user_idx
    ON federated_link_challenges (realm_id, user_id, consumed_at, created_at DESC);
CREATE INDEX federated_link_identity_idx
    ON federated_link_challenges (realm_id, issuer, subject, consumed_at);

INSERT INTO sdk_schema_compatibility(singleton, schema_version, min_reader_version, min_writer_version)
VALUES(TRUE, 7, 7, 7)
ON CONFLICT(singleton) DO UPDATE SET
    schema_version = EXCLUDED.schema_version,
    min_reader_version = EXCLUDED.min_reader_version,
    min_writer_version = EXCLUDED.min_writer_version;
