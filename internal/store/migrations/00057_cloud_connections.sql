-- +goose Up
-- Cloud connections (#251, ADR-0022): a cloud key a platform admin pasted
-- into Keel, used as Keel's base identity for that provider. Platform data,
-- so rows live in the home Tenant; one connection per provider. The key
-- columns hold values sealed by internal/secrets under KEEL_SECRETS_KEY, so
-- the database never holds the plaintext. A stored key only reads.
CREATE TABLE cloud_connections (
    id                uuid PRIMARY KEY,
    tenant_id         uuid NOT NULL REFERENCES tenants (id),
    provider          text NOT NULL CHECK (provider IN ('tencent')),
    name              text NOT NULL CHECK (name <> ''),
    payer_uin         text NOT NULL CHECK (payer_uin ~ '^[0-9]{5,20}$'),
    default_region    text NOT NULL CHECK (default_region <> ''),
    org_region        text NOT NULL DEFAULT '',
    member_role       text NOT NULL DEFAULT '',
    mode              text NOT NULL DEFAULT 'read_only' CHECK (mode = 'read_only'),
    secret_id_sealed  bytea NOT NULL,
    secret_key_sealed bytea NOT NULL,
    secret_id_last4   text NOT NULL CHECK (length(secret_id_last4) = 4),
    created_at        timestamptz NOT NULL,
    created_by        text NOT NULL,
    updated_at        timestamptz NOT NULL,
    rotated_at        timestamptz,
    last_test_at      timestamptz,
    last_test_ok      boolean,
    last_test_uin     text NOT NULL DEFAULT '',  -- the account STS said the key belongs to
    last_test_detail  text NOT NULL DEFAULT '',
    UNIQUE (tenant_id, provider)
);
ALTER TABLE cloud_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cloud_connections USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT, DELETE ON cloud_connections TO keel_app;
GRANT UPDATE (name, payer_uin, default_region, org_region, member_role, secret_id_sealed, secret_key_sealed, secret_id_last4,
    updated_at, rotated_at, last_test_at, last_test_ok, last_test_uin, last_test_detail) ON cloud_connections TO keel_app;

-- +goose Down
DROP TABLE cloud_connections;
