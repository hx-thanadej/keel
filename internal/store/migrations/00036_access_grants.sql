-- +goose Up
-- Access Grants (#133): a person holds a role in an Environment for hours.
CREATE TABLE access_grants (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    role_id      uuid NOT NULL,
    requester    text NOT NULL,                -- principal subject, e.g. user:alice@harmonyx.co
    principal_id text,                         -- Identity Center user id once resolved
    reason       text NOT NULL,
    hours        integer NOT NULL CHECK (hours BETWEEN 1 AND 12),
    state        text NOT NULL CHECK (state IN ('requested', 'active', 'denied', 'rejected', 'revoked', 'expired', 'failed')),
    decision     jsonb NOT NULL DEFAULT '{}',
    approvals    jsonb NOT NULL DEFAULT '[]',
    error        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    expires_at   timestamptz,
    ended_at     timestamptz,
    ended_by     text,
    FOREIGN KEY (tenant_id, role_id) REFERENCES access_roles (tenant_id, id)
);
CREATE INDEX access_grants_tenant_state ON access_grants (tenant_id, state, created_at DESC);
ALTER TABLE access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON access_grants USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON access_grants TO keel_app;
GRANT UPDATE (principal_id, state, approvals, error, activated_at, expires_at, ended_at, ended_by) ON access_grants TO keel_app;

-- +goose Down
DROP TABLE access_grants;
