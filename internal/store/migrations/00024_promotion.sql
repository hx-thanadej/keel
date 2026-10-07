-- +goose Up
-- Releases and Promotions (#93, ADR-0008): a Release is a set of image
-- digests for a Service; promoting it to an Environment is a pull request to
-- the Project's config repository, gated by policy.
ALTER TABLE projects ADD COLUMN config_repo text NOT NULL DEFAULT '' CHECK (config_repo = '' OR config_repo ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$');
GRANT UPDATE (config_repo) ON projects TO keel_app;
ALTER TABLE environments
    ADD COLUMN promotion_order   integer,           -- dev 1, staging 2, prod 3; NULL = not in the path
    ADD COLUMN requires_approval boolean NOT NULL DEFAULT false;
GRANT UPDATE (promotion_order, requires_approval) ON environments TO keel_app;

CREATE TABLE releases (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    service_id uuid NOT NULL,
    version    text NOT NULL,
    images     jsonb NOT NULL,          -- [{"name": "...", "digest": "sha256:..."}]
    commit_sha text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (service_id, version)
);

CREATE TABLE promotions (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    release_id     uuid NOT NULL,
    environment_id uuid NOT NULL,
    state          text NOT NULL CHECK (state IN ('denied', 'pending_approval', 'pr_open', 'merged', 'deployed', 'closed', 'failed')),
    decision       jsonb NOT NULL DEFAULT '{}',
    pr_url         text,
    error          text,
    requested_by   text NOT NULL,
    approved_by    text,
    requested_at   timestamptz NOT NULL DEFAULT now(),
    approved_at    timestamptz,
    pr_opened_at   timestamptz,
    merged_at      timestamptz,
    deployed_at    timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, release_id) REFERENCES releases (tenant_id, id),
    FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id)
);
CREATE UNIQUE INDEX promotions_one_active ON promotions (release_id, environment_id) WHERE state IN ('pending_approval', 'pr_open', 'merged');
CREATE INDEX promotions_tenant_state ON promotions (tenant_id, state, requested_at DESC);

ALTER TABLE releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE releases FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON releases USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE promotions ENABLE ROW LEVEL SECURITY;
ALTER TABLE promotions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON promotions USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON releases, promotions TO keel_app;
GRANT UPDATE (state, decision, pr_url, error, approved_by, approved_at, pr_opened_at, merged_at, deployed_at, updated_at) ON promotions TO keel_app;

-- +goose Down
DROP TABLE promotions;
DROP TABLE releases;
ALTER TABLE environments DROP COLUMN requires_approval, DROP COLUMN promotion_order;
ALTER TABLE projects DROP COLUMN config_repo;
