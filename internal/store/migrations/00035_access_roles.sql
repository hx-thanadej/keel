-- +goose Up
-- Roles (#132): which Team may use which role template in which Environment.
-- Humans never hold them standing; Access Grants (#133) assign them for hours.
CREATE TABLE access_roles (
    id                 uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id          uuid NOT NULL REFERENCES tenants (id),
    environment_id     uuid NOT NULL,
    team_id            uuid NOT NULL,
    template           text NOT NULL,
    state              text NOT NULL CHECK (state IN ('requested', 'active', 'denied', 'retired')),
    decision           jsonb NOT NULL DEFAULT '{}',
    role_configuration text,          -- Cloud Identity Center role configuration id
    requested_by       text NOT NULL,
    decided_by         text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    decided_at         timestamptz,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id)
);
CREATE UNIQUE INDEX access_roles_one ON access_roles (environment_id, team_id, template) WHERE state IN ('requested', 'active');
ALTER TABLE access_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON access_roles USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON access_roles TO keel_app;
GRANT UPDATE (state, decision, role_configuration, decided_by, decided_at) ON access_roles TO keel_app;

-- +goose Down
DROP TABLE access_roles;
