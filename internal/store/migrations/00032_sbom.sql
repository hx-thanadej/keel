-- +goose Up
-- SBOMs per Release and their components (#110).
CREATE TABLE release_sboms (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    release_id    uuid NOT NULL,
    format        text NOT NULL,      -- CycloneDX | SPDX
    spec_version  text NOT NULL,
    tool          text NOT NULL DEFAULT '',
    components    integer NOT NULL,
    gaps          jsonb NOT NULL DEFAULT '[]', -- CISA 2026 minimum elements not met
    submitted_by  text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, release_id) REFERENCES releases (tenant_id, id)
);
CREATE TABLE release_components (
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    release_id uuid NOT NULL,
    purl       text NOT NULL,
    name       text NOT NULL,
    version    text NOT NULL DEFAULT '',
    ecosystem  text NOT NULL DEFAULT '',
    PRIMARY KEY (release_id, purl),
    FOREIGN KEY (tenant_id, release_id) REFERENCES releases (tenant_id, id)
);
CREATE INDEX release_components_name ON release_components (tenant_id, name);
ALTER TABLE release_sboms ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_sboms FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON release_sboms USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE release_components ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_components FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON release_components USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON release_sboms, release_components TO keel_app;

-- +goose Down
DROP TABLE release_components;
DROP TABLE release_sboms;
