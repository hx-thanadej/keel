-- +goose Up
-- Catalog sync from catalog-info.yaml (#27).
ALTER TABLE services
    ADD COLUMN repository text NOT NULL DEFAULT '',
    ADD COLUMN lifecycle  text NOT NULL DEFAULT '',
    ADD COLUMN type       text NOT NULL DEFAULT '';

CREATE TABLE catalog_sync_runs (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),  -- always the home Tenant
    started_at  timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    report      jsonb NOT NULL
);
ALTER TABLE catalog_sync_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalog_sync_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON catalog_sync_runs
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON catalog_sync_runs TO keel_app;

-- Descriptors name Tenants by slug; Keel's own jobs need to resolve them.
-- +goose StatementBegin
CREATE FUNCTION tenant_id_by_slug(p_slug text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT id FROM tenants WHERE slug = p_slug
$$;
CREATE FUNCTION home_tenant_id() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT id FROM tenants WHERE is_home
$$;
-- +goose StatementEnd
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION tenant_id_by_slug(text) OWNER TO keel_lookup;
ALTER FUNCTION home_tenant_id() OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION tenant_id_by_slug(text), home_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_id_by_slug(text), home_tenant_id() TO keel_app;

-- +goose Down
DROP FUNCTION home_tenant_id();
DROP FUNCTION tenant_id_by_slug(text);
DROP TABLE catalog_sync_runs;
ALTER TABLE services DROP COLUMN type, DROP COLUMN lifecycle, DROP COLUMN repository;
