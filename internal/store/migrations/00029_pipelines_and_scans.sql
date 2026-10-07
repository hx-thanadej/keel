-- +goose Up
-- Pipeline identity and scanner ingestion (#109).

-- Which Service(s) a repository id belongs to, across Tenants: lets a CI
-- token that names only its repository be mapped to its Tenant.
-- +goose StatementBegin
CREATE FUNCTION services_by_repository(p_repo bigint) RETURNS TABLE (tenant_id uuid, service_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT tenant_id, id FROM services WHERE repository_id = p_repo AND archived_at IS NULL
$$;
-- +goose StatementEnd
GRANT SELECT (id, tenant_id, repository_id, archived_at) ON services TO keel_lookup;
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION services_by_repository(bigint) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION services_by_repository(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION services_by_repository(bigint) TO keel_app;

ALTER TABLE findings ADD COLUMN service_id uuid;
GRANT UPDATE (service_id) ON findings TO keel_app;
CREATE INDEX findings_tenant_service ON findings (tenant_id, service_id) WHERE status = 'open';

CREATE TABLE scan_runs (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    service_id  uuid NOT NULL,
    tool        text NOT NULL,
    scope       text NOT NULL CHECK (scope IN ('full', 'diff')),
    commit_sha  text NOT NULL DEFAULT '',
    ref         text NOT NULL DEFAULT '',
    results     integer NOT NULL,
    raised      integer NOT NULL,
    resolved    integer NOT NULL,
    uploaded_by text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_runs USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON scan_runs TO keel_app;

-- +goose Down
DROP TABLE scan_runs;
ALTER TABLE findings DROP COLUMN service_id;
DROP FUNCTION services_by_repository(bigint);
