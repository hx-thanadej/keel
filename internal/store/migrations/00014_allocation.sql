-- +goose Up
-- Shared-cost allocation (#35). All rules live in the home Tenant; the facts
-- they produce land in the target Tenants.
CREATE TABLE allocation_rules (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),   -- home Tenant
    provider       text NOT NULL,
    sub_account_id text NOT NULL,
    service_name   text,                                    -- NULL = every service in the account
    kind           text NOT NULL CHECK (kind IN ('weights', 'k8s')),
    shares         jsonb NOT NULL DEFAULT '[]',              -- weights: [{tenant_id, project_id, environment_id, weight}]
    cluster        text,                                    -- k8s: cluster whose namespace costs drive the split
    created_at     timestamptz NOT NULL DEFAULT now(),
    archived_at    timestamptz,
    CHECK ((kind = 'k8s') = (cluster IS NOT NULL))
);
CREATE UNIQUE INDEX allocation_rules_one ON allocation_rules (provider, sub_account_id, coalesce(service_name, '')) WHERE archived_at IS NULL;

CREATE TABLE k8s_namespace_scopes (
    tenant_id        uuid NOT NULL REFERENCES tenants (id), -- home Tenant
    cluster          text NOT NULL,
    namespace        text NOT NULL,
    target_tenant_id uuid NOT NULL REFERENCES tenants (id),
    project_id       uuid NOT NULL,
    environment_id   uuid,
    PRIMARY KEY (cluster, namespace)
);

CREATE TABLE k8s_namespace_costs (
    tenant_id uuid NOT NULL REFERENCES tenants (id),        -- home Tenant
    cluster   text NOT NULL,
    day       date NOT NULL,
    namespace text NOT NULL,
    cost      double precision NOT NULL CHECK (cost >= 0),  -- a share weight, not money
    PRIMARY KEY (cluster, day, namespace)
);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['allocation_rules', 'k8s_namespace_scopes', 'k8s_namespace_costs'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id())', t);
    END LOOP;
END $$;

CREATE FUNCTION scope_by_path(p_tenant text, p_project text, p_env text)
RETURNS TABLE (tenant_id uuid, project_id uuid, environment_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT t.id, p.id, e.id
    FROM tenants t JOIN projects p ON p.tenant_id = t.id AND p.slug = p_project AND p.archived_at IS NULL
    LEFT JOIN environments e ON e.project_id = p.id AND e.name = p_env AND e.archived_at IS NULL
    WHERE t.slug = p_tenant AND (p_env IS NULL OR p_env = '' OR e.id IS NOT NULL)
$$;

CREATE FUNCTION project_owner(p_project uuid, p_env uuid)
RETURNS TABLE (tenant_id uuid, env_ok boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT p.tenant_id, p_env IS NULL OR EXISTS (SELECT 1 FROM environments e WHERE e.id = p_env AND e.project_id = p.id)
    FROM projects p WHERE p.id = p_project
$$;
-- +goose StatementEnd
GRANT SELECT ON projects TO keel_lookup;
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION scope_by_path(text, text, text) OWNER TO keel_lookup;
ALTER FUNCTION project_owner(uuid, uuid) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION scope_by_path(text, text, text), project_owner(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scope_by_path(text, text, text), project_owner(uuid, uuid) TO keel_app;

GRANT SELECT, INSERT ON allocation_rules, k8s_namespace_scopes, k8s_namespace_costs TO keel_app;
GRANT UPDATE (archived_at) ON allocation_rules TO keel_app;
GRANT UPDATE (target_tenant_id, project_id, environment_id) ON k8s_namespace_scopes TO keel_app;
GRANT UPDATE (cost) ON k8s_namespace_costs TO keel_app;

-- +goose Down
DROP FUNCTION project_owner(uuid, uuid);
DROP FUNCTION scope_by_path(text, text, text);
REVOKE SELECT ON projects FROM keel_lookup;
DROP TABLE k8s_namespace_costs, k8s_namespace_scopes, allocation_rules;
