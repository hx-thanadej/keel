-- +goose Up
-- Tenancy spine: Tenant → Project → Environment → Cloud Account, plus Teams
-- and Services (CONTEXT.md, ADR-0001, ADR-0002).
--
-- Isolation model:
--   * every table carries tenant_id and has RLS ENABLED and FORCED;
--   * the policy compares against the transaction-local setting
--     keel.tenant_id, which Store.InTenant sets; unset ⇒ zero rows (fail closed);
--   * children reference parents by (tenant_id, id), so a child can never
--     point at another Tenant's parent even through the FK.
--
-- Teams belong to the Tenant whose people they are. A Project may be delivered
-- by a Team of the home Tenant: projects.team_id is the one deliberate
-- cross-Tenant reference and is a plain FK on id.

CREATE FUNCTION current_tenant_id() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT nullif(current_setting('keel.tenant_id', true), '')::uuid $$;

CREATE TABLE tenants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name       text NOT NULL,
    is_home    boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- At most one home Tenant (the operating company).
CREATE UNIQUE INDEX tenants_one_home ON tenants (is_home) WHERE is_home;

CREATE TABLE teams (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    slug       text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug),
    UNIQUE (tenant_id, id)
);

CREATE TABLE projects (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    team_id     uuid NOT NULL REFERENCES teams (id),
    slug        text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name        text NOT NULL,
    archived_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug),
    UNIQUE (tenant_id, id)
);

CREATE TABLE environments (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL,
    project_id  uuid NOT NULL,
    name        text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,30}$'),
    archived_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id),
    UNIQUE (project_id, name),
    UNIQUE (tenant_id, id)
);

CREATE TABLE cloud_accounts (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    -- NULL = platform-owned account (shared tooling, logging, billing ingest).
    environment_id uuid,
    provider       text NOT NULL CHECK (provider IN ('tencent', 'aws', 'gcp', 'azure', 'alibaba')),
    external_id    text NOT NULL,
    name           text NOT NULL,
    archived_at    timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id),
    -- A provider account exists once in the world, so this is global. It does
    -- reveal that an external id is already registered; accepted (ids are not secret).
    UNIQUE (provider, external_id),
    -- ADR-0002: one dedicated Cloud Account per Environment per provider.
    UNIQUE (environment_id, provider)
);

CREATE TABLE services (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL,
    project_id  uuid NOT NULL,
    team_id     uuid NOT NULL REFERENCES teams (id),
    slug        text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name        text NOT NULL,
    archived_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id),
    UNIQUE (project_id, slug)
);

-- RLS: enabled and forced on every table, one policy each.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
    USING (id = current_tenant_id()) WITH CHECK (id = current_tenant_id());

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['teams', 'projects', 'environments', 'cloud_accounts', 'services'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id())', t);
    END LOOP;
END $$;
-- +goose StatementEnd

-- Creating a Tenant is the one write that cannot happen inside a Tenant's
-- context. This function scopes the transaction to the new id just for the
-- insert, then clears it. Only roles granted EXECUTE can call it.
-- +goose StatementBegin
CREATE FUNCTION create_tenant(p_slug text, p_name text, p_is_home boolean) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE new_id uuid := gen_random_uuid();
BEGIN
    PERFORM set_config('keel.tenant_id', new_id::text, true);
    INSERT INTO tenants (id, slug, name, is_home) VALUES (new_id, p_slug, p_name, p_is_home);
    PERFORM set_config('keel.tenant_id', '', true);
    RETURN new_id;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION create_tenant(text, text, boolean) FROM PUBLIC;

-- The application role: data access only, never owner, never BYPASSRLS.
GRANT SELECT, INSERT, UPDATE ON tenants, teams, projects, environments, cloud_accounts, services TO keel_app;
GRANT EXECUTE ON FUNCTION create_tenant(text, text, boolean) TO keel_app;

-- +goose Down
DROP FUNCTION create_tenant(text, text, boolean);
DROP TABLE services, cloud_accounts, environments, projects, teams, tenants;
DROP FUNCTION current_tenant_id();
