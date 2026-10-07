-- +goose Up
-- Sign-in (#21, #22). Every Tenant, the home Tenant included, signs in through
-- its own OIDC identity providers. IdP groups map to role Bindings.
CREATE TABLE identity_providers (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id         uuid NOT NULL REFERENCES tenants (id),
    issuer            text NOT NULL UNIQUE CHECK (issuer ~ '^https?://'),
    client_id         text NOT NULL,
    -- Name of the secret holding the client secret (env var / secret store
    -- key). The secret itself is never stored here.
    client_secret_ref text NOT NULL,
    groups_claim      text NOT NULL DEFAULT 'groups',
    -- Optional: only accept users whose verified email is in this domain.
    email_domain      text,
    archived_at       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE idp_group_roles (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id        uuid NOT NULL,
    idp_id           uuid NOT NULL,
    group_name       text NOT NULL,
    role             text NOT NULL CHECK (role IN ('platform_admin', 'security_lead', 'finops_lead', 'team_lead', 'engineer', 'tenant_viewer', 'tenant_approver')),
    -- The Tenant the role applies in. Home staff are bound into client Tenants;
    -- a client IdP may only bind into its own Tenant (trigger below).
    target_tenant_id uuid NOT NULL REFERENCES tenants (id),
    team_ids         uuid[] NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers (tenant_id, id),
    UNIQUE (idp_id, group_name, role, target_tenant_id)
);

-- +goose StatementBegin
CREATE FUNCTION idp_group_roles_same_tenant() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF NEW.target_tenant_id <> NEW.tenant_id
       AND NOT (SELECT is_home FROM tenants WHERE id = NEW.tenant_id) THEN
        RAISE EXCEPTION 'a client Tenant''s identity provider can only grant roles in that Tenant'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER idp_group_roles_same_tenant BEFORE INSERT OR UPDATE ON idp_group_roles
    FOR EACH ROW EXECUTE FUNCTION idp_group_roles_same_tenant();

CREATE TABLE sessions (
    id_hash    bytea PRIMARY KEY,             -- sha256 of the cookie token
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    principal  jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX sessions_tenant ON sessions (tenant_id, created_at DESC);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['identity_providers', 'idp_group_roles', 'sessions'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id())', t);
    END LOOP;
END $$;
-- +goose StatementEnd

-- Pre-authentication lookups. Authentication happens before any Tenant is
-- known, so these narrow SECURITY DEFINER functions are the only way to read
-- across Tenants, and they return only what sign-in needs.
-- +goose StatementBegin
CREATE FUNCTION idp_lookup(p_tenant_slug text, p_issuer text)
RETURNS TABLE (id uuid, tenant_id uuid, tenant_is_home boolean, issuer text, client_id text,
               client_secret_ref text, groups_claim text, email_domain text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT i.id, i.tenant_id, t.is_home, i.issuer, i.client_id, i.client_secret_ref, i.groups_claim, i.email_domain
    FROM identity_providers i JOIN tenants t ON t.id = i.tenant_id
    WHERE i.archived_at IS NULL
      AND (p_tenant_slug IS NULL OR t.slug = p_tenant_slug)
      AND (p_issuer IS NULL OR i.issuer = p_issuer)
    ORDER BY i.created_at
    LIMIT 1
$$;

CREATE FUNCTION idp_bindings(p_idp_id uuid, p_groups text[])
RETURNS TABLE (role text, target_tenant_id uuid, team_ids uuid[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT role, target_tenant_id, team_ids FROM idp_group_roles
    WHERE idp_id = p_idp_id AND group_name = ANY (p_groups)
    ORDER BY role, target_tenant_id
$$;

CREATE FUNCTION session_lookup(p_id_hash bytea)
RETURNS TABLE (tenant_id uuid, principal jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT tenant_id, principal FROM sessions
    WHERE id_hash = p_id_hash AND revoked_at IS NULL AND expires_at > now()
$$;
-- +goose StatementEnd
-- FORCE RLS applies to table owners too, so these functions are owned by
-- keel_lookup, a NOLOGIN role with BYPASSRLS whose only privileges are SELECT
-- on the tables they read (db/roles.sql). Nothing else bypasses RLS.
GRANT SELECT ON tenants, identity_providers, idp_group_roles, sessions TO keel_lookup;
-- Owning a function requires CREATE on its schema; grant it only for the transfer.
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION idp_lookup(text, text) OWNER TO keel_lookup;
ALTER FUNCTION idp_bindings(uuid, text[]) OWNER TO keel_lookup;
ALTER FUNCTION session_lookup(bytea) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION idp_lookup(text, text), idp_bindings(uuid, text[]), session_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION idp_lookup(text, text), idp_bindings(uuid, text[]), session_lookup(bytea) TO keel_app;

GRANT SELECT, INSERT, UPDATE ON identity_providers, idp_group_roles TO keel_app;
GRANT SELECT, INSERT ON sessions TO keel_app;
GRANT UPDATE (revoked_at) ON sessions TO keel_app;

-- +goose Down
REVOKE SELECT ON tenants FROM keel_lookup;
DROP FUNCTION session_lookup(bytea);
DROP FUNCTION idp_bindings(uuid, text[]);
DROP FUNCTION idp_lookup(text, text);
DROP TABLE sessions, idp_group_roles, identity_providers;
DROP FUNCTION idp_group_roles_same_tenant();
