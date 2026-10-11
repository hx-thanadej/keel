-- +goose Up
-- ADR-0018 (#182): a client-owned Cloud Account can be its client's payer.
-- Keel reads that payer's bills through the account's read_only_role. A row
-- here marks the account as a payer and says where its Bill Storage delivers.
-- An empty bucket means delivery is not set up yet; the sync raises a Finding
-- in the Tenant saying what to configure. Keel never configures it.
--
-- client_payers_for joins on tenant_id as well as the account id, so a row
-- that names another Tenant's account (FK checks bypass RLS) is inert.
CREATE TABLE client_payers (
    cloud_account_id uuid PRIMARY KEY REFERENCES cloud_accounts (id),
    tenant_id        uuid NOT NULL REFERENCES tenants (id),
    bucket           text NOT NULL DEFAULT '' CHECK (bucket = '' OR (length(bucket) <= 63 AND bucket ~ '^[a-z0-9][a-z0-9-]*-[0-9]{5,20}$')),
    prefix           text NOT NULL DEFAULT '' CHECK (length(prefix) <= 1024),
    region           text NOT NULL CHECK (region ~ '^[a-z]{2,4}-[a-z]+(-[0-9]+)?$'),
    mode             text NOT NULL DEFAULT 'cumulative' CHECK (mode IN ('per-day', 'cumulative')),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE client_payers ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_payers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON client_payers
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON client_payers TO keel_app;
GRANT UPDATE (bucket, prefix, region, mode, updated_at) ON client_payers TO keel_app;
GRANT SELECT ON client_payers TO keel_lookup;

-- Every Tenant's client payers for one provider, for Keel's own bill sync.
-- +goose StatementBegin
CREATE FUNCTION client_payers_for(p_provider text)
RETURNS TABLE (tenant_id uuid, cloud_account_id uuid, external_id text, role_arn text, bucket text, prefix text, region text, mode text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT p.tenant_id, a.id, a.external_id, a.read_only_role->>'role_arn', p.bucket, p.prefix, p.region, p.mode
    FROM client_payers p JOIN cloud_accounts a ON a.id = p.cloud_account_id AND a.tenant_id = p.tenant_id
    WHERE a.provider = p_provider AND a.ownership = 'client' AND a.archived_at IS NULL
    ORDER BY a.external_id
$$;
-- +goose StatementEnd
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION client_payers_for(text) OWNER TO keel_lookup;

-- Ingest needs each account's ownership: a client payer's lines are kept only
-- for its own Tenant's client-owned accounts, and Keel's payers never
-- attribute to a client-owned account.
DROP FUNCTION account_owners(text, text[]);
-- +goose StatementBegin
CREATE FUNCTION account_owners(p_provider text, p_external_ids text[])
RETURNS TABLE (external_id text, tenant_id uuid, cloud_account_id uuid, environment_id uuid, project_id uuid, ownership text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT a.external_id, a.tenant_id, a.id, a.environment_id, e.project_id, a.ownership
    FROM cloud_accounts a LEFT JOIN environments e ON e.id = a.environment_id
    WHERE a.provider = p_provider AND a.external_id = ANY (p_external_ids) AND a.archived_at IS NULL
$$;
-- +goose StatementEnd
ALTER FUNCTION account_owners(text, text[]) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION account_owners(text, text[]), client_payers_for(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION account_owners(text, text[]), client_payers_for(text) TO keel_app;

-- Lines a load dropped because their account is not the payer Tenant's.
-- Reconciliation adds them back: the invoice covers the whole payer.
ALTER TABLE cost_loads
    ADD COLUMN dropped_lines integer NOT NULL DEFAULT 0,
    ADD COLUMN dropped_billed numeric NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE cost_loads DROP COLUMN dropped_billed, DROP COLUMN dropped_lines;
DROP FUNCTION account_owners(text, text[]);
-- +goose StatementBegin
CREATE FUNCTION account_owners(p_provider text, p_external_ids text[])
RETURNS TABLE (external_id text, tenant_id uuid, cloud_account_id uuid, environment_id uuid, project_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT a.external_id, a.tenant_id, a.id, a.environment_id, e.project_id
    FROM cloud_accounts a LEFT JOIN environments e ON e.id = a.environment_id
    WHERE a.provider = p_provider AND a.external_id = ANY (p_external_ids) AND a.archived_at IS NULL
$$;
-- +goose StatementEnd
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION account_owners(text, text[]) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION account_owners(text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION account_owners(text, text[]) TO keel_app;
DROP FUNCTION client_payers_for(text);
DROP TABLE client_payers;
