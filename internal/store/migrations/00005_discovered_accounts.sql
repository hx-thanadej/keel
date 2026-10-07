-- +goose Up
-- Accounts found in provider organisations (#26). Discovery is a platform
-- operation, so rows live in the home Tenant. Whether an account is already
-- registered (in any Tenant) is answered by registered_accounts(), which
-- reveals only the external ids, never which Tenant holds them.
CREATE TABLE discovered_accounts (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    provider      text NOT NULL,
    external_id   text NOT NULL,
    name          text NOT NULL,
    parent        text NOT NULL DEFAULT '',
    tags          jsonb NOT NULL DEFAULT '{}',
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, external_id)
);
ALTER TABLE discovered_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovered_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON discovered_accounts
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT, UPDATE ON discovered_accounts TO keel_app;

-- +goose StatementBegin
CREATE FUNCTION registered_accounts(p_provider text, p_external_ids text[]) RETURNS SETOF text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT external_id FROM cloud_accounts
    WHERE provider = p_provider AND external_id = ANY (p_external_ids) AND archived_at IS NULL
$$;
-- +goose StatementEnd
GRANT SELECT ON cloud_accounts TO keel_lookup;
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION registered_accounts(text, text[]) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION registered_accounts(text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION registered_accounts(text, text[]) TO keel_app;

-- +goose Down
DROP FUNCTION registered_accounts(text, text[]);
REVOKE SELECT ON cloud_accounts FROM keel_lookup;
DROP TABLE discovered_accounts;
