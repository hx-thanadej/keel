-- +goose Up
-- Cost facts (#30, ADR-0011): FOCUS-shaped lines from payer billing exports,
-- attributed to Tenant/Project/Environment by Cloud Account (ADR-0002).
--
-- Loads are never overwritten: each ingest of (provider, billing account,
-- period) is a new load whose facts become `current` only once fully written,
-- and earlier loads' facts are flipped to not current. History stays queryable.
-- A final load freezes the period.

-- Platform-level record of each load, kept in the home Tenant.
CREATE TABLE cost_loads (
    id                 uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id          uuid NOT NULL REFERENCES tenants (id),   -- home Tenant
    provider           text NOT NULL,
    billing_account_id text NOT NULL,
    billing_period     date NOT NULL CHECK (extract(day FROM billing_period) = 1),
    source             text NOT NULL DEFAULT '',
    is_final           boolean NOT NULL DEFAULT false,
    line_count         integer NOT NULL,
    total_billed       numeric NOT NULL,
    unallocated_billed numeric NOT NULL,
    currency           text NOT NULL,
    touched_tenants    uuid[] NOT NULL,                          -- Tenants with facts in this load
    loaded_at          timestamptz NOT NULL DEFAULT now(),
    superseded_at      timestamptz
);
CREATE INDEX cost_loads_period ON cost_loads (provider, billing_account_id, billing_period, loaded_at DESC);
CREATE UNIQUE INDEX cost_loads_one_final ON cost_loads (provider, billing_account_id, billing_period) WHERE is_final;

CREATE TABLE cost_facts (
    id                         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    load_id                    uuid NOT NULL REFERENCES cost_loads (id),
    tenant_id                  uuid NOT NULL REFERENCES tenants (id),
    current                    boolean NOT NULL DEFAULT false,
    provider                   text NOT NULL,
    billing_account_id         text NOT NULL,
    sub_account_id             text NOT NULL,
    cloud_account_id           uuid,
    project_id                 uuid,
    environment_id             uuid,
    allocation_method          text NOT NULL CHECK (allocation_method IN ('account', 'tag', 'k8s', 'rule', 'unallocated')),
    billing_period             date NOT NULL,
    charge_period_start        timestamptz NOT NULL,
    charge_period_end          timestamptz NOT NULL,
    charge_category            text NOT NULL,
    charge_class               text NOT NULL DEFAULT '',
    charge_frequency           text NOT NULL DEFAULT '',
    service_category           text NOT NULL DEFAULT '',
    service_name               text NOT NULL DEFAULT '',
    service_subcategory        text NOT NULL DEFAULT '',
    sku_id                     text NOT NULL DEFAULT '',
    region_id                  text NOT NULL DEFAULT '',
    availability_zone          text NOT NULL DEFAULT '',
    resource_id                text NOT NULL DEFAULT '',
    resource_name              text NOT NULL DEFAULT '',
    resource_type              text NOT NULL DEFAULT '',
    pricing_quantity           numeric,
    pricing_unit               text NOT NULL DEFAULT '',
    consumed_quantity          numeric,
    consumed_unit              text NOT NULL DEFAULT '',
    list_cost                  numeric,
    billed_cost                numeric NOT NULL,
    effective_cost             numeric,             -- may be empty at source (Tencent); derived in #32
    effective_cost_method      text NOT NULL DEFAULT 'source',
    contracted_cost            numeric,
    billing_currency           text NOT NULL,
    commitment_discount_id     text NOT NULL DEFAULT '',
    commitment_discount_type   text NOT NULL DEFAULT '',
    commitment_discount_status text NOT NULL DEFAULT '',
    tags                       jsonb NOT NULL DEFAULT '{}',
    vendor                     jsonb NOT NULL DEFAULT '{}'   -- x_ columns
);
CREATE INDEX cost_facts_tenant_day ON cost_facts (tenant_id, charge_period_start) WHERE current;
CREATE INDEX cost_facts_env_day ON cost_facts (tenant_id, environment_id, charge_period_start) WHERE current;
CREATE INDEX cost_facts_load ON cost_facts (tenant_id, provider, billing_account_id, billing_period, load_id);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['cost_loads', 'cost_facts'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id())', t);
    END LOOP;
END $$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON cost_loads, cost_facts TO keel_app;
GRANT UPDATE (superseded_at) ON cost_loads TO keel_app;
GRANT UPDATE (current) ON cost_facts TO keel_app;

-- Who owns these provider accounts? Returns ids only to Keel's own ingest.
-- +goose StatementBegin
CREATE FUNCTION account_owners(p_provider text, p_external_ids text[])
RETURNS TABLE (external_id text, tenant_id uuid, cloud_account_id uuid, environment_id uuid, project_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT a.external_id, a.tenant_id, a.id, a.environment_id, e.project_id
    FROM cloud_accounts a LEFT JOIN environments e ON e.id = a.environment_id
    WHERE a.provider = p_provider AND a.external_id = ANY (p_external_ids) AND a.archived_at IS NULL
$$;
-- +goose StatementEnd
GRANT SELECT ON environments TO keel_lookup;
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION account_owners(text, text[]) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION account_owners(text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION account_owners(text, text[]) TO keel_app;

-- +goose Down
DROP FUNCTION account_owners(text, text[]);
REVOKE SELECT ON environments FROM keel_lookup;
DROP TABLE cost_facts;
DROP TABLE cost_loads;
