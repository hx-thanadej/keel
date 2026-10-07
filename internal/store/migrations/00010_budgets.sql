-- +goose Up
-- Budgets (#36, #37) and currency (#43, ADR-0012).
ALTER TABLE tenants ADD COLUMN currency text NOT NULL DEFAULT 'USD' CHECK (currency IN ('USD', 'THB'));
GRANT UPDATE (currency, name) ON tenants TO keel_app;

-- Daily reference rates, units per 1 EUR (ECB). Platform data in the home Tenant.
CREATE TABLE fx_rates (
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    day       date NOT NULL,
    currency  text NOT NULL,
    per_eur   numeric NOT NULL CHECK (per_eur > 0),
    source    text NOT NULL DEFAULT 'ecb',
    PRIMARY KEY (day, currency)
);

-- Convert using the latest rate on or before day (ECB skips weekends/holidays).
-- NULL when either currency has no rate yet.
-- +goose StatementBegin
CREATE FUNCTION fx_convert(p_amount numeric, p_from text, p_to text, p_day date) RETURNS numeric
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT CASE WHEN p_from = p_to THEN p_amount ELSE
        p_amount
        * (SELECT per_eur FROM fx_rates WHERE currency = p_to AND day <= p_day ORDER BY day DESC LIMIT 1)
        / (SELECT per_eur FROM fx_rates WHERE currency = p_from AND day <= p_day ORDER BY day DESC LIMIT 1)
    END
$$;

-- Which (provider, month) periods have a final load. No account ids exposed.
CREATE FUNCTION cost_periods_final(p_since date) RETURNS TABLE (provider text, billing_period date)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT DISTINCT provider, billing_period FROM cost_loads WHERE is_final AND billing_period >= p_since
$$;
-- +goose StatementEnd
GRANT SELECT ON fx_rates, cost_loads TO keel_lookup;
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION fx_convert(numeric, text, text, date) OWNER TO keel_lookup;
ALTER FUNCTION cost_periods_final(date) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION fx_convert(numeric, text, text, date), cost_periods_final(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fx_convert(numeric, text, text, date), cost_periods_final(date) TO keel_app;

CREATE TABLE budgets (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id       uuid NOT NULL REFERENCES tenants (id),
    project_id      uuid NOT NULL,
    environment_id  uuid,                        -- NULL = whole Project
    provider        text,                        -- NULL = all providers
    name            text NOT NULL,
    year            integer NOT NULL CHECK (year BETWEEN 2000 AND 2100),
    amount          numeric NOT NULL CHECK (amount > 0),
    currency        text NOT NULL CHECK (currency IN ('USD', 'THB')),
    monthly_weights numeric[] CHECK (monthly_weights IS NULL OR (cardinality(monthly_weights) = 12 AND 0 < ALL (monthly_weights) IS NOT FALSE)),
    cost_basis      text NOT NULL DEFAULT 'effective' CHECK (cost_basis IN ('effective', 'billed')),
    thresholds      jsonb NOT NULL DEFAULT '[{"pct":80,"basis":"actual"},{"pct":100,"basis":"actual"},{"pct":100,"basis":"forecast"}]',
    webhook_url     text CHECK (webhook_url IS NULL OR webhook_url LIKE 'https://%'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    archived_at     timestamptz,
    FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id),
    FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX budgets_one_per_scope ON budgets (project_id, coalesce(environment_id, '00000000-0000-0000-0000-000000000000'), coalesce(provider, ''), year) WHERE archived_at IS NULL;

CREATE TABLE budget_alerts (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL,
    budget_id     uuid NOT NULL,
    month         date NOT NULL,
    pct           numeric NOT NULL,
    basis         text NOT NULL CHECK (basis IN ('actual', 'forecast')),
    value         numeric NOT NULL,
    budget_amount numeric NOT NULL,
    crossed_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, budget_id) REFERENCES budgets (tenant_id, id),
    UNIQUE (budget_id, month, pct, basis)
);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['fx_rates', 'budgets', 'budget_alerts'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id())', t);
    END LOOP;
END $$;
-- +goose StatementEnd
GRANT SELECT, INSERT ON fx_rates, budget_alerts TO keel_app;
GRANT SELECT, INSERT, UPDATE ON budgets TO keel_app;

-- +goose Down
DROP TABLE budget_alerts, budgets;
DROP FUNCTION cost_periods_final(date);
DROP FUNCTION fx_convert(numeric, text, text, date);
DROP TABLE fx_rates;
ALTER TABLE tenants DROP COLUMN currency;
