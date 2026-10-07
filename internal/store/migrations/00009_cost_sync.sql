-- +goose Up
-- Bill file pickup and invoice reconciliation (#32, #33).
ALTER TABLE cost_loads
    ADD COLUMN invoice_total    numeric,
    ADD COLUMN invoice_ready    boolean,
    ADD COLUMN reconcile_status text NOT NULL DEFAULT 'pending'
        CHECK (reconcile_status IN ('pending', 'ok', 'mismatch', 'not_ready', 'unavailable')),
    ADD COLUMN reconcile_diff   numeric,
    ADD COLUMN reconciled_at    timestamptz;
GRANT UPDATE (invoice_total, invoice_ready, reconcile_status, reconcile_diff, reconciled_at) ON cost_loads TO keel_app;

-- Bill files seen in a provider's delivery bucket, by billing period.
CREATE TABLE cost_source_files (
    id                 uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id          uuid NOT NULL REFERENCES tenants (id),  -- home Tenant
    provider           text NOT NULL,
    billing_account_id text NOT NULL,
    object_key         text NOT NULL,
    billing_period     date NOT NULL,
    line_count         integer NOT NULL,
    seen_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, billing_account_id, object_key, billing_period)
);
ALTER TABLE cost_source_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE cost_source_files FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cost_source_files
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON cost_source_files TO keel_app;

-- +goose Down
DROP TABLE cost_source_files;
ALTER TABLE cost_loads DROP COLUMN reconciled_at, DROP COLUMN reconcile_diff, DROP COLUMN reconcile_status,
    DROP COLUMN invoice_ready, DROP COLUMN invoice_total;
