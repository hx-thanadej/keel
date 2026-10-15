-- +goose Up
-- Bill sync status (#257): the latest outcome of each payer's bill sync, so
-- the portal can say when bills were last pulled and why a month has no
-- costs. One row per payer, in the Tenant that sees its costs: the home
-- Tenant for Keel's own payers, the client's Tenant for a client payer.
-- months maps YYYY-MM to that month's latest outcome. Reasons are codes,
-- never provider messages, so no secret can land here.
CREATE TABLE bill_sync_status (
    tenant_id          uuid NOT NULL REFERENCES tenants (id),
    provider           text NOT NULL,
    billing_account_id text NOT NULL,
    source             text NOT NULL CHECK (source IN ('api', 'files')),
    checked_at         timestamptz NOT NULL,
    state              text NOT NULL CHECK (state IN ('ok', 'empty', 'blocked', 'failed')),
    reason             text NOT NULL DEFAULT '',
    code               text NOT NULL DEFAULT '',
    since              timestamptz NOT NULL,
    months             jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(months) = 'object'),
    PRIMARY KEY (tenant_id, provider, billing_account_id)
);
ALTER TABLE bill_sync_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE bill_sync_status FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON bill_sync_status USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT, UPDATE ON bill_sync_status TO keel_app;

-- +goose Down
DROP TABLE bill_sync_status;
