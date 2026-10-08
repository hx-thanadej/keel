-- +goose Up
-- Monthly Tenant report (#152): generated on the first of each month from
-- the Tenant's own data, kept as structured data and as a self-contained
-- HTML page Tenant Members can download.
CREATE TABLE tenant_reports (
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    period       date NOT NULL CHECK (extract(day FROM period) = 1),
    generated_at timestamptz NOT NULL DEFAULT now(),
    data         jsonb NOT NULL,
    html         text NOT NULL,
    PRIMARY KEY (tenant_id, period)
);
ALTER TABLE tenant_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_reports USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON tenant_reports TO keel_app;
GRANT UPDATE (generated_at, data, html) ON tenant_reports TO keel_app;

-- +goose Down
DROP TABLE tenant_reports;
