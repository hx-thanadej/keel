-- +goose Up
-- Platform maturity self-assessment (#154): one per Tenant per quarter.
CREATE TABLE maturity_assessments (
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    quarter      text NOT NULL CHECK (quarter ~ '^\d{4}-Q[1-4]$'),
    version      text NOT NULL,
    answers      jsonb NOT NULL,
    indicators   jsonb NOT NULL,
    submitted_by text NOT NULL,
    submitted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, quarter)
);
ALTER TABLE maturity_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE maturity_assessments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON maturity_assessments USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON maturity_assessments TO keel_app;
GRANT UPDATE (version, answers, indicators, submitted_by, submitted_at) ON maturity_assessments TO keel_app;

-- +goose Down
DROP TABLE maturity_assessments;
