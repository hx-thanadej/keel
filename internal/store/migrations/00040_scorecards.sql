-- +goose Up
-- Scorecards (#149): a daily snapshot per Service for trends.
CREATE TABLE scorecard_snapshots (
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    service_id uuid NOT NULL,
    day        date NOT NULL,
    version    text NOT NULL,
    score      integer NOT NULL CHECK (score BETWEEN 0 AND 100),
    checks     jsonb NOT NULL,
    PRIMARY KEY (service_id, day)
);
ALTER TABLE scorecard_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE scorecard_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scorecard_snapshots USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON scorecard_snapshots TO keel_app;
GRANT UPDATE (version, score, checks) ON scorecard_snapshots TO keel_app;

-- +goose Down
DROP TABLE scorecard_snapshots;
