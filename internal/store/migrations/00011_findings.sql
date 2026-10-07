-- +goose Up
-- Findings: one inbox for anything a Team must act on (CONTEXT.md). Cost
-- anomalies first (#40); rightsizing (M2) and security (M4) reuse it.
CREATE TABLE findings (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    kind           text NOT NULL,
    fingerprint    text NOT NULL,              -- stable identity of "the same problem"
    severity       text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status         text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    title          text NOT NULL,
    detail         jsonb NOT NULL DEFAULT '{}',
    project_id     uuid,
    environment_id uuid,
    owner_team_id  uuid REFERENCES teams (id), -- may be a home Team delivering for a client
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    resolved_at    timestamptz,
    resolution     text
);
CREATE UNIQUE INDEX findings_one_open ON findings (tenant_id, fingerprint) WHERE status = 'open';
CREATE INDEX findings_tenant_status ON findings (tenant_id, status, kind, first_seen_at DESC);
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON findings
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON findings TO keel_app;
GRANT UPDATE (status, severity, detail, last_seen_at, resolved_at, resolution) ON findings TO keel_app;

-- +goose Down
DROP TABLE findings;
