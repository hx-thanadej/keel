-- +goose Up
-- Rightsizing Recommendations (#67, ADR-0013): one record for every source.
CREATE TABLE recommendations (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id       uuid NOT NULL REFERENCES tenants (id),
    fingerprint     text NOT NULL,              -- provider|resource|action: identity of "the same advice"
    source          text NOT NULL,              -- engine:k8s | engine:vm | native:aws_coh | ...
    provider        text NOT NULL,
    account_id      text NOT NULL DEFAULT '',
    region          text NOT NULL DEFAULT '',
    resource_id     text NOT NULL,
    resource_type   text NOT NULL,
    project_id      uuid,
    environment_id  uuid,
    action          text NOT NULL,
    current         jsonb NOT NULL DEFAULT '{}',
    recommended     jsonb NOT NULL DEFAULT '{}',
    evidence        jsonb NOT NULL DEFAULT '{}',
    monthly_savings numeric NOT NULL,
    currency        text NOT NULL,
    savings_basis   text NOT NULL DEFAULT 'effective',
    confidence      numeric NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    risk            jsonb NOT NULL DEFAULT '{}',
    state           text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'accepted', 'applied', 'dismissed', 'superseded')),
    finding_id      uuid REFERENCES findings (id),
    decided_by      text,
    decision_reason text,
    pr_url          text,
    generated_at    timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX recommendations_one_live ON recommendations (tenant_id, fingerprint) WHERE state IN ('open', 'accepted');
CREATE INDEX recommendations_tenant_state ON recommendations (tenant_id, state, monthly_savings DESC);
ALTER TABLE recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE recommendations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON recommendations
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON recommendations TO keel_app;
GRANT UPDATE (state, monthly_savings, evidence, confidence, finding_id, decided_by, decision_reason, pr_url, updated_at) ON recommendations TO keel_app;

-- +goose Down
DROP TABLE recommendations;
