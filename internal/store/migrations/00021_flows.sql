-- +goose Up
-- Durable multi-step flows (#87, ADR-0014): one row per run, one per step.
-- Steps are driven by River jobs enqueued in the same transaction as the
-- state change that causes them.
CREATE TABLE flows (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    kind        text NOT NULL,                 -- e.g. vend_environment
    subject     text NOT NULL,                 -- what it acts on, e.g. environment/<id>
    input       jsonb NOT NULL DEFAULT '{}',
    state       text NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'succeeded', 'failed', 'cancelling', 'cancelled')),
    error       text,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    UNIQUE (tenant_id, id)
);
-- At most one unfinished run per subject and kind: starting again returns it.
CREATE UNIQUE INDEX flows_one_active ON flows (tenant_id, kind, subject) WHERE state IN ('running', 'failed', 'cancelling');
CREATE INDEX flows_tenant_created ON flows (tenant_id, created_at DESC);

CREATE TABLE flow_steps (
    tenant_id   uuid NOT NULL,
    flow_id     uuid NOT NULL,
    seq         integer NOT NULL,
    name        text NOT NULL,
    state       text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'running', 'succeeded', 'failed', 'compensated')),
    attempts    integer NOT NULL DEFAULT 0,
    output      jsonb NOT NULL DEFAULT '{}',
    error       text,
    started_at  timestamptz,
    finished_at timestamptz,
    PRIMARY KEY (flow_id, seq),
    FOREIGN KEY (tenant_id, flow_id) REFERENCES flows (tenant_id, id)
);

ALTER TABLE flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE flows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON flows USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE flow_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON flow_steps USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT ON flows, flow_steps TO keel_app;
GRANT UPDATE (state, error, updated_at, finished_at) ON flows TO keel_app;
GRANT UPDATE (state, attempts, output, error, started_at, finished_at) ON flow_steps TO keel_app;

-- +goose Down
DROP TABLE flow_steps;
DROP TABLE flows;
