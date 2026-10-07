-- +goose Up
-- Daily utilisation summaries: the evidence behind rightsizing (#68).
CREATE TABLE utilisation_daily (
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    provider       text NOT NULL,          -- k8s | tencent | aws
    resource_id    text NOT NULL,          -- k8s: cluster/namespace/workload/container
    resource_type  text NOT NULL,          -- k8s_container | vm | db
    metric         text NOT NULL,          -- cpu_cores | memory_bytes | cpu_pct | memory_pct
    day            date NOT NULL,
    p50            double precision NOT NULL,
    p95            double precision NOT NULL,
    p99            double precision NOT NULL,
    max            double precision NOT NULL,
    samples        integer NOT NULL,
    request        double precision,       -- k8s: current request in the metric's unit
    capacity       double precision,       -- vm: provisioned capacity
    project_id     uuid,
    environment_id uuid,
    labels         jsonb NOT NULL DEFAULT '{}',
    collected_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, provider, resource_id, metric, day)
);
ALTER TABLE utilisation_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE utilisation_daily FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON utilisation_daily
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON utilisation_daily TO keel_app;
GRANT UPDATE (p50, p95, p99, max, samples, request, capacity, project_id, environment_id, labels, collected_at) ON utilisation_daily TO keel_app;

-- +goose Down
DROP TABLE utilisation_daily;
