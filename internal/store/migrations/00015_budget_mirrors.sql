-- +goose Up
-- Native provider budgets mirroring Keel Budgets (#39, ADR-0012).
ALTER TABLE budgets ADD COLUMN mirror_native boolean NOT NULL DEFAULT false;
GRANT UPDATE (mirror_native) ON budgets TO keel_app;

CREATE TABLE budget_mirrors (
    tenant_id  uuid NOT NULL,
    budget_id  uuid NOT NULL,
    provider   text NOT NULL,
    native_id  text NOT NULL,
    spec       jsonb NOT NULL,          -- what Keel last wrote
    synced_at  timestamptz NOT NULL DEFAULT now(),
    last_drift text,
    deleted_at timestamptz,
    PRIMARY KEY (budget_id, provider),
    FOREIGN KEY (tenant_id, budget_id) REFERENCES budgets (tenant_id, id)
);
ALTER TABLE budget_mirrors ENABLE ROW LEVEL SECURITY;
ALTER TABLE budget_mirrors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON budget_mirrors
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON budget_mirrors TO keel_app;
GRANT UPDATE (native_id, spec, synced_at, last_drift, deleted_at) ON budget_mirrors TO keel_app;

-- +goose Down
DROP TABLE budget_mirrors;
ALTER TABLE budgets DROP COLUMN mirror_native;
