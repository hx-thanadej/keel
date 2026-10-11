-- +goose Up
-- PDPA (#190, ADR-0017). A Tenant's data region set, whether the retention
-- job may delete, and a legal hold. No row means the platform defaults: the
-- configured region set, deletion off, no hold.
CREATE TABLE pdpa_settings (
    tenant_id        uuid PRIMARY KEY REFERENCES tenants (id),
    data_regions     text[] NOT NULL CHECK (cardinality(data_regions) > 0),
    deletion_enabled boolean NOT NULL DEFAULT false,
    legal_hold       text NOT NULL DEFAULT '',  -- the reason; empty means no hold
    updated_at       timestamptz NOT NULL,
    updated_by       text NOT NULL
);

-- A personal data breach and its 72-hour clock to notify the PDPC:
-- declared → warning → deadline, ended by notified or closed.
CREATE TABLE pdpa_breaches (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    title          text NOT NULL CHECK (title <> ''),
    description    text NOT NULL DEFAULT '',
    state          text NOT NULL DEFAULT 'declared' CHECK (state IN ('declared', 'warning', 'deadline', 'notified', 'closed')),
    aware_at       timestamptz NOT NULL,
    declared_at    timestamptz NOT NULL,
    declared_by    text NOT NULL,
    notified_at    timestamptz,
    pdpc_reference text NOT NULL DEFAULT '',
    close_reason   text NOT NULL DEFAULT '',
    ended_at       timestamptz,
    ended_by       text NOT NULL DEFAULT '',
    CHECK ((state IN ('notified', 'closed')) = (ended_at IS NOT NULL)),
    CHECK ((state = 'notified') = (notified_at IS NOT NULL AND pdpc_reference <> '')),
    CHECK ((state = 'closed') = (close_reason <> ''))
);
CREATE INDEX pdpa_breaches_open ON pdpa_breaches (tenant_id, aware_at) WHERE state IN ('declared', 'warning', 'deadline');

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['pdpa_settings', 'pdpa_breaches'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id())', t);
    END LOOP;
END $$;
-- +goose StatementEnd
GRANT SELECT, INSERT ON pdpa_settings, pdpa_breaches TO keel_app;
GRANT UPDATE (data_regions, deletion_enabled, legal_hold, updated_at, updated_by) ON pdpa_settings TO keel_app;
GRANT UPDATE (state, notified_at, pdpc_reference, close_reason, ended_at, ended_by) ON pdpa_breaches TO keel_app;

-- The retention job deletes expired rows of these data classes, still under
-- RLS. The Activity Log and its digests stay append-only.
GRANT DELETE ON findings, cost_facts, tenant_reports, utilisation_daily, webhook_deliveries, sessions TO keel_app;

-- +goose Down
REVOKE DELETE ON findings, cost_facts, tenant_reports, utilisation_daily, webhook_deliveries, sessions FROM keel_app;
DROP TABLE pdpa_breaches;
DROP TABLE pdpa_settings;
