-- +goose Up
-- Webhook deliveries already processed (#136): replays are ignored.
-- Platform data, kept in the home Tenant.
CREATE TABLE webhook_deliveries (
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    source      text NOT NULL,
    delivery_id text NOT NULL,
    event       text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source, delivery_id)
);
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON webhook_deliveries USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON webhook_deliveries TO keel_app;

-- +goose Down
DROP TABLE webhook_deliveries;
