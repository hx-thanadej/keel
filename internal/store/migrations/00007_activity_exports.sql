-- +goose Up
-- Which digests have been shipped to the WORM archive (#25).
CREATE TABLE activity_exports (
    digest_id   uuid PRIMARY KEY REFERENCES activity_digests (id),
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    data_key    text NOT NULL,
    digest_key  text NOT NULL,
    exported_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE activity_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_exports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON activity_exports
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON activity_exports TO keel_app;

-- +goose Down
DROP TABLE activity_exports;
