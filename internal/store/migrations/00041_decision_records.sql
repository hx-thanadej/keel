-- +goose Up
-- Decision Record index (#150): MADR files across Service repositories.
CREATE TABLE decision_records (
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    service_id    uuid NOT NULL,
    path          text NOT NULL,
    number        integer,
    title         text NOT NULL,
    status        text NOT NULL,
    decided_on    text NOT NULL DEFAULT '',
    superseded_by text NOT NULL DEFAULT '',
    url           text NOT NULL,
    indexed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (service_id, path)
);
CREATE INDEX decision_records_title ON decision_records (tenant_id, lower(title));
ALTER TABLE decision_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON decision_records USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON decision_records TO keel_app;
GRANT UPDATE (number, title, status, decided_on, superseded_by, url, indexed_at) ON decision_records TO keel_app;

-- +goose Down
DROP TABLE decision_records;
