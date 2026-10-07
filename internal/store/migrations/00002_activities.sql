-- +goose Up
-- Activity Log (ADR-0005): one append-only table. `event` holds the full
-- CloudEvents 1.0 envelope with an OCSF API Activity (6003) payload; the other
-- columns are extracted for filtering. `seq` gives a total order used by the
-- integrity digests (#24).
CREATE TABLE activities (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    seq         bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    occurred_at timestamptz NOT NULL,
    logged_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    source      text NOT NULL,
    type        text NOT NULL,
    subject     text NOT NULL DEFAULT '',
    actor_type  text NOT NULL,
    actor_uid   text NOT NULL,
    operation   text NOT NULL,
    status_id   smallint NOT NULL,
    event       jsonb NOT NULL
);
CREATE INDEX activities_tenant_seq ON activities (tenant_id, seq DESC);
CREATE INDEX activities_tenant_actor ON activities (tenant_id, actor_uid, seq DESC);
CREATE INDEX activities_tenant_type ON activities (tenant_id, type, seq DESC);

ALTER TABLE activities ENABLE ROW LEVEL SECURITY;
ALTER TABLE activities FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON activities
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- Append-only, belt and braces: the app role gets no UPDATE/DELETE/TRUNCATE,
-- and a trigger rejects them for every role, including the owner.
-- +goose StatementBegin
CREATE FUNCTION activities_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'activities are append-only (% rejected)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END $$;
-- +goose StatementEnd
CREATE TRIGGER activities_no_update_delete BEFORE UPDATE OR DELETE ON activities
    FOR EACH ROW EXECUTE FUNCTION activities_append_only();
CREATE TRIGGER activities_no_truncate BEFORE TRUNCATE ON activities
    FOR EACH STATEMENT EXECUTE FUNCTION activities_append_only();

GRANT SELECT, INSERT ON activities TO keel_app;

-- +goose Down
DROP TABLE activities;
DROP FUNCTION activities_append_only();
