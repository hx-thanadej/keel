-- +goose Up
-- Activity Log integrity (#24, ADR-0005). Each Tenant has its own chain of
-- signed digests. A digest covers that Tenant's activities with
-- seq_from < seq <= seq_to: their count, a SHA-256 over them in seq order, and
-- the previous digest's signature. Edits, deletions, removed digests and late
-- inserts are detectable by integrity.Verify.
CREATE TABLE activity_digests (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    seq_from       bigint NOT NULL,          -- exclusive
    seq_to         bigint NOT NULL,          -- inclusive
    count          integer NOT NULL,
    batch_sha256   bytea NOT NULL,
    cutoff         timestamptz NOT NULL,     -- activities logged before this were eligible
    sealed_at      timestamptz NOT NULL,
    prev_signature bytea,
    key_id         text NOT NULL,
    signature      bytea NOT NULL,
    CHECK (seq_to >= seq_from)
);
CREATE INDEX activity_digests_chain ON activity_digests (tenant_id, sealed_at);

ALTER TABLE activity_digests ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_digests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON activity_digests
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE TRIGGER activity_digests_no_update_delete BEFORE UPDATE OR DELETE ON activity_digests
    FOR EACH ROW EXECUTE FUNCTION activities_append_only();
CREATE TRIGGER activity_digests_no_truncate BEFORE TRUNCATE ON activity_digests
    FOR EACH STATEMENT EXECUTE FUNCTION activities_append_only();

GRANT SELECT, INSERT ON activity_digests TO keel_app;

-- The sealer runs for every Tenant, so it needs the list of Tenant ids.
-- +goose StatementBegin
CREATE FUNCTION tenant_ids() RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT id FROM tenants ORDER BY created_at
$$;
-- +goose StatementEnd
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION tenant_ids() OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION tenant_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_ids() TO keel_app;

-- +goose Down
DROP FUNCTION tenant_ids();
DROP TABLE activity_digests;
