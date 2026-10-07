-- +goose Up
-- Exceptions (#108): approved, time-boxed permission for Findings to stand.
CREATE TABLE exceptions (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    project_id   uuid,
    finding_ids  uuid[] NOT NULL DEFAULT '{}',
    fingerprint  text NOT NULL DEFAULT '',        -- prefix match on findings.fingerprint, e.g. "vuln:CVE-2026-1234:"
    reason       text NOT NULL CHECK (length(reason) >= 10),
    state        text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested', 'approved', 'rejected', 'expired', 'revoked')),
    requested_by text NOT NULL,
    decided_by   text,
    decision_note text,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    decided_at   timestamptz,
    CHECK (cardinality(finding_ids) > 0 OR fingerprint <> '')
);
CREATE INDEX exceptions_tenant_state ON exceptions (tenant_id, state, expires_at);
ALTER TABLE exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE exceptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON exceptions USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON exceptions TO keel_app;
GRANT UPDATE (state, decided_by, decision_note, decided_at) ON exceptions TO keel_app;

-- A Finding is excepted while an approved, unexpired Exception covers it.
-- +goose StatementBegin
CREATE FUNCTION finding_excepted(f findings) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM exceptions e
        WHERE e.tenant_id = f.tenant_id AND e.state = 'approved' AND e.expires_at > now()
          AND (e.project_id IS NULL OR e.project_id = f.project_id)
          AND (f.id = ANY (e.finding_ids) OR (e.fingerprint <> '' AND starts_with(f.fingerprint, e.fingerprint))))
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION finding_excepted(findings);
DROP TABLE exceptions;
