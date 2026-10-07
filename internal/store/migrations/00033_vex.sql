-- +goose Up
-- VEX statements (#111, OpenVEX v0.2).
CREATE TABLE vex_statements (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id        uuid NOT NULL REFERENCES tenants (id),
    vulnerability    text NOT NULL,                 -- CVE-…, GHSA-…
    service_id       uuid NOT NULL,
    release_id       uuid,                          -- NULL: every Release of the Service
    status           text NOT NULL CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation')),
    justification    text CHECK (justification IN ('component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path',
                                                   'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist')),
    impact_statement text,
    action_statement text,
    author           text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (status <> 'not_affected' OR justification IS NOT NULL OR coalesce(impact_statement, '') <> '')
);
CREATE INDEX vex_lookup ON vex_statements (tenant_id, vulnerability, service_id, created_at DESC);
ALTER TABLE vex_statements ENABLE ROW LEVEL SECURITY;
ALTER TABLE vex_statements FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON vex_statements USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON vex_statements TO keel_app;

-- The latest Service-wide statement decides; not_affected and fixed suppress.
-- +goose StatementBegin
CREATE FUNCTION vex_suppressed(p_vuln text, p_service uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT coalesce((SELECT status IN ('not_affected', 'fixed') FROM vex_statements
                     WHERE vulnerability = p_vuln AND service_id = p_service AND release_id IS NULL
                     ORDER BY created_at DESC LIMIT 1), false)
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION vex_suppressed(text, uuid);
DROP TABLE vex_statements;
