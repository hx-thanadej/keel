-- +goose Up
-- Release policy (#112): provenance verified per image, with Keel's VSA.
CREATE TABLE release_attestations (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    release_id   uuid NOT NULL,
    image_digest text NOT NULL,
    passed       boolean NOT NULL,
    checks       jsonb NOT NULL,
    certificate  jsonb NOT NULL DEFAULT '{}',
    bundle_sha256 text NOT NULL,
    vsa          jsonb NOT NULL,
    submitted_by text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, release_id) REFERENCES releases (tenant_id, id)
);
CREATE INDEX release_attestations_release ON release_attestations (release_id, image_digest, created_at DESC);
ALTER TABLE release_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE release_attestations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON release_attestations USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON release_attestations TO keel_app;

-- A Release passes when the latest attestation of every image passed.
-- +goose StatementBegin
CREATE FUNCTION release_verified(p_release uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT coalesce(bool_and(coalesce(a.passed, false)), false)
    FROM releases r
    CROSS JOIN LATERAL jsonb_array_elements(r.images) AS img
    LEFT JOIN LATERAL (
        SELECT passed FROM release_attestations x
        WHERE x.release_id = r.id AND x.image_digest = img->>'digest'
        ORDER BY created_at DESC LIMIT 1) a ON true
    WHERE r.id = p_release
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION release_verified(uuid);
DROP TABLE release_attestations;
