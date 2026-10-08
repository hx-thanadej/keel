-- +goose Up
-- Break-glass (#135): the emergency identities outside SSO, their uses and drills.
-- They belong to the platform, so rows live in the home Tenant.
CREATE TABLE breakglass_identities (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    provider      text NOT NULL,
    account       text NOT NULL,          -- account the identity lives in
    principal_id  text NOT NULL,          -- CAM uin of the user
    name          text NOT NULL,          -- CAM user name
    holder        text NOT NULL,          -- who keeps the hardware key
    hardware_mfa  boolean NOT NULL,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_drill_at timestamptz,
    retired_at    timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (provider, account, principal_id)
);
CREATE TABLE breakglass_uses (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    identity_id    uuid NOT NULL,
    event_id       text NOT NULL UNIQUE,
    event_name     text NOT NULL,
    source_ip      text NOT NULL DEFAULT '',
    used_at        timestamptz NOT NULL,
    finding_id     uuid,
    postmortem_url text,
    FOREIGN KEY (tenant_id, identity_id) REFERENCES breakglass_identities (tenant_id, id)
);
ALTER TABLE breakglass_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE breakglass_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON breakglass_identities USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
ALTER TABLE breakglass_uses ENABLE ROW LEVEL SECURITY;
ALTER TABLE breakglass_uses FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON breakglass_uses USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
GRANT SELECT, INSERT ON breakglass_identities, breakglass_uses TO keel_app;
GRANT UPDATE (last_drill_at, retired_at) ON breakglass_identities TO keel_app;
GRANT UPDATE (postmortem_url, finding_id) ON breakglass_uses TO keel_app;

-- +goose Down
DROP TABLE breakglass_uses;
DROP TABLE breakglass_identities;
