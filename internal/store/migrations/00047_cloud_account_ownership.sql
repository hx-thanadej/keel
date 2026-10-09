-- +goose Up
-- ADR-0018 (#181): a Cloud Account is platform-owned (vended and governed by
-- Keel) or client-owned (in the Tenant's own organisation, where Keel holds
-- only a read-only role). This is unrelated to environment_id being NULL,
-- which 00001 calls "platform-owned" in the sense of not serving one
-- Environment.
--
-- read_only_role names the role the client granted. It is a reference, never
-- a credential: Keel assumes it keylessly (ADR-0007). Its keys depend on the
-- provider:
--   tencent, aws, alibaba: role_arn
--   azure:                 tenant_id, client_id
--   gcp:                   workload_identity_provider, service_account
-- read_only_role_ok mirrors checkOwnership in internal/catalog/ownership.go
-- (TestOwnershipValidatorsAgree holds them together): exactly the provider's
-- keys, each a string of at most 1024 characters matching its format, so a
-- writer that bypasses the API still cannot store a secret here. Every branch
-- is coalesced to false because a NULL CHECK result counts as a pass.

-- +goose StatementBegin
CREATE FUNCTION read_only_role_ok(p_provider text, r jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN jsonb_typeof(r) IS DISTINCT FROM 'object' THEN false ELSE coalesce(
        NOT EXISTS (SELECT 1 FROM jsonb_each(r) e WHERE jsonb_typeof(e.value) <> 'string' OR length(e.value #>> '{}') > 1024)
        AND (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(r) k) = CASE p_provider
            WHEN 'azure' THEN ARRAY['client_id', 'tenant_id']
            WHEN 'gcp' THEN ARRAY['service_account', 'workload_identity_provider']
            ELSE ARRAY['role_arn'] END
        AND CASE p_provider
            WHEN 'tencent' THEN r->>'role_arn' ~ '^qcs::cam::uin/[0-9]{1,20}:roleName/[A-Za-z0-9_+=,.@-]{1,128}$'
            WHEN 'aws' THEN r->>'role_arn' ~ '^arn:aws(-cn|-us-gov)?:iam::[0-9]{12}:role/([A-Za-z0-9_+=,.@-]{1,128}/)*[A-Za-z0-9_+=,.@-]{1,64}$'
            WHEN 'alibaba' THEN r->>'role_arn' ~ '^acs:ram::[0-9]{1,20}:role/[A-Za-z0-9_.-]{1,64}$'
            WHEN 'azure' THEN r->>'tenant_id' ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                AND r->>'client_id' ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
            WHEN 'gcp' THEN r->>'workload_identity_provider' ~ '^projects/[0-9]{1,20}/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$'
                AND r->>'service_account' ~ '^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$'
            ELSE false END,
        false) END
$$;
-- +goose StatementEnd

-- Existing accounts were all vended or registered in our organisation.
ALTER TABLE cloud_accounts
    ADD COLUMN ownership text NOT NULL DEFAULT 'platform' CHECK (ownership IN ('platform', 'client')),
    ADD COLUMN read_only_role jsonb,
    ADD CONSTRAINT cloud_accounts_read_only_role CHECK (
        (ownership = 'platform' AND read_only_role IS NULL)
        OR (ownership = 'client' AND read_only_role IS NOT NULL AND read_only_role_ok(provider, read_only_role)));

-- +goose Down
ALTER TABLE cloud_accounts DROP CONSTRAINT cloud_accounts_read_only_role, DROP COLUMN read_only_role, DROP COLUMN ownership;
DROP FUNCTION read_only_role_ok(text, jsonb);
