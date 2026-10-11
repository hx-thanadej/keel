-- +goose Up
-- ADR-0018 (#183): an AWS management account can be its client's payer too.
-- Each row carries its account's provider (the composite FK keeps the two
-- equal) so the table checks each provider's own shape:
--   tencent: a COS bucket ending in -<appid>, a Tencent region, per-day or
--            cumulative bill files, no KMS key.
--   aws:     an S3 bucket name, an AWS region (us-gov-west-1 has three
--            parts), Data Exports folders, a prefix with no IAM wildcard
--            (it scopes the session policy), and optionally the SSE-KMS key,
--            which S3 requires in the bucket's region.
ALTER TABLE cloud_accounts ADD CONSTRAINT cloud_accounts_id_provider_key UNIQUE (id, provider);
ALTER TABLE client_payers
    ADD COLUMN provider text,
    ADD COLUMN kms_key_arn text NOT NULL DEFAULT '';
UPDATE client_payers p SET provider = a.provider FROM cloud_accounts a WHERE a.id = p.cloud_account_id;
ALTER TABLE client_payers
    ALTER COLUMN provider SET NOT NULL,
    ADD CONSTRAINT client_payers_account_provider_fkey FOREIGN KEY (cloud_account_id, provider) REFERENCES cloud_accounts (id, provider),
    DROP CONSTRAINT client_payers_bucket_check,
    DROP CONSTRAINT client_payers_region_check,
    DROP CONSTRAINT client_payers_mode_check,
    ADD CONSTRAINT client_payers_provider_check CHECK (provider IN ('tencent', 'aws')),
    ADD CONSTRAINT client_payers_tencent_check CHECK (provider <> 'tencent' OR (
        (bucket = '' OR (length(bucket) <= 63 AND bucket ~ '^[a-z0-9][a-z0-9-]*-[0-9]{5,20}$'))
        AND region ~ '^[a-z]{2,4}-[a-z]+(-[0-9]+)?$'
        AND mode IN ('per-day', 'cumulative')
        AND kms_key_arn = '')),
    ADD CONSTRAINT client_payers_aws_check CHECK (provider <> 'aws' OR (
        (bucket = '' OR (length(bucket) BETWEEN 3 AND 63
            AND bucket ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'
            AND bucket !~ '\.\.'
            AND bucket !~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
            AND bucket !~ '^(xn--|sthree-|amzn-s3-demo-)'
            AND bucket !~ '(-s3alias|--ol-s3|\.mrap|--x-s3|--table-s3)$'))
        AND region ~ '^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$'
        AND mode = 'export-folder'
        AND prefix !~ '[*?$]'
        AND (kms_key_arn = '' OR (kms_key_arn ~ '^arn:aws(-cn|-us-gov)?:kms:[a-z0-9-]+:[0-9]{12}:key/(mrk-[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
            AND split_part(kms_key_arn, ':', 4) = region))));
GRANT INSERT (provider, kms_key_arn) ON client_payers TO keel_app;
GRANT UPDATE (kms_key_arn) ON client_payers TO keel_app;

DROP FUNCTION client_payers_for(text);
-- +goose StatementBegin
CREATE FUNCTION client_payers_for(p_provider text)
RETURNS TABLE (tenant_id uuid, cloud_account_id uuid, external_id text, role_arn text, role_external_id text, bucket text, prefix text, region text, mode text, kms_key_arn text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT p.tenant_id, a.id, a.external_id, a.read_only_role->>'role_arn', p.role_external_id, p.bucket, p.prefix, p.region, p.mode, p.kms_key_arn
    FROM client_payers p JOIN cloud_accounts a ON a.id = p.cloud_account_id AND a.tenant_id = p.tenant_id
    WHERE a.provider = p_provider AND a.ownership = 'client' AND a.archived_at IS NULL
    ORDER BY a.external_id
$$;
-- +goose StatementEnd
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION client_payers_for(text) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION client_payers_for(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION client_payers_for(text) TO keel_app;

-- +goose Down
-- 00050 holds Tencent payers only. Every Tencent row already meets its
-- checks, which client_payers_tencent_check repeats.
DELETE FROM client_payers WHERE provider <> 'tencent';
DROP FUNCTION client_payers_for(text);
-- +goose StatementBegin
CREATE FUNCTION client_payers_for(p_provider text)
RETURNS TABLE (tenant_id uuid, cloud_account_id uuid, external_id text, role_arn text, role_external_id text, bucket text, prefix text, region text, mode text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT p.tenant_id, a.id, a.external_id, a.read_only_role->>'role_arn', p.role_external_id, p.bucket, p.prefix, p.region, p.mode
    FROM client_payers p JOIN cloud_accounts a ON a.id = p.cloud_account_id AND a.tenant_id = p.tenant_id
    WHERE a.provider = p_provider AND a.ownership = 'client' AND a.archived_at IS NULL
    ORDER BY a.external_id
$$;
-- +goose StatementEnd
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION client_payers_for(text) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION client_payers_for(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION client_payers_for(text) TO keel_app;
ALTER TABLE client_payers
    DROP CONSTRAINT client_payers_tencent_check,
    DROP CONSTRAINT client_payers_aws_check,
    DROP CONSTRAINT client_payers_provider_check,
    DROP CONSTRAINT client_payers_account_provider_fkey,
    DROP COLUMN kms_key_arn,
    DROP COLUMN provider,
    ADD CONSTRAINT client_payers_bucket_check CHECK (bucket = '' OR (length(bucket) <= 63 AND bucket ~ '^[a-z0-9][a-z0-9-]*-[0-9]{5,20}$')),
    ADD CONSTRAINT client_payers_region_check CHECK (region ~ '^[a-z]{2,4}-[a-z]+(-[0-9]+)?$'),
    ADD CONSTRAINT client_payers_mode_check CHECK (mode IN ('per-day', 'cumulative'));
ALTER TABLE cloud_accounts DROP CONSTRAINT cloud_accounts_id_provider_key;
