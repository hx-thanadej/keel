-- +goose Up
-- ADR-0018 (#183): an AWS management account can be its client's payer too.
-- Its Data Exports land in an S3 bucket (no Tencent appid suffix), in any
-- AWS region (us-gov-west-1 has three parts), as export folders. The table
-- keeps what every provider shares; catalog.SetClientPayer checks each
-- provider's own bucket, region and mode.
ALTER TABLE client_payers
    DROP CONSTRAINT client_payers_bucket_check,
    DROP CONSTRAINT client_payers_region_check,
    DROP CONSTRAINT client_payers_mode_check,
    ADD CONSTRAINT client_payers_bucket_check CHECK (bucket = '' OR bucket ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'),
    ADD CONSTRAINT client_payers_region_check CHECK (region ~ '^[a-z]{2,4}(-[a-z]+)+(-[0-9]+)?$'),
    ADD CONSTRAINT client_payers_mode_check CHECK (mode IN ('per-day', 'cumulative', 'export-folder'));

-- +goose Down
DELETE FROM client_payers WHERE mode = 'export-folder';
ALTER TABLE client_payers
    DROP CONSTRAINT client_payers_bucket_check,
    DROP CONSTRAINT client_payers_region_check,
    DROP CONSTRAINT client_payers_mode_check,
    ADD CONSTRAINT client_payers_bucket_check CHECK (bucket = '' OR (length(bucket) <= 63 AND bucket ~ '^[a-z0-9][a-z0-9-]*-[0-9]{5,20}$')),
    ADD CONSTRAINT client_payers_region_check CHECK (region ~ '^[a-z]{2,4}-[a-z]+(-[0-9]+)?$'),
    ADD CONSTRAINT client_payers_mode_check CHECK (mode IN ('per-day', 'cumulative'));
