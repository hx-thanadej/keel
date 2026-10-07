-- +goose Up
-- Providers that overwrite export files in place (AWS Data Exports) are
-- detected by ETag: the same key with a new ETag is a new version (#44).
ALTER TABLE cost_source_files ADD COLUMN etag text NOT NULL DEFAULT '';
ALTER TABLE cost_source_files DROP CONSTRAINT cost_source_files_provider_billing_account_id_object_key_bi_key;
ALTER TABLE cost_source_files ADD CONSTRAINT cost_source_files_version_key UNIQUE (provider, billing_account_id, object_key, etag, billing_period);

-- +goose Down
ALTER TABLE cost_source_files DROP CONSTRAINT cost_source_files_version_key;
ALTER TABLE cost_source_files ADD CONSTRAINT cost_source_files_provider_billing_account_id_object_key_bi_key UNIQUE (provider, billing_account_id, object_key, billing_period);
ALTER TABLE cost_source_files DROP COLUMN etag;
