-- +goose Up
-- Landing Zone (#89): which baseline version each Cloud Account carries.
ALTER TABLE cloud_accounts
    ADD COLUMN baseline_version    text,
    ADD COLUMN baseline_applied_at timestamptz;
GRANT UPDATE (baseline_version, baseline_applied_at) ON cloud_accounts TO keel_app;

-- +goose Down
ALTER TABLE cloud_accounts DROP COLUMN baseline_applied_at, DROP COLUMN baseline_version;
