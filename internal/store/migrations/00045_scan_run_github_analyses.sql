-- +goose Up
-- The GitHub code scanning analyses a scan run ingested (#121), so the
-- GitHub sync ingests each analysis once. NULL for CI uploads.
ALTER TABLE scan_runs ADD COLUMN github_analysis_ids bigint[];

-- +goose Down
ALTER TABLE scan_runs DROP COLUMN github_analysis_ids;
