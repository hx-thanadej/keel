-- +goose Up
-- Admission policies per Environment (#113): warn first, then enforce.
ALTER TABLE environments
    ADD COLUMN admission_mode   text NOT NULL DEFAULT 'warn' CHECK (admission_mode IN ('warn', 'enforce')),
    ADD COLUMN admission_hash   text NOT NULL DEFAULT '',
    ADD COLUMN admission_pr_url text;
GRANT UPDATE (admission_mode, admission_hash, admission_pr_url) ON environments TO keel_app;

-- +goose Down
ALTER TABLE environments DROP COLUMN admission_pr_url, DROP COLUMN admission_hash, DROP COLUMN admission_mode;
