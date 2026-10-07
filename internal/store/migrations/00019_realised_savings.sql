-- +goose Up
-- Savings tracker (#75): what applying a recommendation actually saved.
ALTER TABLE recommendations
    ADD COLUMN applied_at       timestamptz,
    ADD COLUMN realised_savings numeric,
    ADD COLUMN realised_method  text CHECK (realised_method IN ('measured', 'estimated')),
    ADD COLUMN regression       text;
GRANT UPDATE (applied_at, realised_savings, realised_method, regression) ON recommendations TO keel_app;

-- +goose Down
ALTER TABLE recommendations DROP COLUMN regression, DROP COLUMN realised_method, DROP COLUMN realised_savings, DROP COLUMN applied_at;
