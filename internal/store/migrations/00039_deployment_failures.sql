-- +goose Up
-- DORA (#148): a deployment can be marked failed (by people, or by Keel when
-- Argo CD reports it Degraded after the deploy).
ALTER TABLE promotions
    ADD COLUMN failed_at      timestamptz,
    ADD COLUMN failure_reason text;
GRANT UPDATE (failed_at, failure_reason) ON promotions TO keel_app;

-- +goose Down
ALTER TABLE promotions DROP COLUMN failure_reason, DROP COLUMN failed_at;
