-- +goose Up
-- Per-Environment opt-in for automatic waste cleanup (#72). Off by default;
-- Keel never cleans production regardless of this flag.
ALTER TABLE environments ADD COLUMN waste_cleanup boolean NOT NULL DEFAULT false;
GRANT UPDATE (waste_cleanup) ON environments TO keel_app;

-- +goose Down
ALTER TABLE environments DROP COLUMN waste_cleanup;
