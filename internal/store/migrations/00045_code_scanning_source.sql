-- +goose Up
-- Where a Service's code scanning Findings come from (#121): 'keel' is CI's
-- SARIF uploads, 'github' is GitHub's code scanning alerts. Never both, so
-- Keel does not have to guess that two copies of a result are one alert.
ALTER TABLE services ADD COLUMN code_scanning_source text NOT NULL DEFAULT 'keel' CHECK (code_scanning_source IN ('keel', 'github'));
GRANT UPDATE (code_scanning_source) ON services TO keel_app;

-- +goose Down
ALTER TABLE services DROP COLUMN code_scanning_source;
