-- +goose Up
-- Service Templates (#92): which template (and pinned commit) a Service was created from.
ALTER TABLE services
    ADD COLUMN template         text NOT NULL DEFAULT '',
    ADD COLUMN template_version text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE services DROP COLUMN template_version, DROP COLUMN template;
