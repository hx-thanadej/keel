-- +goose Up
-- Regional registry (#94): each Project's TCR namespace and when it was created.
ALTER TABLE projects
    ADD COLUMN registry_namespace  text NOT NULL DEFAULT '',
    ADD COLUMN registry_created_at timestamptz;
GRANT UPDATE (registry_namespace, registry_created_at) ON projects TO keel_app;

-- +goose Down
ALTER TABLE projects DROP COLUMN registry_created_at, DROP COLUMN registry_namespace;
