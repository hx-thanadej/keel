-- +goose Up
-- Permission Boundaries (#131): which boundary version each account carries.
ALTER TABLE cloud_accounts ADD COLUMN boundary_version text;
GRANT UPDATE (boundary_version) ON cloud_accounts TO keel_app;

-- +goose Down
ALTER TABLE cloud_accounts DROP COLUMN boundary_version;
