-- +goose Up
-- Keyless CI (#90): GitHub's immutable ids for each Service's repository, so
-- cloud roles trust repository_id rather than a renameable name, and when
-- each Cloud Account got its CI identity.
ALTER TABLE services
    ADD COLUMN repository_id       bigint,
    ADD COLUMN repository_owner_id bigint;
GRANT UPDATE (repository_id, repository_owner_id) ON services TO keel_app;
ALTER TABLE cloud_accounts ADD COLUMN ci_identity_at timestamptz;
GRANT UPDATE (ci_identity_at) ON cloud_accounts TO keel_app;

-- +goose Down
ALTER TABLE cloud_accounts DROP COLUMN ci_identity_at;
ALTER TABLE services DROP COLUMN repository_owner_id, DROP COLUMN repository_id;
