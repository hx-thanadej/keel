-- +goose Up
-- An Exception's approval and revocation each keep their own time (#152),
-- so revoking no longer overwrites when it was granted. Rows decided before
-- this migration only know decided_at; it is the best record of either.
ALTER TABLE exceptions ADD COLUMN approved_at timestamptz, ADD COLUMN revoked_at timestamptz;
UPDATE exceptions SET approved_at = decided_at WHERE state IN ('approved', 'expired');
UPDATE exceptions SET revoked_at = decided_at WHERE state = 'revoked';
GRANT UPDATE (approved_at, revoked_at) ON exceptions TO keel_app;

-- +goose Down
REVOKE UPDATE (approved_at, revoked_at) ON exceptions FROM keel_app;
ALTER TABLE exceptions DROP COLUMN approved_at, DROP COLUMN revoked_at;
