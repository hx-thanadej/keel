-- +goose Up
-- ADR-0018 (#185): a grant that ends after its account became client-owned is
-- orphaned. Keel may not remove its Identity Center assignment, so the grant
-- is not reported as cleanly revoked or expired, and a critical Finding tells
-- the account owner to remove it.
ALTER TABLE access_grants DROP CONSTRAINT access_grants_state_check,
    ADD CONSTRAINT access_grants_state_check CHECK (state IN ('requested', 'active', 'denied', 'rejected', 'revoked', 'expired', 'failed', 'orphaned'));

-- +goose Down
UPDATE access_grants SET state = 'failed', error = coalesce(error, 'orphaned: its Identity Center assignment was left for the account owner') WHERE state = 'orphaned';
ALTER TABLE access_grants DROP CONSTRAINT access_grants_state_check,
    ADD CONSTRAINT access_grants_state_check CHECK (state IN ('requested', 'active', 'denied', 'rejected', 'revoked', 'expired', 'failed'));
