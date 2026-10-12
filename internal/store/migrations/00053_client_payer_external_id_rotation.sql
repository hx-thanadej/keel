-- +goose Up
-- #213: Keel may issue a client payer a new ExternalId (catalog
-- RotateClientPayerExternalID, platform_admin only, recorded as an
-- Activity). keel_app gets this one column and nothing else of the row, so
-- it still cannot move a payer to another account or Tenant. Row security
-- keeps each Tenant to its own payers and the 32-hex check still holds.
GRANT UPDATE (role_external_id) ON client_payers TO keel_app;

-- +goose Down
REVOKE UPDATE (role_external_id) ON client_payers FROM keel_app;
