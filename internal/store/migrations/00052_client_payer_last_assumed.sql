-- +goose Up
-- #186: when Keel last assumed a client payer's read-only role, stamped by
-- every client bill sync whose AssumeRole succeeds. Role health shows it;
-- resolving the role's Finding by hand never moves it.
ALTER TABLE client_payers ADD COLUMN last_assumed_at timestamptz;
GRANT UPDATE (last_assumed_at) ON client_payers TO keel_app;

-- +goose Down
REVOKE UPDATE (last_assumed_at) ON client_payers FROM keel_app;
ALTER TABLE client_payers DROP COLUMN last_assumed_at;
