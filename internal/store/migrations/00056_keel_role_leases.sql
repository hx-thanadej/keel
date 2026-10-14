-- +goose Up
-- #249: KeelAccount.Enter no longer holds a connection, and the ownership
-- lock with it, across the STS call. It takes the lock shared only to check
-- ownership and record a lease (enter_keel_account), then assumes with no
-- connection held. A write that can make the account client-owned still
-- takes the lock exclusively (00055), which stops new leases, then waits
-- for the live ones to be left or to expire. Enter refuses an assumption
-- whose lease expired before it was left, since a switch may then have
-- committed under it.
CREATE TABLE keel_role_leases (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lock_key   bigint NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX keel_role_leases_lock_key ON keel_role_leases (lock_key);
-- Not Tenant data: only the functions below, running as the owner, touch it.
ALTER TABLE keel_role_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE keel_role_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY keel_role_leases_owner ON keel_role_leases TO CURRENT_USER USING (true) WITH CHECK (true);

-- enter_keel_account is NULL when a Tenant holds the account as
-- client-owned, archived or not. Otherwise it is a lease on the account for
-- p_lease, or 0 when p_lease is not positive (a check alone). A switch in
-- flight is waited for and then seen.
-- +goose StatementBegin
CREATE FUNCTION enter_keel_account(p_provider text, p_external_id text, p_lease interval) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    k     bigint := account_lock_key(p_provider, p_external_id);
    lease bigint := 0;
BEGIN
    PERFORM pg_advisory_xact_lock_shared(k);
    IF account_ownership(p_provider, p_external_id) IS NOT DISTINCT FROM 'client' THEN
        RETURN NULL;
    END IF;
    IF p_lease > interval '0' THEN
        DELETE FROM keel_role_leases WHERE lock_key = k AND expires_at <= clock_timestamp();
        INSERT INTO keel_role_leases (lock_key, expires_at) VALUES (k, clock_timestamp() + p_lease) RETURNING id INTO lease;
    END IF;
    RETURN lease;
END $$;
-- +goose StatementEnd

-- leave_keel_account ends a lease: true when it was still live, so no
-- switch can have committed while it was held.
-- +goose StatementBegin
CREATE FUNCTION leave_keel_account(p_lease bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    DELETE FROM keel_role_leases WHERE id = p_lease RETURNING expires_at > clock_timestamp()
$$;
-- +goose StatementEnd

-- await_keel_role_leases waits until no live lease is held on k. Each
-- loop reads with a fresh snapshot only under READ COMMITTED; under a
-- transaction snapshot it would miss leases and their ends.
-- +goose StatementBegin
CREATE FUNCTION await_keel_role_leases(k bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'an account ownership write must run at READ COMMITTED, not %', current_setting('transaction_isolation');
    END IF;
    WHILE EXISTS (SELECT 1 FROM keel_role_leases WHERE lock_key = k AND expires_at > clock_timestamp()) LOOP
        PERFORM pg_sleep(0.02);
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cloud_accounts_ownership_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(account_lock_key(NEW.provider, NEW.external_id));
    PERFORM await_keel_role_leases(account_lock_key(NEW.provider, NEW.external_id));
    RETURN NEW;
END
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION enter_keel_account(text, text, interval), leave_keel_account(bigint), await_keel_role_leases(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION enter_keel_account(text, text, interval), leave_keel_account(bigint), await_keel_role_leases(bigint) TO keel_app;

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION cloud_accounts_ownership_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(account_lock_key(NEW.provider, NEW.external_id));
    RETURN NEW;
END
$$;
-- +goose StatementEnd
DROP FUNCTION await_keel_role_leases(bigint);
DROP FUNCTION leave_keel_account(bigint);
DROP FUNCTION enter_keel_account(text, text, interval);
DROP TABLE keel_role_leases;
