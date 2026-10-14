-- +goose Up
-- #244: Keel's own role is assumed only while no Tenant can make the account
-- client-owned. KeelAccount.Enter holds the account's ownership lock shared
-- for the whole assumption; any write that can make a provider account
-- client-owned (a switch, a new or re-keyed registration, an unarchive)
-- takes it exclusively first, so the two never interleave. An advisory lock,
-- because a new registration has no row to lock yet.
CREATE FUNCTION account_lock_key(p_provider text, p_external_id text) RETURNS bigint
LANGUAGE sql IMMUTABLE AS $$
    SELECT hashtextextended('cloud_account:' || p_provider || ':' || p_external_id, 0)
$$;

-- +goose StatementBegin
CREATE FUNCTION cloud_accounts_ownership_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(account_lock_key(NEW.provider, NEW.external_id));
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER cloud_accounts_ownership_lock BEFORE INSERT OR UPDATE OF provider, external_id, ownership, archived_at ON cloud_accounts
    FOR EACH ROW EXECUTE FUNCTION cloud_accounts_ownership_lock();

-- account_ownership is who holds a provider account, archived or not (one
-- row per provider and id); NULL when no Tenant registered it.
-- +goose StatementBegin
CREATE FUNCTION account_ownership(p_provider text, p_external_id text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT ownership FROM cloud_accounts WHERE provider = p_provider AND external_id = p_external_id
$$;
-- +goose StatementEnd
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION account_ownership(text, text) OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION account_ownership(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION account_ownership(text, text) TO keel_app;

-- +goose Down
DROP FUNCTION account_ownership(text, text);
DROP TRIGGER cloud_accounts_ownership_lock ON cloud_accounts;
DROP FUNCTION cloud_accounts_ownership_lock();
DROP FUNCTION account_lock_key(text, text);
