-- +goose Up
-- Lets Keel's FX job see how far back rates go without reading the home
-- Tenant's table directly.
-- +goose StatementBegin
CREATE FUNCTION fx_rates_days() RETURNS TABLE (day date)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT DISTINCT day FROM fx_rates
$$;
-- +goose StatementEnd
GRANT USAGE, CREATE ON SCHEMA public TO keel_lookup;
ALTER FUNCTION fx_rates_days() OWNER TO keel_lookup;
REVOKE CREATE ON SCHEMA public FROM keel_lookup;
REVOKE ALL ON FUNCTION fx_rates_days() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fx_rates_days() TO keel_app;

-- +goose Down
DROP FUNCTION fx_rates_days();
