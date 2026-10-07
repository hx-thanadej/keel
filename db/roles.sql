-- Cluster-level roles Keel needs. Run once per Postgres cluster as a superuser
-- (or a role with CREATEROLE + BYPASSRLS grant rights), before the first migration.
-- Passwords come from the secret store; set them with \password or ALTER ROLE.
--
--   keel_owner   owns the schema; runs migrations. Subject to FORCE RLS.
--   keel_app     the API. No BYPASSRLS, owns nothing, no DELETE anywhere.
--   keel_lookup  NOLOGIN. Owns only the pre-authentication lookup functions
--                (idp_lookup, idp_bindings, session_lookup) and can SELECT only
--                the tables they read. The one place RLS is bypassed.

CREATE ROLE keel_owner LOGIN;
CREATE ROLE keel_app LOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE keel_lookup NOLOGIN BYPASSRLS;
GRANT keel_lookup TO keel_owner;   -- lets migrations assign function ownership

-- Then: CREATE DATABASE keel OWNER keel_owner;
