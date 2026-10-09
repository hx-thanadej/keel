-- +goose Up
-- One clock (#176): Finding timestamps are written from the service clock, so
-- the database stops comparing them with its own now().

-- A Finding is excepted while an approved Exception covers it and has not
-- expired at as_of, the caller's clock time.
DROP FUNCTION finding_excepted(findings);
-- +goose StatementBegin
CREATE FUNCTION finding_excepted(f findings, as_of timestamptz) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM exceptions e
        WHERE e.tenant_id = f.tenant_id AND e.state = 'approved' AND e.expires_at > as_of
          AND (e.project_id IS NULL OR e.project_id = f.project_id)
          AND (f.id = ANY (e.finding_ids) OR (e.fingerprint <> '' AND starts_with(f.fingerprint, e.fingerprint))))
$$;
-- +goose StatementEnd

-- overdue_at is the clock time the SLA run flagged the Finding. A due date
-- moved past that time may no longer be late, so the flag clears and the next
-- SLA run re-flags it against its clock if it still is.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION finding_due() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    days integer;
BEGIN
    SELECT (finding_sla ->> NEW.severity)::integer INTO days FROM tenants WHERE id = NEW.tenant_id;
    days := coalesce(days, CASE NEW.severity WHEN 'critical' THEN 7 WHEN 'high' THEN 30 WHEN 'medium' THEN 90 ELSE 180 END);
    NEW.due_at := NEW.first_seen_at + make_interval(days => days);
    IF NEW.due_at > NEW.overdue_at THEN
        NEW.overdue_at := NULL;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION finding_due() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    days integer;
BEGIN
    SELECT (finding_sla ->> NEW.severity)::integer INTO days FROM tenants WHERE id = NEW.tenant_id;
    days := coalesce(days, CASE NEW.severity WHEN 'critical' THEN 7 WHEN 'high' THEN 30 WHEN 'medium' THEN 90 ELSE 180 END);
    NEW.due_at := NEW.first_seen_at + make_interval(days => days);
    IF NEW.due_at > now() THEN
        NEW.overdue_at := NULL;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
DROP FUNCTION finding_excepted(findings, timestamptz);
-- +goose StatementBegin
CREATE FUNCTION finding_excepted(f findings) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM exceptions e
        WHERE e.tenant_id = f.tenant_id AND e.state = 'approved' AND e.expires_at > now()
          AND (e.project_id IS NULL OR e.project_id = f.project_id)
          AND (f.id = ANY (e.finding_ids) OR (e.fingerprint <> '' AND starts_with(f.fingerprint, e.fingerprint))))
$$;
-- +goose StatementEnd
