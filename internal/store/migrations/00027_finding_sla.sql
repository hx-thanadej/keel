-- +goose Up
-- Finding SLAs (#107): every Finding is due by a date set from its severity.
ALTER TABLE tenants ADD COLUMN finding_sla jsonb NOT NULL DEFAULT '{"critical": 7, "high": 30, "medium": 90, "low": 180}';
GRANT UPDATE (finding_sla) ON tenants TO keel_app;
ALTER TABLE findings
    ADD COLUMN due_at     timestamptz,
    ADD COLUMN overdue_at timestamptz;
GRANT UPDATE (overdue_at) ON findings TO keel_app;
CREATE INDEX findings_tenant_due ON findings (tenant_id, due_at) WHERE status = 'open';

-- +goose StatementBegin
CREATE FUNCTION finding_due() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE TRIGGER findings_due BEFORE INSERT OR UPDATE OF severity ON findings FOR EACH ROW EXECUTE FUNCTION finding_due();

-- +goose Down
DROP TRIGGER findings_due ON findings;
DROP FUNCTION finding_due();
ALTER TABLE findings DROP COLUMN overdue_at, DROP COLUMN due_at;
ALTER TABLE tenants DROP COLUMN finding_sla;
