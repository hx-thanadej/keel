-- +goose Up
-- Off-hours scheduling (#73): each day's maximum per UTC hour, and the
-- Tenant's time zone that schedules are expressed in.
ALTER TABLE utilisation_daily ADD COLUMN hourly_max double precision[];
GRANT UPDATE (hourly_max) ON utilisation_daily TO keel_app;
ALTER TABLE tenants ADD COLUMN time_zone text NOT NULL DEFAULT 'Asia/Bangkok';
GRANT UPDATE (time_zone) ON tenants TO keel_app;

-- +goose Down
ALTER TABLE tenants DROP COLUMN time_zone;
ALTER TABLE utilisation_daily DROP COLUMN hourly_max;
