-- +goose Up
-- #224: the PDPA residency check reads each Cloud Account's regional billed
-- usage by account: whether it has any in the usage window, its last billed
-- day, and the regions of its last window. With no index leading with
-- cloud_account_id, each quiet account walked the Tenant's whole
-- cost_facts_tenant_day range (about 330 s for 1M facts, 1,000 accounts).
CREATE INDEX cost_facts_account_region_day ON cost_facts (cloud_account_id, charge_period_start) INCLUDE (region_id)
    WHERE current AND region_id <> '';

-- +goose Down
DROP INDEX cost_facts_account_region_day;
