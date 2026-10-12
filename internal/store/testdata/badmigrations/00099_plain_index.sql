-- +goose Up
CREATE INDEX cost_facts_bad ON cost_facts (cloud_account_id);

-- +goose Down
DROP INDEX cost_facts_bad;
