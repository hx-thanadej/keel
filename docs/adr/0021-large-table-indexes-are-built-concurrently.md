---
status: accepted
date: 2026-10-12
deciders: thanadej@harmonyx.co
---

# Indexes on large tables are built concurrently

## Context

`keel-api` applies pending migrations when it starts. A plain
`CREATE INDEX` takes a lock that blocks writes to the table until the build
ends. On `cost_facts`, that stops bill ingest. On `activities`, it stops every
change record (ADR-0005).

Migration 00054 (#224) added `cost_facts_account_region_day` with a plain
`CREATE INDEX`. That is the case this decision covers.

## Decision

An index on a large table is built in its own migration, marked
`-- +goose NO TRANSACTION`, because `CREATE INDEX CONCURRENTLY` cannot run in
a transaction:

```sql
-- +goose NO TRANSACTION
-- +goose Up
DROP INDEX IF EXISTS cost_facts_example;
CREATE INDEX CONCURRENTLY cost_facts_example ON cost_facts (cloud_account_id);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS cost_facts_example;
```

- The `DROP INDEX IF EXISTS` comes first. A concurrent build that fails
  leaves an INVALID index of that name, and a retry would then stop at
  "relation already exists". The drop makes the migration safe to run again.
- Without a transaction, a migration is not atomic. Keep one index per
  migration file, so a failure leaves nothing half applied.
- The large tables are `cost_facts`, `activities`, `findings` and
  `webhook_deliveries`. Add a table to `largeTables` in
  `internal/store/migrations_lint_test.go` when it becomes hot.
- `TestMigrationsBuildLargeTableIndexesConcurrently` fails any migration
  numbered 00055 or higher that creates an index on one of these tables
  without all three parts. Indexes on small tables are not checked.

## Consequences

- 00054 stays as it is. It predates this rule and is already applied in
  environments, so rewriting it would change a migration goose has recorded.
  It is not converted in a new migration either. A migration that dropped and
  rebuilt the index would take the same write lock this decision avoids, only
  a second time.
- Whether that lock ever hurt is not knowable from this repository. The
  repository holds no record of whether any environment has real cost data.
  The risk to check before relying on that: an environment where `cost_facts`
  is large and 00054 has not yet run. Its build would block ingest once.
- A concurrent build takes longer and does two table scans. That is the price
  of not blocking writes.
- The migrator needs no change. Goose v3.28 reads the `NO TRANSACTION`
  marker per file, and `store.Migrate` runs through it. Verified against a real
  database: up, down and up again create, remove and recreate the index.
