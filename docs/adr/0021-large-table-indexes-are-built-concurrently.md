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
- Name the index. An unnamed index cannot be dropped by name before a retry.
- Do not wrap it in a `DO` block. `CREATE INDEX CONCURRENTLY` cannot run
  inside a function body.
- A `UNIQUE` or `PRIMARY KEY` constraint added by `ALTER TABLE` builds its
  index under a lock that blocks writes. Build the unique index concurrently
  as above, then attach it in a later migration with
  `ALTER TABLE ... ADD CONSTRAINT name UNIQUE USING INDEX name`.
- The large tables are `cost_facts`, `activities`, `findings`,
  `webhook_deliveries`, `utilisation_daily`, `k8s_namespace_costs` and
  `release_components`. Add a table to `largeTables` in
  `internal/store/migrations_lint_test.go` when it becomes hot.
- `TestMigrationsBuildLargeTableIndexesConcurrently` fails any migration
  numbered 00055 or higher that breaks one of these rules on one of these
  tables. It reads the SQL after stripping comments, lower-casing and
  removing identifier quotes, and ignores any schema prefix, so spelling does
  not hide a statement. It also flags `ALTER TABLE ... ADD EXCLUDE` and
  `REINDEX TABLE` without `CONCURRENTLY` on these tables. Indexes on small
  tables are not checked.
- The lint reads SQL text, not a parse tree, so some forms pass it unchecked.
  A statement built as a string and run by `EXECUTE` is not seen. Neither is
  `REINDEX INDEX`, `SCHEMA` or `DATABASE`, whose table the text does not name.
  Comment markers inside a dollar-quoted or `E''` string, and `U&""`
  identifiers, can hide a statement too. Review these forms by hand.

### Replicas migrate one at a time

Every `keel-api` replica runs `store.Migrate` when it starts, so replicas that
start together race. Without serialising them, River's grants failed with
`tuple concurrently updated` in most rounds of three or four parallel
migrators (#239).

`store.Migrate` takes a session advisory lock on a dedicated connection
before goose's migrations, River's migrations and River's grants, and holds
it until all three finish. A second replica waits, then finds nothing
pending. The wait is bounded at 15 minutes, after which `Migrate` fails with
"migration lock not acquired within 15m0s; another replica is still
migrating". The lock is released when its connection closes, so a crashed
replica does not leave it held.

`CREATE INDEX CONCURRENTLY` waits for every transaction whose snapshot is
older than the build, so no replica may hold a snapshot while the lock is
held. The holder's lock connection is idle outside any transaction while the
migrations run on other connections. A waiter does not block in
`pg_advisory_lock`. That statement would hold a snapshot for the whole wait,
and a `NO TRANSACTION` migration's concurrent build would stall until the
waiter gave up. Instead the waiter runs `pg_try_advisory_lock` as a single
autocommit statement about once a second, with jitter, and holds no snapshot
between attempts. `TestConcurrentIndexBuildIsNotBlockedByTheMigrationLock`
and `TestConcurrentIndexBuildIsNotBlockedByAWaitingMigrator` check both
sides. A session lock needs a direct connection, so `KEEL_MIGRATE_URL` must
not point at a transaction-mode pooler.

Goose's own session locker was not used. It covers only goose's migrations,
and River's migrations and grants would still race.

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
- A replica that starts during a long concurrent build waits for it before
  serving. One longer than 15 minutes makes waiting replicas fail and
  restart. `TestConcurrentMigratorsApplyOnce` runs four migrators at once
  over five fresh databases and requires no errors and one goose row per
  version.
- Goose v3.28 reads the `NO TRANSACTION` marker per file, and
  `store.Migrate` runs through it. Verified against a real
  database: up, down and up again create, remove and recreate the index.
