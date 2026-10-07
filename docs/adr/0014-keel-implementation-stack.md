---
status: accepted
date: 2026-10-06
deciders: thanadej@harmonyx.co
---

# Keel's own stack: Go + Postgres (RLS) + River; no separate workflow engine

- **Go** for the API, control plane and adapters: first-class SDKs for Tencent,
  AWS and the Kubernetes/Sigstore/OPA ecosystems.
- **TypeScript + React** for the portal.
- **PostgreSQL with row-level security** keyed on `tenant_id` is the only
  datastore in phase 1: Catalog, Budgets, Findings, Exceptions, Access Grants,
  the Activity Log and cost facts (partitioned by provider and billing period).
  Tenant isolation is enforced by the database, not application filters
  ([ADR-0001](./0001-tenant-is-a-client-organisation.md)).
- **River** (Postgres-backed job queue, MPL-2.0) for everything that must
  survive restarts: scheduled ingest, retries, timers (Access Grant and
  Exception expiry) and multi-step flows (account vending) modelled as an
  explicit step-state table driven by River jobs. Jobs are enqueued in the same
  transaction as the state change that causes them.

## Considered Options

- **Temporal** for durable workflows: the strongest model for long multi-step
  sagas, but a separate cluster (its own services and database) to operate and
  secure. Rejected for now; revisit if multi-step flows become hard to reason
  about as step tables.
- **trigger.dev** (already used in this workspace): another hosted/self-hosted
  service, TypeScript-only.
- **TypeScript end-to-end + pg-boss**: one language, weaker Tencent/K8s SDKs.
- **ClickHouse** for cost facts and utilisation from day one: deferred. Cost and
  utilisation access goes through a repository interface so it can move to a
  columnar store when Postgres partitions stop keeping up.

## Consequences

- One stateful dependency (Postgres) to run, back up and secure.
- Workflow logic is plain Go code + step tables, testable without a workflow
  server; the cost is writing idempotency and compensation by hand.
