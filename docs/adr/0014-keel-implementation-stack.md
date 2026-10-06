---
status: proposed
date: 2026-10-06
---

# Keel's own stack: Go services, Postgres with row-level security, ClickHouse for facts, Temporal for workflows

- **Go** for the control plane and adapters: first-class SDKs for Tencent,
  AWS, GCP, Azure, Alibaba and the Kubernetes/Sigstore/OPA ecosystems.
- **TypeScript + React** for the portal.
- **PostgreSQL with row-level security** keyed on `tenant_id` as the system of
  record (Catalog, Budgets, Findings, Exceptions, Access Grants). Tenant
  isolation is enforced by the database, not by application filters
  ([ADR-0001](./0001-tenant-is-a-client-organisation.md)).
- **ClickHouse** for high-volume append-only data: cost facts (hourly,
  resource-level lines across all accounts), utilisation samples for
  rightsizing, and the queryable copy of the Activity Log.
- **Temporal** for durable, long-running workflows: account vending, Access
  Grant expiry, Exception expiry, ingest/finality loops, recommendation apply.

## Considered Options

- **TypeScript end-to-end + trigger.dev** (already used in this workspace):
  faster for a TS-heavy team; weaker cloud-SDK coverage for Tencent/Alibaba
  and the Kubernetes ecosystem.
- **Postgres only** (no ClickHouse): simpler to start with; cost and
  utilisation volume at hourly, resource-level grain across many Tenants will
  outgrow it. Acceptable for phase 1 behind a repository interface.

## Status note

Proposed, pending confirmation of the team's language skills. This is the
most reversible ADR in the set until the first service ships.
