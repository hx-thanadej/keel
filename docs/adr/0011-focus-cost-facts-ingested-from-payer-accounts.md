---
status: proposed
date: 2026-10-06
---

# Cost data: FOCUS-shaped facts, ingested from payer accounts, daily canonical grain

All spend from every provider is normalised into one **FOCUS-based cost fact**
table (FOCUS 1.2 semantics; current spec is 1.4) with Keel extension columns
(`x_project_id`, `x_environment`, `x_allocation_method`, `x_k8s`, `x_source`).
Connectors read from the **payer / billing scope** (AWS management account, GCP
billing account, Azure EA/MCA scope, Tencent payer UIN, Alibaba main account),
because member accounts see nothing or only themselves; on Tencent this is
documented behaviour. **Daily** is the canonical grain because Azure, Tencent
and Alibaba export no finer; hourly lines are kept where present.

## Considered Options

- **Each provider's native schema, unified in queries**: every report and
  Budget would need five code paths.
- **Trust FOCUS exports as-is**: Tencent's FOCUS 1.0 leaves `EffectiveCost`,
  `ServiceCategory`, `SkuId` and others empty; Alibaba's is preview-only and
  "not for reconciliation"; AWS's FOCUS lacks EKS split-cost rows. Each
  provider therefore has an adapter that may also read the native bill to fill
  gaps.

## Consequences

- Ingest is idempotent per (provider, billing period) and re-runs until that
  provider's **finality rule** is met (AWS: invoice id present, ≤2 weeks of
  edits; Azure ~72h after month end; Tencent 19:00 on the 1st; Alibaba 3rd–4th,
  amortised 6th; GCP no guarantee), then freezes. Reports show "not final".
- Project/Environment comes from the Cloud Account first
  ([ADR-0002](./0002-one-cloud-account-per-project-environment.md)), then tags,
  then Kubernetes namespace/labels (OpenCost) for shared clusters. Unallocated
  spend is a reported KPI.
- Both billed and effective (amortised, after discounts) cost are stored;
  Budgets default to effective cost.
