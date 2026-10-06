---
status: proposed
date: 2026-10-06
---

# Keel owns Budgets; provider budgets are optional mirrors

Budgets are Keel objects scoped to a Project, or to a Project × Environment
(optionally narrowed by provider), with a yearly amount phased into months and
days, and thresholds on both Actual Spend and Forecast. Keel evaluates every
Budget after each cost ingest on its own normalised data and shows budget vs
actual vs forecast per day, month and year. Native budgets are created as
**mirrors** only where an API exists, because native budgets cannot express a
cross-provider Project, and Alibaba has no create-budget API at all.

## Consequences

- Enforcement is opt-in and per Environment: alerts first; on hard breach
  optionally block Promotion to that Environment (Policy) and trigger provider
  actions where they exist (AWS Budgets Actions; GCP spend caps; Azure action
  groups; Cloud Custodian stop for Tencent non-prod). Never automatic in prod.
- Forecast uses Keel's own seasonal model with p10/p50/p90 bands, shown next to
  native forecasts (AWS, Azure) for comparison; hidden until one full cycle of
  history exists.
- Budget alerts lag reality by provider data latency (up to D+1). Real-time
  guardrails come from Policy (e.g. instance-type allowlists), not Budgets.
