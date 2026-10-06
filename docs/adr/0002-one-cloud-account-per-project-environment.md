---
status: accepted
date: 2026-10-06
deciders: thanadej@harmonyx.co
---

# One Cloud Account per Project Environment

Each Environment of each Project gets its own dedicated Cloud Account per cloud
provider (e.g. Tencent member accounts `tat-crm-dev`, `tat-crm-prod`; AWS
accounts in an Organization OU per Tenant). This gives the strongest blast-radius
isolation between Tenants and between prod and non-prod, and makes Cost
Allocation exact at the account level instead of depending on tag hygiene. It
also matches how the existing Tencent estate is already laid out.

## Considered Options

- **One account per Tenant**, Environments separated by VPC/namespace/tags:
  fewer accounts, but prod and dev share an IAM and quota blast radius, and
  cost per Environment depends on tags being complete.
- **Shared accounts and clusters**, separation by namespace/IAM/tags only:
  cheapest, but weakest isolation for a multi-client company and unsuitable for
  client data separation commitments.

## Consequences

- **Account vending** (create account → apply Landing Zone → wire identity,
  logging, budget, Guardrails) is a first-class Golden Path, fully automated.
- Billing must be ingested from the organisation's payer/management account,
  because member accounts may not see their own bills (observed on Tencent Cloud).
- Shared tooling (CI runners, registries, observability) lives in platform-owned
  Cloud Accounts, and its cost must be split back to Projects by usage. That
  shared cost is the one place where tags/labels still carry allocation.
- More accounts means more fixed overhead (NAT gateways, baseline services per
  account). Landing Zone design must keep per-account baseline cost small.
