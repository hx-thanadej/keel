---
status: proposed
date: 2026-10-06
---

# GitOps delivery: Argo CD, PR-based Promotion of immutable digests

Deployments are reconciled by Argo CD from per-Project config repos. A Release
references Artifacts by digest only; Promotion between Environments is a PR to
the config repo that changes the digest, gated by Policy (provenance verified,
no unexcepted critical Findings, Budget not hard-breached for that
Environment). Pipelines never `kubectl apply` or hold cluster credentials.

## Considered Options

- **Flux**: equally mature (CNCF graduated). Argo CD wins on its UI and
  multi-cluster ApplicationSet model, which suit one cluster per Project
  Environment ([ADR-0002](./0002-one-cloud-account-per-project-environment.md)).
- **Push-based deploys from CI**: puts cluster credentials in CI, which
  contradicts [ADR-0007](./0007-no-long-lived-cloud-credentials-in-ci.md).

## Consequences

- Argo's Source Hydrator (beta) and GitOps Promoter (experimental) are patterns
  to follow, not dependencies; Keel's Promotion service owns the PR flow.
- Progressive delivery (Argo Rollouts) is added once DORA metrics exist to judge it.
