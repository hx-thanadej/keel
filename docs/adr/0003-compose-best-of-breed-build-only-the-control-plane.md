---
status: proposed
date: 2026-10-06
---

# Compose best-of-breed tools; build only the control plane

Keel is a multi-tenant **control plane** that orchestrates mature tools (GitHub,
Argo CD, Kyverno/OPA, Sigstore, Trivy/Syft, OpenCost, cloud-native billing and
recommender APIs) behind one Catalog, one policy model and one Activity Log. We
build only what no tool provides for our shape (multi-tenant, multi-cloud,
Tencent-first): the Catalog and tenancy model, the Policy and Exception service,
the FinOps engine (cost ingestion, Budgets, Rightsizing), the Access broker, the
Activity Log, and Decision Records. Everything else is an adapter.

## Considered Options

- **Build an all-in-one platform** (own CI runner, own scanner, own GitOps
  engine): years of work to reach parity with tools that already have large
  security teams behind them.
- **Buy one commercial suite** (GitLab Ultimate, Harness, etc.): none covers
  Tencent Cloud FinOps, Tencent CAM boundaries or client-facing multi-tenancy,
  and switching cost later is extreme.

## Consequences

- Every integrated tool sits behind a narrow adapter interface (e.g.
  `ScmProvider`, `CloudProvider`, `CostSource`, `Scanner`, `Deployer`) so it can
  be swapped. The adapter, not Keel's core, owns tool-specific quirks.
- Keel's value is the *joins*: Finding → Service → Team → Tenant; Cost → Project →
  Environment; Deployment → Release → Artifact → Attestation.
