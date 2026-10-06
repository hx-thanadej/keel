---
status: proposed
date: 2026-10-06
---

# One Policy model, four Enforcement Points, audit-first rollout

Each Control maps to Policies evaluated at the earliest Enforcement Point that
can see the evidence: **PR** (Conftest/OPA on IaC and workflow files via an org
ruleset required check), **Pipeline/plan** (OPA on the plan JSON, provenance
checks), **admission** (Kubernetes ValidatingAdmissionPolicy for simple CEL;
Kyverno CEL policy types incl. `ImageValidatingPolicy` for signature and
provenance), and **cloud control plane** (organisation SCPs, as Guardrails).
Every Policy ships in audit/warn mode first, has an owner, and can be waived only
by an **Exception** with an approver and an expiry.

## Considered Options

- **Kyverno `ClusterPolicy`**: deprecated in Kyverno 1.19 with removal planned
  in 1.20 (~Nov 2026). New work starts on the CEL types.
- **Gatekeeper only**: viable; Kyverno chosen for native image-verification.
  Gatekeeper stays an option behind the same Policy abstraction.

## Consequences

- Keel's own authorisation (who can do what to which Project) uses the same
  engine family (OPA or Cedar as a decision point), not ad-hoc code checks.
- Expired Exceptions turn back into blocking Findings automatically.
