---
status: accepted
date: 2026-10-09
deciders: thanadej@harmonyx.co
---

# Stay on GitHub Free; Keel reports the protections Free cannot enforce

## Context

Q1 in [DESIGN.md §10](../DESIGN.md#10-open-questions) asked which GitHub plan
Keel runs on (#8). Several protections Keel wants need a paid plan.
Rulesets and branch protection on private repositories need Team or higher.
Required workflows, audit-log streaming and artifact attestations on private
repositories need Enterprise Cloud. The GitHub governance reconciler
(`internal/githubgov`, #91) already reads the plan and records each
protection the plan cannot enforce as a Finding.

## Decision

The organisation stays on **GitHub Free** for now. Keel **reports** the
protections Free lacks on private repositories. It does not pretend to enforce
them. Each gap is a high-severity Finding on the Repository, visible to the
owning Team and the Tenant. Keel keeps enforcing what it controls outside
GitHub. Promotion still requires a verified Release, provenance and a
passing Policy decision (ADR-0008, ADR-0010), whatever the plan.

## Considered options

- **GitHub Team.** Rulesets and branch protection on private repositories.
  No required workflows, audit-log streaming or private-repo attestations.
- **GitHub Enterprise Cloud.** Every protection in DESIGN.md. Highest cost.
- **Make private repositories public.** Not acceptable for client code.

## Consequences

- A merge to a default branch on a private repository is not blocked by
  GitHub. The Finding and the Activity Log record it. Promotion gates still
  stop unreviewed or unverified code from reaching production.
- Keel's reusable workflows are referenced by convention, not required by
  the organisation. Drift is a Finding.
- Keel polls the organisation audit log instead of receiving a stream.
- Attestations for private repositories are signed and stored by Keel
  (ADR-0010) rather than by GitHub.
- Revisit when a Tenant contract or an audit (ADR-0017) requires enforced
  branch protection. Moving to Team or Enterprise Cloud needs no Keel
  change because the reconciler switches mode from the plan it reads.
