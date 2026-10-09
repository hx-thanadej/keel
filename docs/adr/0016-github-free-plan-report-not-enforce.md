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
(`internal/githubgov`, #91) reads the plan. On Free it reports two things
today. It raises a high-severity Finding for rulesets on private
repositories, and a high-severity Finding when secret scanning or push
protection is off on a private repository, which also needs a paid product.
It does not yet report required workflows, audit-log streaming, artifact
attestations or branch protection on private repositories. Those gaps are
documented here and not detected.

## Decision

The organisation stays on **GitHub Free** for now. Keel **reports** the
protections Free lacks on private repositories. It does not pretend to enforce
them. Each reported gap is a high-severity Finding on the Repository,
visible to the owning Team and the Tenant. The unreported gaps are listed in
Context. Keel keeps enforcing what it controls outside
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
- Audit-log streaming and the audit-log REST API need Enterprise Cloud, so
  Keel cannot read the audit log on Free or Team. Keel receives organisation
  webhook events instead (#193).
- Attestations for private repositories are signed and stored by Keel
  (ADR-0010) rather than by GitHub.
- Revisit when a Tenant contract or an audit (ADR-0017) requires enforced
  branch protection. Moving to Team or Enterprise Cloud needs no Keel
  change because the reconciler switches mode from the plan it reads.
