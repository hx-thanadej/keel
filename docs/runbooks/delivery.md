# Runbook: Golden Path delivery (M3)

## GitHub organisation

- `KEEL_GITHUB_ADMIN_TOKEN` (org administration + repository administration)
  lets the daily reconcile enforce `keel-github@1`: custom properties
  (`keel-tenant`, `keel-project`, `keel-tier`), a default-branch ruleset (1
  review, CODEOWNERS, `KEEL_GITHUB_REQUIRED_CHECKS`) and a stricter one for
  `keel-tier=prod` (2 reviews, last-push approval), the OIDC subject-claim
  template, and the Actions policy (SHA pinning, read-only `GITHUB_TOKEN`,
  approval for outside contributors' workflows, `KEEL_GITHUB_ALLOWED_ACTIONS`).
  Drift becomes Findings. Set `KEEL_GITHUB_REMEDIATE=1` to fix it. Set
  `KEEL_GITHUB_ORG=1` when `KEEL_GITHUB_OWNER` is an organisation.
- Some of this needs a paid plan (#8): on GitHub Free, rulesets on private
  repositories are unavailable and are reported, not enforced.

## Service Templates

`KEEL_TEMPLATES` lists templates (`name=owner/repo@sha,…`, repositories in
the `KEEL_GITHUB_OWNER` organisation). Creating a Service
renders the template into a new repository with `catalog-info.yaml`,
CODEOWNERS, `.sops.yaml` (`KEEL_SOPS_AGE_PROD`/`_NONPROD`) and a caller of the
reusable build workflow (`KEEL_REUSABLE_WORKFLOW`, see `deploy/README.md`).
Uses `KEEL_GITHUB_ADMIN_TOKEN`.

## Images

Pipelines push to TCR with one-hour tokens Keel brokers after verifying the
GitHub OIDC token (ADR-0015): `KEEL_TCR_REGISTRY_ID`, `KEEL_TCR_DOMAIN`,
audience `KEEL_PIPELINE_AUDIENCE` (default `keel`). Releases must use the
Project's namespace.

## Promotions (GitOps)

A Release is promoted by pull request to the Project's config repository
(`KEEL_PROMOTION_PATH` pattern), evaluated by `keel-promotion@1`: it must be
deployed to the previous Environment first, the budget not hard-breached, no
open critical Findings without an Exception, and every image must have a
passing VSA; Environments marked as requiring approval also need one. Keel watches Argo CD
(`KEEL_ARGOCD_URL`, `KEEL_ARGOCD_TOKEN` read-only, `KEEL_ARGOCD_APP` pattern)
every two minutes: merged → deployed; *Degraded* after deploy marks the
deployment failed, which feeds DORA. Promotion pull requests use
`KEEL_GITHUB_WRITE_TOKEN`. So do admission-policy and rightsizing pull
requests.
