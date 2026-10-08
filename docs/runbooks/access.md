# Runbook: permission boundaries and access (M5)

## Boundaries

Every CAM role or user Keel creates carries the Environment's permission
boundary; the daily check reports any principal without one or with an
unexpected policy. CAM users with access keys are Findings.

## Human access (Identity Center)

`KEEL_CIC_ZONE_ID` names the Tencent CIC zone. Teams are eligible for role
templates per Environment (read-only, operator, …; `keel-access@1`). An
Access Grant is requested for 1–12 hours with a reason; production write
needs Team lead + security lead approval. Keel assigns the CIC role
configuration for the window and removes it at expiry, even across restarts.
The daily **standing access** report raises a critical Finding for any human
with write access to production outside a Grant.

## Break-glass

Register break-glass identities (home Tenant security leads only,
`/v1/breakglass`; hardware MFA required). Any CloudAudit sign-in by one
raises a critical Finding until a post-mortem is recorded
(`POST /v1/breakglass/uses/{use}/postmortem`); a drill is due every 90 days
(`POST /v1/breakglass/{identity}/drill`).

## Leaked keys

Point the GitHub organisation's secret-scanning webhook at
`POST /v1/webhooks/github` (`KEEL_GITHUB_WEBHOOK_SECRET`). Keel finds the
owner of a leaked Tencent key, disables it at once and opens a critical
Finding; the secret is never stored. No replacement key is issued: the owner
moves to workload identity.

## Workload secrets

See [workload-secrets.md](workload-secrets.md): TKE pod identity first (#145
must confirm the `oidc:sub` format in ap-bangkok), SOPS + age in Git.
