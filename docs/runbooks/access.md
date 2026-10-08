# Runbook: permission boundaries and access (M5)

## Boundaries

Every CAM role Keel creates carries the Environment's permission boundary.
The daily check reports each role in a Keel account that lacks the boundary
as a high Finding. It does not check users and does not stamp existing
roles. CAM users are covered by the standing access report below.

## Human access (Identity Center)

`KEEL_CIC_ZONE_ID` names the Tencent CIC zone. It takes effect only when
`KEEL_TENCENT_ORG_REGION` is also set. Teams are eligible for role
templates per Environment (read-only, operator, …; `keel-access@1`). An
Access Grant is requested with a reason. Each template caps its length:
read-only 8 hours, data-reader 4, deployer 4, operator 2. Production write
needs Team lead approval and a second approval. The second approver is a
security lead, or the Tenant approver when the Tenant requires approval. Keel assigns the CIC role
configuration for the window and removes it at expiry, even across restarts.
The daily **standing access** report raises a critical Finding for any CIC
assignment in a production account outside an active Grant and for any CAM
user in a production account.

## Break-glass

Register break-glass identities with `POST /v1/breakglass`. Platform admins
and security leads of the home Tenant may do this. Hardware MFA is
required. Any CloudAudit sign-in by one
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
