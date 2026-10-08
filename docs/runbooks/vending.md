# Runbook: account vending, Landing Zone and CI identity (M3)

Keel creates a Tencent member account per Environment, applies the Landing
Zone baseline and gives the Environment's repositories a keyless CI role.
Nothing here uses long-lived keys (ADR-0007).

## One-time setup (organisation admin)

1. In the Tencent organisation admin account create the automation role Keel
   assumes (`KEEL_TENCENT_AUTOMATION_ROLE`) with organisation read/write for
   units, member creation, SCP attach/detach and CIC (Identity Center) role
   configurations and assignments. Set `KEEL_TENCENT_ORG_ADMIN_UIN` and
   `KEEL_TENCENT_ORG_REGION`.
2. Name the role Keel assumes **inside** each new member account
   (`KEEL_TENCENT_VENDING_ROLE`, created by member-account creation).
3. Landing Zone drift: runs daily and reports Findings. Set
   `KEEL_LANDING_ZONE_REMEDIATE=true` only after the guardrails were checked
   on a sandbox member account (#98 — the SCP condition key and CloudAudit
   action names are still unverified).

## Vend an Environment

Portal → Projects → Environment → *Vend account* (or
`POST /v1/tenants/{t}/projects/{p}/environments/{e}/vend`). The durable flow
runs: organisation unit → member account (name ≤ 25 chars) → wait until
ready → register as a Cloud Account → Landing Zone baseline (`keel-baseline@1`
SCPs: stay in the organisation, protect CloudAudit, identities only via Keel)
→ CI identity. Each step is retried by River and
undone in reverse on cancel. Watch it under Delivery → Flows; retry or
cancel from there.

## CI identity

Keel registers GitHub's OIDC issuer in the member account (CAM OIDC provider
with automatic key rotation) and one role per Environment whose trust is
limited to the Service repositories' numeric ids and the Environment's branch
or environment claim. The daily `ci identity sync` re-applies it when
repositories change.

## Troubleshooting

- *Flow failed at `account`*: the organisation's member quota or name clash;
  fix and *Retry*.
- *CI role assume fails*: compare the workflow's `sub` claim with the
  role's trust in the Activity detail of `keel.ci_identity.*`.
