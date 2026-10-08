# Runbook: account vending, Landing Zone and CI identity (M3)

Keel creates a Tencent member account per Environment, applies the Landing
Zone baseline and gives the Environment's repositories a keyless CI role.
Nothing here uses long-lived keys (ADR-0007).

## One-time setup (organisation admin)

1. Keel calls the organisation APIs with its ambient identity, the TKE pod
   identity (OIDC) or the CVM instance role. In the Tencent organisation
   admin account give that role organisation read/write for units, member
   creation, SCP attach/detach and CIC (Identity Center) role configurations
   and assignments. Set `KEEL_TENCENT_AUTOMATION_ROLE` to its name. Keel does
   not assume it. The name only exempts the role from the identity guardrail
   SCP. Set `KEEL_TENCENT_ORG_ADMIN_UIN` and `KEEL_TENCENT_ORG_REGION`.
2. Keel assumes `KEEL_TENCENT_VENDING_ROLE` **inside** each new member
   account. It defaults to `OrganizationAccessControlRole`, which
   member-account creation makes.
3. Landing Zone drift runs daily and reports Findings. Set
   `KEEL_LANDING_ZONE_REMEDIATE=1` only after the guardrails were checked on
   a sandbox member account (#98). The SCP condition key and CloudAudit
   action names are still unverified.

## Vend an Environment

Vending is API-only. The portal has no vend action. Call
`POST /v1/tenants/{t}/projects/{p}/environments/{e}/vend` with
`{"provider": "tencent"}`. The durable flow runs organisation unit → member
account (name ≤ 25 chars) → wait until ready → register as a Cloud Account
→ Landing Zone baseline (`keel-baseline@1` SCPs that keep the account in the
organisation, protect CloudAudit and allow identities only via Keel) → CI
identity → permission boundary → registry (only when `KEEL_TCR_REGISTRY_ID`
is set). River retries each step. Cancel undoes the finished steps in
reverse. Watch the run under Delivery → Runs, which offers *Retry from the
failed step*. Cancel is API-only
(`POST /v1/tenants/{t}/flows/{flow}/cancel` with a reason).

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
