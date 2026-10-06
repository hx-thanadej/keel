---
status: proposed
date: 2026-10-06
---

# No long-lived cloud credentials in CI: OIDC Workload Identity only

Pipelines authenticate to clouds, registries and package publishers only through
short-lived federated credentials (GitHub OIDC → Tencent
`sts:AssumeRoleWithWebIdentity`, AWS `AssumeRoleWithWebIdentity`, GCP WIF).
Trust policies pin the GitHub **immutable** subject (`owner@ID/repo@ID`) plus
environment, never repo names. This is a deliberate, enforced "no", because
stolen long-lived CI tokens drove the 2025–2026 supply-chain incidents
(tj-actions, Shai-Hulud, the Trivy action compromise).

## Consequences

- Tencent's CAM OIDC provider stores a static copy of GitHub's signing keys
  (`IdentityKey`) instead of fetching them. Keel runs a **key sync job** that
  diffs GitHub's JWKS and calls `UpdateOIDCConfig`, and alerts on federation
  failures. Without it, CI auth breaks when GitHub rotates keys.
- Tencent caps `oidc:sub` conditions at 10 values, so Keel uses one role per
  Project Environment and a custom GitHub `sub` template, not allow-lists.
- The signing/OIDC step is isolated from untrusted build steps (the TanStack
  lesson: an OIDC token scraped from runner memory published valid-looking
  provenance).
- Any leaked cloud key found by secret scanning triggers automated
  revoke → rotate → Activity.
