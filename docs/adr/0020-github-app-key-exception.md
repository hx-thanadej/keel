---
status: accepted
date: 2026-10-12
deciders: thanadej@harmonyx.co
---

# A GitHub App private key is an accepted long-lived credential

## Context

[ADR-0007](./0007-no-long-lived-cloud-credentials-in-ci.md) says no
long-lived credentials, because stolen long-lived tokens drove the recent
supply-chain incidents. Keel follows it for clouds by assuming roles
keylessly.

GitHub has no keyless workload identity for a server outside GitHub
Actions. A GitHub OIDC token is issued only to a workflow run, and GitHub
accepts no federated identity from another issuer. Keel runs as a server, so
anything it does to GitHub needs a secret it holds.

Keel already holds three long-lived personal access tokens:
`KEEL_GITHUB_ADMIN_TOKEN`, `KEEL_GITHUB_WRITE_TOKEN` and `KEEL_GITHUB_TOKEN`.
Each is tied to a person and carries every scope its owner chose.

The webhook catch-up job (#226) needs to write to GitHub, to ask it to
redeliver missed organisation webhook deliveries. It authenticates as a
GitHub App installation. That makes the App's private key Keel's first
GitHub App credential. The key has no expiry.

## Decision

The GitHub App private key is a documented exception to ADR-0007.

- The key only signs a JWT that lives under ten minutes. Keel trades that
  JWT for an installation token that lives one hour and asks only for the
  permission the caller needs. The catch-up job asks only for
  `organization_hooks: write`.
- Before it mints a token, Keel checks that the installation is on
  `KEEL_GITHUB_OWNER`. It refuses otherwise, so a wrong installation id
  never yields a token for another organisation.
- The App is owned by the organisation, installed only on it, and granted
  only the permissions Keel's callers use.
- The key is stored in the platform secret store with Keel's other secrets.
  It never goes into a repository, an image or a log.
- The key is rotated every 90 days, and at once on suspected exposure.
  GitHub lets an App hold more than one active key, so a new key is added
  and deployed before the old one is deleted, with no downtime. The steps
  are in [delivery.md](../runbooks/delivery.md#rotating-the-github-app-key).
- New GitHub integrations use the App, not a personal access token.

## Considered options

- **Sign the App JWT with a non-exportable KMS key.** The PEM would not sit
  in Keel's environment. GitHub generates App keys itself, so the key must
  still be downloaded once and imported into KMS. It also adds a KMS signing
  path and its credentials for one 15-minute job. Rejected for now. It
  becomes worth doing when the personal access tokens move to the App and
  the key guards more than one permission.
- **Reuse `KEEL_GITHUB_ADMIN_TOKEN`.** No new secret, but the job would run
  with an administrator's full scopes, tied to a person, behind a token that
  never expires. That is the risk ADR-0007 exists to avoid.
- **Drop the catch-up job.** No new credential. A missed delivery then never
  becomes an Activity, and the hourly reconcile reports only the end state,
  not who changed what. The change record (ADR-0005) would have gaps.

## Consequences

- Keel holds one more long-lived secret. Its blast radius is one hour of the
  narrowest permission each mint asks for, on one organisation.
- Rotation is an operator task on a schedule. Nothing in Keel enforces the
  90 days.
- Keel still holds the three personal access tokens, which are the larger
  risk. Moving them to App installation tokens is tracked in
  [#231](https://github.com/hx-thanadej/keel/issues/231). Until then the
  exception sits beside them, not in place of them.
