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

Keel held three long-lived personal access tokens:
`KEEL_GITHUB_ADMIN_TOKEN`, `KEEL_GITHUB_WRITE_TOKEN` and `KEEL_GITHUB_TOKEN`.
Each was tied to a person and carried every scope its owner chose. Since
#231 Keel reads none of them; every GitHub caller uses the App.

The webhook catch-up job (#226) needs to write to GitHub, to ask it to
redeliver missed organisation webhook deliveries. It authenticates as a
GitHub App installation. That makes the App's private key Keel's first
GitHub App credential. The key has no expiry.

## Decision

The GitHub App private key is a documented exception to ADR-0007.

- The key only signs a JWT that lives under ten minutes. Keel trades that
  JWT for an installation token that lives one hour and asks only for the
  permissions the caller needs. Each caller has its own token source, which
  reuses its token until five minutes before it expires. The table under
  Consequences lists every caller's permissions.
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
- No personal access token remains in Keel's code or configuration
  ([#231](https://github.com/hx-thanadej/keel/issues/231)). Keel refuses to
  start when a GitHub integration is configured (`KEEL_GITHUB_OWNER`,
  `KEEL_GITHUB_WEBHOOK_SECRET` or `KEEL_TEMPLATES`) without the App. The
  three tokens are revoked by an operator after the App change deploys
  ([delivery.md](../runbooks/delivery.md#moving-from-personal-access-tokens)).
- The App holds the union of the permissions below, so the key now guards
  organisation administration and repository writes, not one webhook
  permission. That makes the KMS-signing option above worth revisiting.
- Each caller's installation token asks for only its row. The levels are
  GitHub's for each endpoint, from
  [Permissions required for GitHub Apps](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps).
  Every caller reads repositories chosen at run time (Services' repositories,
  new template repositories, every repository for sync and governance), so
  no token is narrowed to a fixed repository list.

| Caller | Replaced | Endpoints | Installation token permissions |
| --- | --- | --- | --- |
| Rightsizing pull requests (`apply`) | `KEEL_GITHUB_WRITE_TOKEN` | `GET /repos/{o}/{r}` (metadata read); `GET .../git/trees/{sha}`, `GET .../contents/{path}`, `GET .../git/ref/{ref}` (contents read); `POST .../git/refs`, `PUT .../contents/{path}` (contents write); `POST .../pulls` (pull requests write); `GET .../pulls/{n}` (pull requests read) | `contents: write`, `pull_requests: write`, `metadata: read` |
| Admission-policy pull requests | `KEEL_GITHUB_WRITE_TOKEN` | same as rightsizing | same as rightsizing |
| Promotion pull requests and PR status sync | `KEEL_GITHUB_WRITE_TOKEN` | same as rightsizing | same as rightsizing |
| GitHub governance reconcile (`githubgov`) | `KEEL_GITHUB_ADMIN_TOKEN` | `GET /orgs/{org}` plan (organization plan read); `GET`/`PATCH /orgs/{org}/properties/schema` (custom properties read / admin); `GET /orgs/{org}/properties/values` (custom properties read); `GET`/`POST`/`PUT /orgs/{org}/rulesets[/{id}]` (organization administration write, also for GET); `GET`/`PUT /orgs/{org}/actions/oidc/customization/sub` and `/orgs/{org}/actions/permissions[/selected-actions\|/workflow\|/fork-pr-contributor-approval]` (organization administration read / write); `GET /orgs/{org}/repos`, `GET /repos/{o}/{r}/rulesets[/{id}]` (metadata read); `POST`/`PUT /repos/{o}/{r}/rulesets[/{id}]`, `PATCH /repos/{o}/{r}` (administration write) | organisation: `organization_administration: write`, `organization_custom_properties: read`, `organization_plan: read`, `metadata: read`. With `KEEL_GITHUB_REMEDIATE=1` also `administration: write` and `organization_custom_properties: admin`. A user owner gets `metadata: read`, plus `administration: write` when remediating |
| GitHub alert sync (`ghalerts`) | `KEEL_GITHUB_ADMIN_TOKEN` | `GET /repos/{o}/{r}/code-scanning/alerts` (code scanning alerts read); `GET .../dependabot/alerts` (Dependabot alerts read); `GET .../secret-scanning/alerts` (secret scanning alerts read) | `security_events: read`, `vulnerability_alerts: read`, `secret_scanning_alerts: read` |
| Secret-scanning webhook (`leaks`) | `KEEL_GITHUB_ADMIN_TOKEN` | `GET /repos/{o}/{r}/secret-scanning/alerts/{n}` | `secret_scanning_alerts: read` |
| Service Templates (`templates`) | `KEEL_GITHUB_ADMIN_TOKEN` | `GET /repos/{o}/{r}` (metadata read); `GET .../git/ref/{ref}` (contents read); `POST /repos/{t}/{r}/generate` (administration write, contents read); `GET`/`PUT .../contents/{path}` (contents read / write); `PATCH /orgs/{org}/properties/values` (custom properties write); `PATCH /repos/{o}/{r}` (administration write); `PUT /orgs/{org}/teams/{team}/repos/{o}/{r}` (members read, administration write) | `administration: write`, `contents: write`, `metadata: read`, `organization_custom_properties: write`, `members: read` |
| Decision index (`decisions`) | `KEEL_GITHUB_TOKEN` | `GET /repos/{o}/{r}/contents/{path}` | `contents: read` |
| Catalog sync (`catalogsync`) | `KEEL_GITHUB_TOKEN` | `GET /orgs/{org}/repos` or `/users/{u}/repos` (metadata read); `GET /repos/{o}/{r}/contents/{path}` (contents read) | `contents: read`, `metadata: read` |
| Webhook catch-up (`githubgov.Catchup`) | none (App since #226) | `GET /orgs/{org}/hooks/{id}/deliveries` (webhooks read); `POST .../deliveries/{id}/attempts` (webhooks write) | `organization_hooks: write` |
