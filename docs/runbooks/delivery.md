# Runbook: Golden Path delivery (M3)

## GitHub organisation

Every GitHub integration authenticates as the Keel GitHub App
([below](#the-keel-github-app)). Keel holds no personal access token.

- With `KEEL_GITHUB_OWNER` set, the hourly reconcile enforces
  `keel-github@1`: custom properties (`keel-tenant`, `keel-project`, `keel-tier`), a default-branch ruleset (1
  review, CODEOWNERS, `KEEL_GITHUB_REQUIRED_CHECKS`) and a stricter one for
  `keel-tier=prod` (2 reviews, last-push approval), the OIDC subject-claim
  template, and the Actions policy (SHA pinning, read-only `GITHUB_TOKEN`,
  approval for outside contributors' workflows, `KEEL_GITHUB_ALLOWED_ACTIONS`).
  Drift becomes Findings. Set `KEEL_GITHUB_REMEDIATE=1` to fix it. Set
  `KEEL_GITHUB_ORG=1` when `KEEL_GITHUB_OWNER` is an organisation.
- Some of this needs a paid plan (#8): on GitHub Free, rulesets on private
  repositories are unavailable and are reported, not enforced.

### The Keel GitHub App

Keel signs a short JWT with the App's private key and trades it for one-hour
installation tokens (ADR-0020). Each caller mints its own token, asking only
for that caller's permissions, and reuses it until five minutes before it
expires. Before each mint Keel checks that the installation is on
`KEEL_GITHUB_OWNER`; when it is on another account the mint fails with
`installation <id> is on "<login>", not "<owner>"`. Each GitHub call times
out after 30 seconds.

Grant the App exactly these permissions. A token can never carry more than
the App holds, and each caller asks for less (the per-caller table is in
[ADR-0020](../adr/0020-github-app-key-exception.md#consequences)).

| Permission | Access | Used by |
| --- | --- | --- |
| Repository: Administration | Read and write | governance remediation, Service Templates |
| Repository: Contents | Read and write | rightsizing, admission-policy and promotion pull requests, Service Templates, decision index, catalog sync |
| Repository: Metadata | Read | everything (GitHub grants it to every App) |
| Repository: Workflows | Read and write | Service Templates, only when `KEEL_REUSABLE_WORKFLOW` is set (the token asks for it only then) |
| Repository: Pull requests | Read and write | rightsizing, admission-policy and promotion pull requests |
| Repository: Code scanning alerts | Read | alert sync |
| Repository: Dependabot alerts | Read | alert sync |
| Repository: Secret scanning alerts | Read | alert sync, secret-scanning webhook |
| Organization: Administration | Read and write | governance (GitHub lists organisation rulesets only to write) |
| Organization: Custom properties | Admin | governance (schema, admin with `KEEL_GITHUB_REMEDIATE=1`), Service Templates (values) |
| Organization: Members | Read | Service Templates (team access) |
| Organization: Plan | Read | governance |
| Organization: Webhooks | Read and write | webhook catch-up |

Set it up as an organisation owner:

1. Create a GitHub App owned by the organisation (**Settings > Developer
   settings > GitHub Apps**). Turn its own webhook off. Grant the
   permissions in the table and nothing else.
2. Generate a private key and install the App on the organisation only,
   with access to **All repositories**. Templates create repositories, and
   sync and governance read every repository, so a fixed list goes stale.
3. Set `KEEL_GITHUB_APP_ID` to the App ID (or Client ID), and
   `KEEL_GITHUB_APP_INSTALLATION_ID` to the number at the end of the
   installation's settings URL. Store the PEM key in
   `KEEL_GITHUB_APP_PRIVATE_KEY` with Keel's other secrets.

Keel refuses to start when `KEEL_GITHUB_OWNER`, `KEEL_GITHUB_WEBHOOK_SECRET`
or `KEEL_TEMPLATES` is set and any of the three App settings is missing or
malformed, when the App is set without `KEEL_GITHUB_OWNER`, and when one of
the removed `KEEL_GITHUB_ADMIN_TOKEN`, `KEEL_GITHUB_WRITE_TOKEN` or
`KEEL_GITHUB_TOKEN` is set and the App is not. The error names the missing
settings or the removed variable.

#### Rotating the GitHub App key

Rotate the key every 90 days, and at once when it may have been exposed
(ADR-0020). GitHub lets the App hold more than one key, so there is no
downtime.

1. In the App's settings, under **Private keys**, choose **Generate a
   private key**. The old key keeps working.
2. Replace `KEEL_GITHUB_APP_PRIVATE_KEY` in the secret store with the new
   PEM and redeploy Keel.
3. Confirm the next `github governance` or `github webhook catch-up` log
   line has no error. Both run once at start.
4. Delete the old key in the App's settings. GitHub lists each key with
   the date it was added. Keep the newest.
5. Delete the downloaded PEM file.

On suspected exposure, delete the exposed key in step 4 even before step 3
succeeds. Every GitHub integration fails until the new key is deployed.

### Moving from personal access tokens

Keel before #231 read `KEEL_GITHUB_ADMIN_TOKEN`, `KEEL_GITHUB_WRITE_TOKEN`
and `KEEL_GITHUB_TOKEN`. It no longer reads them, and refuses to start when
any is set without the App. In this order:

1. Add the permissions in the table above to the existing Keel App, exactly
   those. If you set `KEEL_REUSABLE_WORKFLOW`, include Repository: Workflows,
   Read and write, or template creation fails. GitHub then asks the organisation to accept the new permissions on
   the installation (**Settings > GitHub Apps > Keel > Review request**). An
   organisation owner accepts. Until then mints that ask for a new
   permission fail.
2. Deploy the Keel version that carries #231 with the App settings in place.
3. Confirm, in the first hour, a log line with no error from each job you
   run: `github governance`, `github alerts`, `decision records`,
   `github webhook catch-up`, and the catalog sync. Open one rightsizing or
   promotion pull request if you use them.
4. Revoke the three personal access tokens in their owners' GitHub settings
   (**Settings > Developer settings > Personal access tokens**), then delete
   `KEEL_GITHUB_ADMIN_TOKEN`, `KEEL_GITHUB_WRITE_TOKEN` and
   `KEEL_GITHUB_TOKEN` from the secret store and the deployment environment.

### Governance webhook (Free and Team)

GitHub offers the organisation audit-log API only on Enterprise Cloud. On
Free and Team, Keel learns about governance changes from the organisation
webhook it already uses for secret-scanning alerts ([access.md](access.md)).
The hourly reconcile stays the source of truth for the end state. A
delivery that failed is redelivered by the catch-up job below, so its
Activity is still written.

Keel needs `KEEL_GITHUB_WEBHOOK_SECRET`, `KEEL_GITHUB_OWNER` and
`KEEL_GITHUB_ORG=1`. Receiving needs no token. Set it up as an organisation
owner under **Settings > Webhooks**. If the secret-scanning webhook exists,
edit it rather than adding a second one.

1. Payload URL: `https://<keel host>/v1/webhooks/github`.
2. Content type: `application/json`.
3. Secret: the value of `KEEL_GITHUB_WEBHOOK_SECRET`. Generate it with
   `openssl rand -hex 32` and store it with Keel's other secrets.
4. Choose **Let me select individual events** and tick: Branch protection
   configurations, Branch protection rules, Collaborator add, remove, or
   changed (`member`), Memberships, Organizations, Repositories, Repository
   rulesets, Secret scanning alerts, Security and analyses, Teams, and
   Visibility changes (`public`).
5. Save. GitHub sends a `ping`, which Keel answers with `202`.

Keel answers each delivery this way:

- `413` when the body is over 1 MiB and `401` when the
  `X-Hub-Signature-256` HMAC does not match. Nothing is recorded.
- `200 duplicate` for a delivery id it has already processed. The
  `webhook_deliveries` primary key enforces this, so a redelivery never
  records twice.
- `202 ignored` for an event from any organisation other than
  `KEEL_GITHUB_OWNER`. Nothing is recorded.
- `202 accepted` otherwise. Each event becomes an Activity of type
  `github.<event>.<action>` with source `github/org-webhook`. The Activity
  goes to the Tenant named by the repository's `keel-tenant` property, or
  to the home Tenant for organisation-level events and unlabelled
  repositories.

These changes also raise a `github_governance` Finding on the Repository.
It uses the reconciler's fingerprint, so the next reconcile updates it or
resolves it.

| Event | Weakens a protection Keel owns when |
| --- | --- |
| `repository_ruleset` | a `keel-github@1` ruleset (`keel-default-branch`, `keel-prod-tier`) is deleted, or after the change it no longer covers the policy: enforcement is not `active`, a bypass actor is added, a rule is removed, the required review count drops, a review flag the policy sets is turned off, a required check is removed, or a target branch or repository is excluded or dropped |
| `security_and_analysis` | secret scanning or push protection goes from `enabled` to anything else |

Stricter changes raise no Finding. Examples are more reviews, extra rules,
extra checks and wider targets. Rulesets Keel does not own also raise no
Finding. Classic branch protection, visibility, collaborators, teams and
membership are not protections Keel owns, so they are recorded as Activities
only.

#### Redelivering failed deliveries

GitHub does not retry a delivery that failed because Keel was down,
answered `5xx` or timed out. Every 15 minutes, and once at start, Keel reads
the hook's deliveries of the last 24 hours and asks GitHub to resend each one
that meets all of these conditions:

- No attempt for its delivery id (`guid`) got a `2xx`.
- The delivery id is not in `webhook_deliveries`, so Keel has not recorded it.
- It has had fewer than 3 attempts. A payload Keel keeps rejecting is left
  to the hourly reconcile.
- Its first attempt is inside the 24-hour window.

The redelivery arrives at the receiver with the original delivery id and a
fresh signature. It becomes one Activity, and a Finding if it weakens a
protection. Keel resends one delivery per second and stops the run on `403`
or `429`. Each run logs `github webhook catch-up` with the counts.

The job authenticates as the [Keel GitHub App](#the-keel-github-app) with a
token limited to `organization_hooks: write`. With it Keel lists the
deliveries and POSTs to `/orgs/{org}/hooks/{hook_id}/deliveries/{id}/attempts`
for Keel's own hook. It writes nothing else to GitHub. To turn it on, set
`KEEL_GITHUB_WEBHOOK_HOOK_ID` to the hook id. It is the number at the end of
the webhook's URL under **Settings > Webhooks**, or `gh api
/orgs/<org>/hooks --jq '.[] | [.id, .config.url]'`.

Without `KEEL_GITHUB_WEBHOOK_HOOK_ID`, Keel logs `github webhook catch-up
disabled` at start and redelivers nothing. A failed delivery then stays
missed until the next reconcile reports the drift.

## Service Templates

`KEEL_TEMPLATES` lists templates (`name=owner/repo@sha,…`, repositories in
the `KEEL_GITHUB_OWNER` organisation). Creating a Service
renders the template into a new repository with `catalog-info.yaml`,
CODEOWNERS, `.sops.yaml` (`KEEL_SOPS_AGE_PROD`/`_NONPROD`) and a caller of the
reusable build workflow (`KEEL_REUSABLE_WORKFLOW`, see `deploy/README.md`).
Uses the [Keel GitHub App](#the-keel-github-app).

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
deployment failed, which feeds DORA. Promotion pull requests use the
[Keel GitHub App](#the-keel-github-app). So do admission-policy and
rightsizing pull requests.
