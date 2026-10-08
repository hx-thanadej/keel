# Runbook: supply chain and policy (M4)

## Build

Use the reusable workflow in `deploy/github/workflows/keel-build.yml` on
ephemeral runners (`deploy/arc`). The build job has no credentials; the
publish job signs with Sigstore (keyless), attaches SLSA provenance and an
SBOM, and uploads SARIF.

## Keel's checks

Paths are relative to `/v1/tenants/{tenant}`.

| Step | Endpoint | Gate |
|---|---|---|
| Scanner results | `POST /services/{s}/scans` (SARIF, pipeline OIDC) | Findings with SLAs; a `scope=full` upload resolves absent ones, `scope=diff` only adds |
| Provenance | `POST /releases/{r}/attestations` | Sigstore bundle verified against `KEEL_SIGSTORE_TRUSTED_ROOT` (SCTs required), builder `KEEL_TRUSTED_BUILDER`; Keel signs a VSA with `KEEL_DIGEST_KEY` |
| SBOM | `POST /releases/{r}/sbom` | CycloneDX/SPDX; OSV re-matched daily (`KEEL_OSV`) |
| VEX | `POST /vex` | `not_affected` and `fixed` statements resolve matching Findings |
| Exceptions | `/exceptions` | time-boxed, approved, expire automatically |
| Admission | `POST /projects/{p}/environments/{e}/admission` | renders a Kyverno ImageValidatingPolicy requiring a keyless signature and SLSA provenance from `KEEL_TRUSTED_BUILDER`, plus a digest-only ValidatingAdmissionPolicy |

Admission does not check the VSA. Promotion does. Every promotion requires
a passing VSA for every image by default
(`KEEL_REQUIRE_VSA=0` turns it off, e.g. while onboarding). Private GitHub repositories sign through GitHub's Sigstore
instance (`KEEL_SIGSTORE_GITHUB_PRIVATE`).

## Evidence

`GET /v1/tenants/{tenant}/evidence?from=&to=` returns a signed `keel-evidence@1` bundle;
`keel-api verify-evidence bundle.json <pubkey>` checks it offline. CISA KEV
matches against deployed software start the EU CRA reporting clock
(`KEEL_KEV`).

## GitHub alerts

With `KEEL_GITHUB_ADMIN_TOKEN` set, Keel syncs GitHub Dependabot and secret
scanning alerts for every Service with a GitHub `repository` every 6 hours
(#121). It also syncs code scanning alerts for the Services that choose
GitHub as their code scanning source. The token needs read access to code
scanning, Dependabot and secret scanning alerts.

- Each Service has one code scanning source, `code_scanning_source`. It is
  `keel` by default, which means CI's SARIF uploads. The other value is
  `github`, which means GitHub's code scanning alerts. The source applies to
  code scanning results only, the kinds `sast` and `code_scan` (CodeQL,
  Semgrep, gosec, Bandit and unrecognised tools). Keel never merges the two,
  so a Service on `github` gets none of those from CI, and a Service on
  `keel` gets none from GitHub. Set it with
  `PATCH /v1/tenants/{tenant}/services/{service}` and a body such as
  `{"code_scanning_source": "github", "why": "..."}`. This needs the
  `service.update` permission for the Service's Team.
- Switching the source resolves the open code scanning Findings of the old
  source with the resolution `code scanning source changed to <source>`. The
  Activity records how many it resolved. Only code scanning Findings are
  resolved. Vulnerability, secret, IaC and workflow Findings are not touched.
- With `keel`, the sync records code scanning as `keel` and reads nothing
  from GitHub code scanning. CI uploads work as before.
- With `github`, each GitHub alert is one Finding,
  `scan:github:<repository id>:<alert number>`. It stays the same Finding
  when the code around it moves. Its detail holds the tool, the rule, the
  alert's most recent location and its GitHub link. When GitHub fixes the
  alert, the Finding resolves as `fixed on GitHub`. When someone dismisses
  it on GitHub, it resolves as `dismissed on GitHub: <reason>`. Only GitHub
  reopening the alert raises it again, as a new Finding. A Service without a
  `repository_id` cannot be keyed this way. Its code scanning status is
  `no_repository_id` and nothing is synced.
- With `github`, CI's SARIF uploads skip only results of the code scanning
  kinds, and a full upload never resolves a Finding of those kinds. Results
  of other kinds keep flowing and resolving as with `keel`: Trivy's CVEs,
  secret scanners (gitleaks, trufflehog), IaC scanners (checkov, tfsec, kics)
  and workflow scanners (zizmor).
- GitHub code scanning alerts of other kinds are skipped. A CVE-rule alert,
  for example from Trivy results uploaded to GitHub, raises no Finding, so a
  CVE is never counted twice and an Exception on its `vuln:` Finding covers
  it. The cost is that a CVE known only from a Trivy SARIF uploaded to GitHub
  and not to Keel is not synced. Dependabot, the SBOM/OSV matcher and CI's
  vulnerability results report vulnerabilities.
- Exceptions name Finding ids, so an Exception covers one GitHub alert. It
  stays in force while that alert stays open, wherever the alert moves. A
  new alert of the same rule needs its own Exception.
- A Dependabot alert is `vuln:<CVE or GHSA>:<service>`, with the CVE
  preferred. The same CVE from Trivy or OSV is therefore one Finding with
  several `tools`. A secret alert is a critical `secret` Finding,
  `secret:github:<repository id>:<number>`. The secret value is never
  requested (`hide_secret=true`), read or stored. An alert no longer open on
  GitHub resolves its Finding unless another scanner still reports it. VEX
  statements and Exceptions apply as for CI scans.
- Private repositories need GitHub Advanced Security (Code Security, Secret
  Protection) for these APIs. Each sync records, per Service, `ok`,
  `not_enabled`, `forbidden` or `error` for each alert type in the Service's
  `SyncGitHubAlerts` Activity (`status_detail`). An `error` carries the HTTP
  status and GitHub's message. `not_enabled`, `forbidden` and `error` mean
  "unknown", never "no alerts", so nothing of that type is raised or
  resolved. Lists follow GitHub's `Link` cursor, up to 100 pages of 100.
- To learn why an alert closed, Keel reads the dismissed and fixed lists,
  most recently updated first, and stops once it has found every alert it
  is looking for. A Finding whose alert is in neither list resolves as
  `no longer on GitHub`, for example after its analysis was deleted. If
  either list reaches the page cap first, that Finding stays open.
