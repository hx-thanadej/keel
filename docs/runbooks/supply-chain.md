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

With `KEEL_GITHUB_ADMIN_TOKEN` set, Keel syncs GitHub code scanning,
Dependabot and secret scanning for every Service with a GitHub `repository`
every 6 hours (#121). The token needs read access to code scanning alerts
(which covers analyses), Dependabot alerts and secret scanning alerts.

- Code scanning comes in as the SARIF GitHub itself holds. For each tool,
  Keel downloads the newest analysis of every category on the default branch
  and ingests them together as one full scan, once per analysis, so the
  Findings fingerprint exactly as a CI upload of the same SARIF and one alert is
  one Finding whoever uploaded it; a fixed alert resolves when the next analysis
  no longer reports it. An alert dismissed on GitHub resolves as `dismissed on
  GitHub: <reason>` and is left out of later ingests.
- A Dependabot alert is `vuln:<CVE or GHSA>:<service>` (CVE preferred), so the
  same CVE from Trivy or OSV is one Finding with several `tools`. A secret alert
  is a critical `secret` Finding (`secret:github:<repository id>:<number>`).
  The secret value is never requested (`hide_secret=true`), read or stored.
  Alerts no longer open on GitHub resolve the Finding (a Finding another
  scanner still reports stays open). VEX statements and Exceptions apply as for
  CI scans.
- Private repositories need GitHub Advanced Security (Code Security, Secret
  Protection) for these APIs. Each sync records, per Service, `ok`,
  `not_enabled`, `forbidden` or `error` for each alert type in the Service's
  `SyncGitHubAlerts` Activity (`status_detail`); `error` carries the HTTP
  status and GitHub's message. `not_enabled`, `forbidden` and `error` mean
  "unknown", never "no alerts": nothing of that type is ingested or resolved.
  A tool whose newest analysis failed on GitHub is left as it is. Lists follow
  GitHub's `Link` cursor, up to 100 pages of 100. For analyses that means the
  newest 10,000 on the default branch, so a category not analysed within them
  counts as removed.
