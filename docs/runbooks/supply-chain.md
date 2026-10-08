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

With `KEEL_GITHUB_ADMIN_TOKEN` set, Keel pulls open code scanning, Dependabot
and secret scanning alerts for every Service with a GitHub `repository`
every 6 hours and raises them as Findings (#121). The token needs read access
to code scanning alerts, Dependabot alerts and secret scanning alerts.

- A Dependabot alert is `vuln:<CVE or GHSA>:<service>` (CVE preferred), so the
  same CVE from Trivy or OSV is one Finding with several `tools`. Code scanning
  alerts use the SARIF fingerprint scheme; a secret alert is a critical
  `secret` Finding (`secret:github:<repository id>:<number>`). The secret value
  is never requested (`hide_secret=true`), read or stored.
- One source per code scanning tool. GitHub's alert list has no partial
  fingerprints, so its copy of a SARIF result is a different Finding from CI's.
  CI is the source while a full-scope SARIF upload from that tool reached Keel
  in the last 30 days (diff uploads never count); the sync then skips the
  tool's GitHub alerts (status `sarif`) and resolves GitHub's open Findings for
  it as "source handed over to CI uploads". Otherwise GitHub is the source, and
  CI's open Findings for each tool GitHub reports resolve as "source handed
  over to GitHub code scanning" before GitHub's copies are raised, so each
  handover resets the SLA clock once. The sync Activity records each handover
  with its tool, direction and count.
- Alerts dismissed or fixed on GitHub resolve the Finding (a Finding another
  scanner still reports stays open). VEX statements and Exceptions apply as for
  CI scans.
- Private repositories need GitHub Advanced Security (Code Security, Secret
  Protection) for these APIs. Each sync records, per Service, `ok`, `sarif`,
  `not_enabled`, `forbidden` or `error` for each alert type in the Service's
  `SyncGitHubAlerts` Activity (`status_detail`); `error` carries the HTTP
  status and GitHub's message. `not_enabled`, `forbidden` and `error` mean
  "unknown", never "no alerts": existing Findings of that type are kept.
  Lists follow GitHub's `Link` cursor, up to 100 pages of 100 alerts.
