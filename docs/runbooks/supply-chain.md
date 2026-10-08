# Runbook: supply chain and policy (M4)

## Build

Use the reusable workflow in `deploy/github/workflows/keel-build.yml` on
ephemeral runners (`deploy/arc`). The build job has no credentials; the
publish job signs with Sigstore (keyless), attaches SLSA provenance and an
SBOM, and uploads SARIF.

## Keel's checks

| Step | Endpoint | Gate |
|---|---|---|
| Scanner results | `POST /services/{s}/scans` (SARIF, pipeline OIDC) | Findings with SLAs; "nothing reported" resolves absent ones |
| Provenance | `POST /releases/{r}/attestations` | Sigstore bundle verified against `KEEL_SIGSTORE_TRUSTED_ROOT` (SCTs required), builder `KEEL_TRUSTED_BUILDER`; Keel signs a VSA with `KEEL_DIGEST_KEY` |
| SBOM | `POST /releases/{r}/sbom` | CycloneDX/SPDX; OSV re-matched daily (`KEEL_OSV`) |
| VEX | `POST /vex` | `not_affected` statements suppress matching Findings |
| Exceptions | `/exceptions` | time-boxed, approved, expire automatically |
| Admission | `POST /projects/{p}/environments/{e}/admission` | renders a Kyverno ImageValidatingPolicy requiring Keel's VSA, plus a digest-only ValidatingAdmissionPolicy |

Promotion requires a passing VSA for every image by default
(`KEEL_REQUIRE_VSA=0` turns it off, e.g. while onboarding). Private GitHub repositories sign through GitHub's Sigstore
instance (`KEEL_SIGSTORE_GITHUB_PRIVATE`).

## Evidence

`GET /evidence?from=&to=` returns a signed `keel-evidence@1` bundle;
`keel-api verify-evidence bundle.json <pubkey>` checks it offline. CISA KEV
matches against deployed software start the EU CRA reporting clock
(`KEEL_KEV`).
