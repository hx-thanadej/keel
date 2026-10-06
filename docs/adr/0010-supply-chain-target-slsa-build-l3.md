---
status: proposed
date: 2026-10-06
---

# Supply chain target: SLSA v1.2 Build L3 + verified at admission

Every Artifact built on the Golden Path carries signed SLSA provenance
(`slsa.dev/provenance/v1`) and an SBOM (CycloneDX 1.7 primary, SPDX export),
signed with Sigstore keyless signing and stored as OCI referrers in our own
registry. We do not depend on the public Rekor log, which stopped storing
attestations in Rekor v2. Builds run on ephemeral, isolated runners with caches
partitioned by trust level. The cluster admits only digests signed by our
builder identity from an expected repo, protected ref and workflow.

## Consequences

- Provenance alone is not trusted (malware shipped with valid provenance in
  2026). A Release policy also checks builder ID, repo, protected branch,
  workflow file and trigger (denying `pull_request_target`/fork contexts), and
  emits a Verification Summary Attestation.
- Registry: a regional registry in-account (Tencent TCR) replaces cross-region
  ghcr pulls. This also cuts the CI build-cache egress observed in Sep 2026.
- Dependency ingestion goes through a proxy with a minimum release age
  (cooldown) and install scripts off by default.
