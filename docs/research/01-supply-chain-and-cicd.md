# 01 — Software supply chain security, CI/CD security, secure SDLC frameworks

Research date: 2026-10-06. Primary sources only (spec bodies, project docs/repos, vendor first-party docs, government publications). Versions were checked live on this date, mostly through each project's GitHub releases API (`gh api repos/<org>/<repo>/releases/latest`). Anything that could not be traced to a primary source is marked **UNVERIFIED**.

## TL;DR

- **SLSA v1.2** (approved 2025-11-24) is current. It now has two tracks: **Build L0–L3** and a new **Source L1–L4**. No v1.3 yet. Build Environment and Dependency tracks are still in development. Provenance is the in-toto Statement v1 with predicate type `https://slsa.dev/provenance/v1`.
- **Sigstore keyless signing is the de facto signing layer.** Current versions: cosign **v3.1.3**, Rekor v2 (tile-backed, GA 2025-10-10), Fulcio v1.9.0. Cosign v3 now signs with the Sigstore *bundle* format by default. GitHub artifact attestations (`actions/attest@v4`), npm trusted publishing/provenance and PyPI PEP 740 attestations are all built on it.
- **SBOM formats:** CycloneDX **1.7** (2025-10-21; ECMA-424) and SPDX **3.0.1** (3.1-RC1 out since 2026-01). CISA replaced the 2021 NTIA list with the **2026 Minimum Elements** (2026-07-29). It adds new elements such as hash, license, tool name/version, generation context and author signature.
- **Frameworks:**
  - NIST **SSDF 1.1** (SP 800-218) is still the final version. **SSDF 1.2** (SP 800-218r1) has been an initial public draft since 2025-12-17 and adds PO.6 and PS.4.
  - SP 800-218A (gen-AI profile) is final (2024-07).
  - OWASP **SAMM v2.2.0** (2026-07); OWASP **DSOMM v5.1.0** (2026-09), which now has an Agentic AI dimension.
  - OpenSSF Scorecard v5.5.0 (20 checks) and OSPS Baseline v2026.08.28.
- **EU CRA:** vulnerability and incident **reporting obligations have applied since 2026-09-11** (24h/72h/14d via the ENISA Single Reporting Platform). The main obligations apply from 2027-12-11.
- **2025–2026 incidents all exploit CI/CD trust:**
  - tj-actions (Mar 2025): mutable tags.
  - Shai-Hulud (Sep 2025) and Shai-Hulud 2.0 (Nov 2025): an npm worm that stole tokens.
  - Trivy/trivy-action (Mar 2026): tags force-pushed after a non-atomic credential rotation.
  - axios (Mar 2026): a malicious dependency.
  - Mini Shai-Hulud/TanStack (May 2026): `pull_request_target` + cache poisoning + OIDC token theft. It shipped malware **with valid SLSA provenance**.
  - Nx Console (May 2026).
- **GitHub's response:** SHA-pinning enforcement policy, immutable releases, safer `pull_request_target` defaults (checkout v7), read-only cache for untrusted triggers, workflow execution rules (pull_request_target blocked by default on public repos from 2026-11-02), and immutable OIDC `sub` claims. On npm: classic tokens revoked, install scripts off by default in v12, and staged publishing.
- **Lesson for us: provenance is necessary but not sufficient.** The platform must also enforce *which* workflow, branch and trigger may produce a release, isolate caches and signing identity from build steps, and verify policy at admission.

---

## 1. SLSA (Supply-chain Levels for Software Artifacts)

- **Current version: v1.2, status "Approved".** Versions listed: v1.2 (current), v1.1, and a Working Draft [https://slsa.dev/spec/]. v1.2 was announced **2025-11-24**, is backward compatible with v1.1, and added the Source Track. Next tracks in development: **Build Environment Track** and **Dependency Track** [https://slsa.dev/blog/2025/11/announce-slsa-v1.2].
- The blog has no v1.3 or new-track release as of 2026-10. The latest post is dated 2026-05-15 [https://slsa.dev/blog].
- v1.2 also updated the threat model for Source mitigations and restructured the spec for multiple tracks. Source levels were reorganised between RCs: L2 covers history and provenance, L3 covers continuous enforcement [https://slsa.dev/spec/v1.2/whats-new].

### Build track [https://slsa.dev/spec/v1.2/build-track-basics], [https://slsa.dev/spec/v1.2/build-requirements]

| Level | Name | Key requirement |
|---|---|---|
| L0 | No guarantees | — |
| L1 | Provenance exists | Consistent build process; provenance auto-generated showing builder, process and inputs |
| L2 | Hosted build platform | Hosted platform **generates and signs** provenance (authentic) |
| L3 | Hardened builds | Provenance **unforgeable**. Build **isolated**: ephemeral environment per build, no access to platform secrets/signing material, no cross-build interference or **cache poisoning** |

- There is no Build L4 in v1.2.
- Producer duties at all levels: choose an appropriate platform, follow a consistent process, distribute provenance [https://slsa.dev/spec/v1.2/build-requirements].

### Source track [https://slsa.dev/spec/v1.2/source-requirements]

| Level | Name | Key requirement |
|---|---|---|
| L1 | Version controlled | Use a VCS; immutable, uniquely identifiable revisions |
| L2 | History & Provenance | Preserve change history; generate **source provenance attestations** |
| L3 | Continuous Technical Controls | Org technical controls continuously enforced on protected branches; consumers can verify them |
| L4 | Two-Party Review | Two trusted persons review before merge |

- Common requirements across levels: identity management, human-readable diffs, and source **VSAs** (Verification Summary Attestations).

### Provenance format [https://slsa.dev/spec/v1.2/build-provenance]

- The envelope is an in-toto Statement: `_type: https://in-toto.io/Statement/v1`, plus `subject[]` (name + digest), `predicateType: https://slsa.dev/provenance/v1` and `predicate`.
- The predicate has two parts:
  - `buildDefinition` {`buildType`, `externalParameters` (untrusted, user-controlled; must be verified), `internalParameters`, `resolvedDependencies`}
  - `runDetails` {`builder.id`, `metadata`, `byproducts`}
- **Consumer verification** [https://slsa.dev/spec/v1.2/verifying-artifacts]:
  1. Verify the envelope signature against the trust roots and check that the builder ID is in an allow-list.
  2. Check that the subject digest equals the artifact digest.
  3. Compare the source repo, `buildType` and `externalParameters` against expectations.
  - Verifiers SHOULD reject unrecognised `externalParameters`. A VSA can short-circuit recursive verification.
- **Boundary of SLSA (2026-05 post-mortem)** [https://slsa.dev/blog/2026/05/mini-shai-hulud-what-slsa-can-and-cannot-do]:
  - In Mini Shai-Hulud, 84 malicious `@tanstack` artifacts carried cryptographically valid provenance, because the attacker extracted the OIDC token from runner memory.
  - Provenance shows *which workflow* built an artifact. It does not show that the run was authorised, came from a protected branch or a legitimate PR, or used an unpoisoned toolchain.
  - The post recommends Build L3 builders where the signing identity is structurally inaccessible, plus policy that combines build provenance with source attestations, monitoring for publishes from failed runs, VSAs, and independent rebuilders.

## 2. in-toto attestations, Sigstore, ecosystem attestations

### in-toto Attestation Framework [https://github.com/in-toto/attestation]

- **Latest release v1.2.0 (2026-03-18).** It added Simple Verification Result (SVR) and SPDX 3 predicates and Rust bindings. Earlier releases: v1.1.2 (2025-06-14), v1.1.1 (2025-01-24) [https://github.com/in-toto/attestation/releases].
- **Layers:**
  - Envelope: DSSE signature wrapper.
  - Statement: subject digests + predicateType.
  - Predicate: the typed metadata.
  - Bundle: a collection of attestations.
- **Vetted predicates** in `spec/predicates`: provenance (SLSA), link, SPDX (2 and 3), CycloneDX, VSA, vulns, SCAI, runtime-trace, test-result, release, reference, SVR [https://github.com/in-toto/attestation/tree/main/spec/predicates].

### Sigstore

- **Keyless flow** [https://docs.sigstore.dev/about/overview/]:
  1. The client obtains an OIDC token (person, service account, or CI workflow identity).
  2. **Fulcio** issues a short-lived X.509 certificate binding that identity to an ephemeral key. The key is discarded after signing.
  3. The signature, certificate and digest are recorded in the **Rekor** transparency log.
  4. Verifiers check the signature, the certificate chain to the Sigstore root, Rekor inclusion, and that the **identity (SAN) + OIDC issuer** match policy.
- Fulcio certificates are **valid for 10 minutes** [https://docs.sigstore.dev/certificate_authority/overview/].
- **Current releases** (GitHub releases API, 2026-10-06): cosign **v3.1.3** (2026-08-06), Fulcio **v1.9.0** (2026-10-05), rekor (v1 server) v1.5.4 (2026-08-20), rekor-tiles (Rekor v2) **v2.3.0** (2026-06-10), policy-controller v0.15.1 (2026-03-26).
- **Cosign v3** (2025-10-08) makes three opt-in features the default [https://blog.sigstore.dev/cosign-3-0-available/]:
  - the **Sigstore bundle** format (`--new-bundle-format`), which supports offline verification;
  - `--trusted-root`;
  - `--use-signing-config`, so log shards can rotate without a client update.
  - About half the flags are slated for removal in v4. Defaults align with PyPI, Maven Central and Homebrew.
- **Rekor v2 GA** (2025-10-10) [https://blog.sigstore.dev/rekor-v2-ga/]:
  - The log is now tile-backed and cheaper to run.
  - Removed: built-in signed timestamps (moved to a separate TSA), search index, and attestation storage. Users must store attestations alongside artifacts (e.g. OCI referrers).
  - Only `hashedrekord` and `dsse` entry types remain.
  - Rekor v1 keeps running; new uploads will be frozen with 1 year's notice.
  - Supported from cosign v2.6.0+.
- **Implication:** store attestations in our own registry/artifact store. Do not rely on Rekor for retrieval.

### Ecosystem attestations

- **GitHub artifact attestations** [https://docs.github.com/en/actions/concepts/security/artifact-attestations]:
  - Signed SLSA provenance (and optionally SBOM) that links the artifact to the workflow, repo, commit SHA and trigger.
  - **Build L2 by default; Build L3 when built in a reusable workflow** (the build is isolated from the caller).
  - Public repos sign with the Sigstore public-good instance and Rekor. Private repos sign with **GitHub's private Sigstore instance**, and attestations are stored only in GitHub.
  - Verify with `gh attestation verify`.
  - GitHub warns that attestations are not a security guarantee by themselves: you must define policy.
- **Actions and plan availability:**
  - `actions/attest-build-provenance` v4.2.2 (2026-08-06) is, **as of v4, a wrapper on `actions/attest`**.
  - Required permissions: `id-token: write`, `attestations: write`, `contents: read` (+ `packages: write` for images).
  - Available for public repos on all current plans; private/internal repos need **GitHub Enterprise Cloud**.
  - Sources: [https://github.com/actions/attest-build-provenance], [https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations].
- **npm trusted publishing** [https://docs.npmjs.com/trusted-publishers]:
  - OIDC publish from GitHub Actions (GitHub-hosted runners), GitLab.com shared runners and CircleCI cloud. **Self-hosted runners are not supported.**
  - Provenance is generated automatically for GitHub and GitLab.
  - Requires npm ≥ 11.5.1 and Node ≥ 22.14.0. npm recommends "Require 2FA and disallow tokens".
  - Trusted publishing went GA on 2025-07-31 [https://github.blog/changelog/2025-07-31-npm-trusted-publishing-with-oidc-is-generally-available/].
- **PyPI PEP 740 attestations** [https://docs.pypi.org/attestations/]:
  - Predicates: SLSA Provenance and PyPI Publish.
  - Signers: Trusted Publishers (GitHub Actions, GitLab CI/CD, Google Cloud, ActiveState).
  - At most 2 attestations per file (one per predicate type).

## 3. SBOM and VEX

- **CycloneDX** [https://cyclonedx.org/specification/overview/]:
  - **v1.7 released 2025-10-21.** The latest spec repo tag is 1.7.2 (2026-09-17) [https://github.com/CycloneDX/specification/releases].
  - Standardised as **ECMA-424** (edition published 2025-12-10). Owned by OWASP; Ecma TC54.
  - Covers SBOM, SaaSBOM, HBOM, CBOM (crypto), AI/ML-BOM, VEX/VDR and attestations (CDXA). Formats: JSON, XML, Protobuf.
- **SPDX:**
  - **Current stable 3.0.1 (2024-12-17).** **3.1-RC1 published 2026-01-24** (pre-release) [https://github.com/spdx/spdx-spec/releases].
  - 3.1 extends scope to safety, services, hardware and operations [https://spdx.dev/spdx-3-1-ontology-and-schema-available-for-review/].
  - The ISO standard is **ISO/IEC 5962:2021**, which corresponds to SPDX 2.2.1 [https://spdx.dev/use/specifications/], [https://github.com/spdx/spdx-spec/tags].
- **Practical split:** CycloneDX is more security- and VEX-oriented and widely emitted by scanners. SPDX 2.3 remains the most widely used for licence compliance; SPDX 3 tooling is still maturing (**UNVERIFIED** adoption claim, no primary source). Platform should ingest both and emit at least CycloneDX 1.6+/SPDX 2.3.
- **CISA 2026 Minimum Elements for an SBOM** [https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom], [https://www.cisa.gov/sites/default/files/2026-07/2026_cisa_sbom_minimum_elements_508c.pdf]:
  - Published **2026-07-29** jointly with NSA, FBI and international partners. It replaces the 2021 NTIA minimum elements (the 2025 draft was open for comment until 2025-10-03).
  - Applies to all software, including OSS, AI and SaaS.
  - **Data fields:**
    - SBOM Author (major update)
    - **SBOM Author Signature (new)**
    - **SBOM Data Format Name and Version (new)**
    - **SBOM Generation Context (new)**, e.g. source / build / binary
    - SBOM Timestamp
    - **SBOM Tool Name and Tool Version (new)**
    - **SBOM Version (new)**
    - Component Producer (renamed from Supplier Name)
    - Component Name
    - Component Version
    - Component Identifiers
    - Component Dependency Relationship
    - **Component Hash Value and Hash Algorithm (new)**
    - **Component License (new)**
  - **Practices:** Coverage (replaces Depth), Explicitly Identifying Unknown Information (replaces Known Unknowns), Frequency, Distribution and Delivery, Accommodation of Updates, Machine-Processable Data. "Access Control" was removed.
- **VEX:**
  - **OpenVEX v0.2.0** spec [https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md]:
    - Statuses: `not_affected` | `affected` | `fixed` | `under_investigation`.
    - `not_affected` MUST carry a machine-readable `justification` (e.g. `component_not_present`) or an `impact_statement`. This aligns with the CISA Minimal Requirements for VEX.
    - The spec repo's last release was 2023-08 [https://github.com/openvex/spec/releases].
  - **CSAF:**
    - CSAF 2.0 has been an OASIS Standard since 2022-11-18. It has a VEX profile (Profile 5).
    - **CSAF 2.1 is still a Committee Specification Draft (CSD03, dated 2026-09-11)**, not yet an OASIS Standard [https://docs.oasis-open.org/csaf/csaf/v2.1/csaf-v2.1.html].
  - CycloneDX also embeds VEX natively.

## 4. Secure SDLC frameworks and regulation

- **NIST SSDF:**
  - **SP 800-218 v1.1 (Feb 2022) is the current final version** [https://csrc.nist.gov/projects/ssdf].
  - **SP 800-218r1 ipd = SSDF v1.2 draft, published 2025-12-17**, comments closed 2026-01-30, issued per EO 14306. It is **not final as of 2026-10-06** [https://csrc.nist.gov/pubs/sp/800/218/r1/ipd], [https://csrc.nist.gov/projects/ssdf/news].
  - Four practice groups: PO (Prepare the Organization), PS (Protect Software), PW (Produce Well-Secured Software), RV (Respond to Vulnerabilities).
  - v1.2 adds two practices [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218r1.ipd.pdf, Appendix B]:
    - **PO.6 Continuous Process Improvement**: update dev environments for new threats, e.g. add scanners for malicious content in supplier artifacts; improve dev-environment logging/audit; adopt zero trust.
    - **PS.4 Updates Are Robust and Reliable**: test releases; tiered/canary/staged roll-outs.
  - v1.2 also adds examples across PW.1, PW.4, PW.5, PW.8, PW.9, RV.1 and RV.2, and drops the EO 14028 references.
  - **SP 800-218A** (SSDF Community Profile for generative AI / dual-use foundation models) has been **final since 2024-07-26**. It adds AI model-artifact practices [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf].
- **OWASP SAMM:**
  - Model release **v2.2.0 (2026-07-06)**; previous v2.1.0 (2024-09) [https://github.com/owaspsamm/core/releases].
  - Structure: 5 business functions (Governance, Design, Implementation, Verification, Operations) × 3 practices = 15 practices, each with **2 streams × 3 maturity levels** [https://owaspsamm.org/model/].
  - Implementation → **Secure Build** has two streams [https://owaspsamm.org/model/implementation/secure-build/]:
    - Build Process: L3 = non-compliant artifacts fail the build.
    - Software Dependencies: L1 = BOM; L3 = deps get the same analysis as first-party code.
- **OWASP DSOMM:**
  - Data model **v5.1.0 (2026-09-21)**, which added a "minimum release age" activity [https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel-data/releases].
  - **Dimensions:** Build & Deployment, Culture & Organization, Implementation, Information Gathering, Test & Verification, and a new **Agentic AI** dimension (Data Protection, Guidance, Isolation, Verification).
  - **5 levels:** L1 basic understanding → L5 advanced deployment at scale.
  - Maps to SAMM v2 and ISO 27001.
  - Sources: [https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel-data/tree/main/src/assets/YAML/default], [https://dsomm.owasp.org/].
  - Good fit as the activity catalogue behind a platform "maturity score".
- **OpenSSF Scorecard:**
  - **v5.5.0 (2026-04-23)** [https://github.com/ossf/scorecard/releases/latest].
  - **20 checks:** Binary-Artifacts, Branch-Protection, CI-Tests, CII-Best-Practices, Code-Review, Contributors, Dangerous-Workflow, Dependency-Update-Tool, Fuzzing, License, Maintained, Packaging, Pinned-Dependencies, SAST, SBOM, Security-Policy, Signed-Releases, Token-Permissions, Vulnerabilities, Webhooks [https://github.com/ossf/scorecard/blob/main/docs/checks.md].
  - v5.5.0 changes: Branch-Protection reads rulesets; Dangerous-Workflow detects `toJSON(github.event)`; a **Scorecard v6 proposal aligns with OSPS Baseline**.
- **OpenSSF OSPS Baseline:**
  - **v2026.08.28.** Mandatory controls per project maturity level.
  - Control families: AC (access control), BR (build & release), DO (docs), LE (legal), QA, SA (security assessment), VM (vulnerability mgmt) [https://baseline.openssf.org/].
  - The family names are expanded from the abbreviations (**UNVERIFIED**: not shown on the fetched page).
- **OpenSSF S2C2F** (Secure Supply Chain Consumption Framework):
  - Last tagged v1.1 (2022-10) [https://github.com/ossf/s2c2f].
  - **8 practices:** Ingest, Scan, Inventory, Update, Audit, Enforce, Rebuild, Fix+Upstream.
  - **4 maturity levels** [https://github.com/ossf/s2c2f/blob/main/specification/framework.md]:
    - L1: package cache + inventory + scan/update.
    - L2: secure ingestion config, faster MTTR, incident response.
    - L3: proactive analysis, malware scanning before download, internal source mirrors.
    - L4: rebuild OSS on trusted infrastructure (aspirational).
- **CISA Secure by Design** [https://www.cisa.gov/securebydesign], [https://www.cisa.gov/securebydesign/pledge]:
  - Principles: own customer security outcomes, radical transparency, lead from the top.
  - **Pledge goals (7):** MFA, no default passwords, reduce entire vulnerability classes, increase patch uptake, publish a VDP, CVEs with accurate CWE/CPE, evidence of intrusions (customer logs).
  - 200+ signatories.
  - The pledge launch date (May 2024) is not on the fetched page: **UNVERIFIED**.
  - CISA also published "Open-Source Software Security Principles and Practices" (2026-08) [https://www.cisa.gov/sites/default/files/2026-08/open-source-software-security-principles-and-practices.pdf] (not reviewed in depth).
- **EU Cyber Resilience Act (Regulation (EU) 2024/2847)** [https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act], [https://digital-strategy.ec.europa.eu/en/policies/cra-summary], [https://digital-strategy.ec.europa.eu/en/policies/cra-reporting]:
  - **Timeline:**
    - In force 2024-12-10.
    - Conformity-assessment-body notification provisions from **2026-06-11**.
    - **Reporting obligations from 2026-09-11** (now live).
    - Main obligations from **2027-12-11**.
    - Commission guidance published 2026-07-27.
  - **Reporting:** actively exploited vulnerabilities and severe incidents, via the **ENISA CRA Single Reporting Platform**:
    - early warning ≤ 24h;
    - notification ≤ 72h;
    - final report ≤ 14 days after a fix is available (vulnerabilities) or ≤ 1 month (incidents).
    - This applies to products already on the market [https://commission.europa.eu/news-and-media/news/safer-and-more-secure-digital-products-2026-09-11_en], [https://www.enisa.europa.eu/news/the-cra-single-reporting-platform-is-launched].
  - **Annex I:** Part I covers product properties; Part II covers vulnerability handling during a declared **support period** (end month/year shown at purchase). Open-source stewards have a light regime with no fines.
  - **SBOM duty:** Annex I Part II(1) requires an SBOM "in a commonly used and machine-readable format covering at the very least the top-level dependencies". The support period must be **≥ 5 years** unless expected use is shorter (Art. 13(8)).
    - **UNVERIFIED from primary**: EUR-Lex was unreachable from this environment. The wording was confirmed only via secondary sources. Re-check against https://eur-lex.europa.eu/eli/reg/2024/2847/oj.

## 5. CI/CD hardening

### OWASP Top 10 CI/CD Security Risks [https://owasp.org/www-project-top-10-ci-cd-security-risks/]

- **The 10 risks:**
  1. CICD-SEC-1 Insufficient Flow Control
  2. SEC-2 Inadequate IAM
  3. SEC-3 Dependency Chain Abuse
  4. SEC-4 **Poisoned Pipeline Execution (PPE)**
  5. SEC-5 Insufficient Pipeline-Based Access Controls
  6. SEC-6 Insufficient Credential Hygiene
  7. SEC-7 Insecure System Configuration
  8. SEC-8 Ungoverned 3rd-party Services
  9. SEC-9 Improper Artifact Integrity Validation
  10. SEC-10 Insufficient Logging & Visibility
- The list has not been revised since the original (2022) edition; that date is not shown on the page (**UNVERIFIED** date).
- The incidents below map directly onto SEC-1, SEC-3, SEC-4, SEC-5, SEC-6 and SEC-9.

### GitHub Actions hardening [https://docs.github.com/en/actions/reference/security/secure-use]

- **Pin actions to a full-length commit SHA.** This is "the only way to use an action as an immutable release". Verify the SHA is from the upstream repo, not a fork. Keep pins fresh with Dependabot.
- **Org-level enforcement:**
  - The allowed-actions policy can **require SHA pinning** and **block** specific actions/versions (`!owner/repo@ref`), effective 2025-08-15 [https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/].
  - **Coming:** a workflow-level `dependencies:` lockfile that locks transitive actions by SHA (2026 roadmap: preview in 3–6 months, GA in about 6 months from 2026-03-26) [https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/].
- **`GITHUB_TOKEN` least privilege:** default to read-only and grant `permissions:` per job. Use CODEOWNERS on `.github/workflows/`. Disable Actions creating or approving PRs.
- **Script injection:** never interpolate `${{ github.event.* }}` into `run:`. Pass the value through `env:` and quote it. Scan workflows with CodeQL (GitHub calls this the most critical action [https://github.blog/security/supply-chain-security/securing-the-open-source-supply-chain-across-github/]) and/or zizmor (v1.30.1) [https://github.com/zizmorcore/zizmor].
- **`pull_request_target` / `workflow_run`:** avoid them, and never check out fork code in them. Platform changes:
  - Since **2025-12-08**, the workflow file and checkout for `pull_request_target` always come from the **default branch** [https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/].
  - **actions/checkout v7** (GA 2026-06-18) refuses fork-head checkouts in these triggers unless `allow-unsafe-pr-checkout` is set. This was backported to supported majors on 2026-07-20 [https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/].
  - **Read-only Actions cache tokens** for untrusted triggers (2026-06-26) [https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/], plus a `cache-mode` read/write control per workflow/job (2026-09-10) [https://github.blog/changelog/2026-09-10-control-github-actions-cache-access-with-cache-mode/].
  - **Workflow execution protections GA (2026-09-17):** actor/event rulesets, evaluate mode, and a default rule disabling `pull_request_target` on public repos with **enforcement from 2026-11-02** [https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available/].
- **OIDC to cloud** (AWS, Azure, GCP, Vault) instead of long-lived secrets [https://docs.github.com/en/actions/reference/security/secure-use].
  - The OIDC **`sub` claim now carries immutable owner/repo IDs** (`repo:org@123/repo@456:...`). This blocks repo-name-recycling attacks.
  - It is opt-in, and enforced for new or renamed repos from 2026-07-15 [https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens/].
  - Cloud trust policies must pin `sub` (repo + ref/environment), not just `aud`.
- **Self-hosted runners:**
  - They "should almost never be used for public repositories".
  - Use **JIT/ephemeral runners** (one job, then destroyed) and runner groups scoped to repos.
  - Keep no long-lived credentials or metadata-endpoint access on hosts [https://docs.github.com/en/actions/reference/security/secure-use].
  - GitHub-hosted runners are ephemeral VMs.
- **Releases:** **Immutable releases GA (2025-10-28)**. Assets are locked, tags protected, and releases get signed attestations [https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/].
- **Roadmap items not yet GA (as of the 2026-03-26 post):**
  - **scoped secrets** bound to branch/environment/workflow identity;
  - write access no longer implies secret management;
  - **Actions Data Stream** telemetry to S3/Event Hub;
  - **native L7 egress firewall** for hosted runners.
  - The network firewall was in technical preview as of 2026-07-28 [https://github.blog/security/supply-chain-security/disrupting-supply-chain-attacks-on-npm-and-github-actions/].
- **Proof of presence** (re-auth for token creation, webhook edits, org security settings): public preview 2026-09-24, EMU + Entra only [https://github.blog/changelog/2026-09-24-require-proof-of-presence-for-high-impact-actions/].

### Notable incidents and lessons

| Date | Incident | Mechanism | Lesson |
|---|---|---|---|
| 2025-03-14/15 | **tj-actions/changed-files** CVE-2025-30066 (+ reviewdog/action-setup CVE-2025-30154) | Version tags retargeted to a malicious commit that dumped runner memory secrets into public logs; ~23k repos [https://github.com/advisories/GHSA-mrrh-fwg8-r2c3], [https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066] | SHA-pin; allow-list actions; rotate on exposure; treat logs as sensitive |
| 2025-09 (from 09-14) | **Shai-Hulud** npm worm | Compromised maintainer accounts; postinstall stole GitHub PATs and cloud keys, then republished the victim's packages; 500+ packages [https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem], [https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/] | Lockfiles + pinned versions; no long-lived publish tokens; trusted publishing |
| 2025-11-24 | **Shai-Hulud 2.0** | Preinstall-phase payload; TruffleHog secret harvesting; registers the victim as a self-hosted runner ("SHA1HULUD") for persistence; ~800 packages. **UNVERIFIED** (vendor write-ups only; GitHub refers to "late 2025 Shai-Hulud attacks" [https://github.blog/security/supply-chain-security/securing-the-open-source-supply-chain-across-github/]) | Disable install scripts in CI; detect unexpected runner registration |
| 2026-02 → 03-19/22 | **Trivy / trivy-action / setup-trivy** CVE-2026-33634 | After a February compromise, credential rotation was **not atomic**. The attacker used retained access to publish malicious Trivy v0.69.4 and force-push 76/77 trivy-action tags and all setup-trivy tags. Malicious Docker Hub images followed (v0.69.5/6) [https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23] | Even security scanners are supply chain. Use immutable releases, SHA pins and cosign verification; revoke credentials atomically |
| 2026-03-31 | **axios** 1.14.1 / 0.30.4 | Malicious dependency `plain-crypto-js` fetched a RAT at install time [https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager] | CISA advises `ignore-scripts=true` and `min-release-age=7` in `.npmrc` |
| 2026-05-11 | **Mini Shai-Hulud** (@tanstack + 170 more) | `pull_request_target` pwn request → poisoned pnpm cache shared with `release.yml` → OIDC token scraped from runner memory → npm publish with **valid provenance** [https://slsa.dev/blog/2026/05/mini-shai-hulud-what-slsa-can-and-cannot-do] | Cache is a trust boundary; signing identity must be unreachable from build steps (Build L3); require source/branch policy on top of provenance |
| 2026-05 (≈05-18) | **Nx Console** VS Code extension 18.95.0 + "Megalodon" workflow injection | Poisoned extension auto-updated onto developer machines (incl. GitHub staff) and exfiltrated repos; CVE-2026-48027 in KEV [https://www.cisa.gov/news-events/alerts/2026/05/28/supply-chain-compromises-impact-nx-console-and-github-repositories] | Developer workstations and IDE extensions are in scope; cooldown before consuming new versions |

- **Ecosystem responses on npm** (GitHub-owned):
  - Classic tokens revoked **2025-12-09** [https://github.blog/changelog/2025-12-09-npm-classic-tokens-revoked-session-based-auth-and-cli-token-management-now-available/].
  - Write granular tokens default to 7 days, max 90 [https://github.blog/changelog/2025-11-05-npm-security-update-classic-token-creation-disabled-and-granular-token-changes/].
  - **npm v12:** dependency lifecycle scripts **off by default** (`npm approve-scripts` allowlist), and git/remote deps blocked by default. 2FA-bypass tokens lose direct publish (~2027-01) [https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation/].
  - Staged publishing and stage-only tokens [https://github.blog/changelog/2026-09-18-stage-only-npm-tokens-for-safer-automation/].
  - 72h read-only lock after high-impact account changes.
  - **Dependabot 3-day cooldown** [https://github.blog/security/supply-chain-security/disrupting-supply-chain-attacks-on-npm-and-github-actions/].

## 6. Security scanning taxonomy in pipelines

- No single standards body defines the stage placement below. It is synthesised from:
  - SSDF PW.7/PW.8 (review/analyse code, test executable code) and PO.6.1 (scan supplier artifacts) [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218r1.ipd.pdf];
  - SAMM Secure Build L3 (fail non-compliant builds) [https://owaspsamm.org/model/implementation/secure-build/];
  - DSOMM Test & Verification sub-dimensions (static/dynamic depth for apps and infra) [https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel-data].
- **Stage placement** is therefore a design recommendation, not a cited standard.

| Scan | Pre-commit / IDE | PR | Build | Deploy / admission | Runtime | OSS tools (latest release, 2026-10-06) |
|---|---|---|---|---|---|---|
| **Secrets** | ✓ (block) | ✓ | ✓ (artifacts/images) | — | repo history sweep; push protection | gitleaks v8.30.1; TruffleHog v3.98.0 (verifies live creds) |
| **SAST** | optional (fast rules) | ✓ (diff-aware, blocking on new high) | full scan on main | — | — | Semgrep v1.179.0; CodeQL bundle v2.27.1 (also scans Actions workflows) |
| **SCA / dependency** | lockfile check | ✓ dependency review (new vulns, licences, malware, **release age**) | ✓ full + SBOM gen | gate on policy | continuous re-match of stored SBOMs against new CVEs | OSV-Scanner v2.6.0 (incl. container, licence, offline, guided remediation); Grype v0.120.0; Trivy v0.75.0 |
| **SBOM generation** | — | — | ✓ (attest to artifact) | verify present | inventory | Syft v1.54.0; Trivy; cdxgen |
| **IaC / config** | ✓ | ✓ | ✓ | admission policy (K8s) | drift detection | Checkov 3.3.23; Trivy (misconfig) |
| **Container image** | — | — | ✓ (post-build, pre-push) | ✓ registry/admission | ✓ continuous registry rescan | Trivy; Grype |
| **CI workflow lint** | ✓ | ✓ | — | — | — | zizmor v1.30.1; CodeQL Actions; Scorecard Dangerous-Workflow/Token-Permissions |
| **DAST** | — | optional ephemeral env | — | ✓ staging/pre-prod | scheduled prod-safe | ZAP v2.17.0 |

- Tool capabilities cited:
  - Trivy scans vulns, misconfig, secrets, licences and SBOM [https://github.com/aquasecurity/trivy].
  - OSV-Scanner: container, licence, offline, guided remediation [https://github.com/google/osv-scanner].
  - Versions are from each repo's GitHub releases API.

## 7. Admission-time enforcement in Kubernetes

- **Sigstore policy-controller** (v0.15.1) [https://docs.sigstore.dev/policy-controller/overview/]:
  - Admission webhook with **`ClusterImagePolicy`**. Namespaces opt in with the label `policy.sigstore.dev/include=true`.
  - Resolves tags → digests.
  - Authorities: key (incl. KMS), **keyless** (Fulcio issuer + subject match), or static pass/fail.
  - Attestation policies in **CUE or Rego**. Modes `enforce`/`warn`.
  - Logic: AND across matched policies, OR across authorities within a policy.
- **Kyverno** (v1.19.1; 1.19.0 released 2026-08-20):
  - **`ImageValidatingPolicy`** (CEL-based; introduced v1.14 in 2025-04, at parity in v1.19). Verifies **Cosign (key/keyless/Rekor) and Notary** signatures and in-toto attestations (SLSA provenance, CycloneDX SBOM) [https://kyverno.io/docs/policy-types/image-validating-policy/].
  - It also supports `mutateDigest` (tag→digest), `verifyDigest` and `required`.
  - **Legacy `ClusterPolicy`/`Policy` (including `verifyImages` rules) is deprecated in 1.19, with removal planned for 1.20 (≈ Nov 2026)** [https://kyverno.io/blog/2026/08/20/announcing-kyverno-release-1.19/], [https://kyverno.io/docs/guides/migration-to-cel/]. New platform work should target `ImageValidatingPolicy` only.
- **Ratify** (v1.4.6; 2.0.0-beta available; CNCF Sandbox) [https://ratify.dev/docs/what-is-ratify]:
  - A verification engine used as an **OPA Gatekeeper external data provider** (Gatekeeper v3.23.1).
  - Verifies **Notation** and **Cosign** signatures fetched as OCI referrer artifacts via ORAS. Strong Azure/AKS alignment [https://ratify.dev/docs/quickstarts/ratify-on-azure].
- **Choice:**
  - Kyverno IVP: broadest single tool. Policy-as-CEL, plus mutation and generation.
  - policy-controller: Sigstore-native, simplest for keyless.
  - Ratify + Gatekeeper: Notation/X.509 shops and Rego standardisation.
  - All three need attestations stored as **OCI referrers** next to the image, consistent with Rekor v2 no longer storing attestations.

---

## Implications for our platform (ordered by value)

1. **Short-lived identity everywhere.**
   - Each pipeline job gets an OIDC workload identity. Cloud, registry and package publish use only federated short-lived credentials.
   - Trust bindings pin immutable repo/owner IDs + ref/environment (not names).
   - No long-lived publish tokens. Automatic, **atomic** credential revocation when a job or account is compromised (Trivy lesson).
2. **Hardened, isolated build platform (target SLSA Build L3).**
   - Ephemeral JIT runners, one job per VM/pod.
   - The signing/OIDC identity lives in a separate trusted step or service that untrusted build steps cannot read (Mini Shai-Hulud lesson).
   - Caches are partitioned by trust level: untrusted triggers get read-only caches and never write caches consumed by release jobs.
   - Default-deny egress with allowlists, plus egress logs.
3. **Signed SLSA provenance + SBOM attestations for every artifact by default.**
   - in-toto Statement v1 / `slsa.dev/provenance/v1`, signed via Sigstore (self-hosted Fulcio/Rekor v2/TSA, or a private instance for private code).
   - Stored as OCI referrers / Sigstore bundles in our registry, not dependent on Rekor for retrieval.
   - CycloneDX 1.6+/1.7 and SPDX 2.3/3.0 export.
4. **Release policy engine on top of provenance**, with a VSA as the output. Before publish or deploy, verify:
   - expected builder ID;
   - expected repo + **protected branch/tag**;
   - expected workflow file and trigger (deny releases from `pull_request_target`/fork contexts);
   - source attestations (two-party review = SLSA Source L4);
   - the run succeeded.
   - Emit a VSA so downstream checks stay cheap.
5. **Pipeline-definition guardrails (CI/CD Top 10).**
   - Org policy: SHA-pinned third-party actions/steps only, with an allow/block list and a lockfile of transitive actions.
   - Least-privilege token defaults (read-only).
   - Lint every workflow change (injection, dangerous triggers, excessive permissions), using zizmor/CodeQL-style rules.
   - CODEOWNERS on pipeline files.
   - Actor/event execution rules with an evaluate mode before enforcement.
6. **Dependency ingestion control (S2C2F L1–L3).**
   - Proxy/cache all registries.
   - Malware and known-bad blocking at ingest.
   - **Minimum release age / cooldown** (e.g. 3–7 days) with emergency override.
   - Install scripts disabled by default in CI with a per-package allowlist; lockfile enforcement; no git/URL deps by default.
7. **Kubernetes admission enforcement.** Ship Kyverno `ImageValidatingPolicy` (or policy-controller) templates:
   - signed by our identity;
   - provenance from our builder;
   - SBOM present;
   - no critical CVEs without a VEX `not_affected`;
   - digest-only references.
   - Warn mode → enforce mode rollout. Avoid the deprecated Kyverno `ClusterPolicy`.
8. **Unified scanning orchestration with stage-appropriate gates.** One findings model and dedup across:
   - secrets: pre-commit + PR + push protection;
   - SAST/SCA: diff-aware on PR, full on main;
   - IaC;
   - image scanning: build + registry;
   - DAST in staging.
   - Continuous re-matching of stored SBOMs against new advisories (OSV).
   - Tools are pluggable; scanner binaries themselves are verified by signature and digest before use.
9. **VEX workflow.** Triage UI that records OpenVEX/CycloneDX VEX statements with mandatory justifications. Attach them to artifacts, and apply them in admission and scan gates to cut noise.
10. **Inventory and compliance evidence.**
    - SBOMs that meet the CISA 2026 minimum elements: author signature, tool name/version, generation context, hashes, licences.
    - Mapping of controls to SSDF 1.1/1.2, SAMM 2.2, DSOMM 5.x, OSPS Baseline/Scorecard.
    - Per-repo maturity scores built from automatically collected evidence.
11. **CRA readiness.**
    - Per-product support period.
    - Vulnerability intake (VDP), plus an incident/exploited-vuln clock that tracks the **24h/72h/14d** deadlines.
    - Export to ENISA SRP formats.
    - Retained SBOM per product version. Reporting has been live since 2026-09-11.
12. **Audit and telemetry.** Immutable audit log of pipeline-definition changes, secret access, publish events (alert on publishes from failed or unexpected runs) and runner registrations (Shai-Hulud 2.0 persistence). Stream to SIEM.
13. **Immutable releases and tags.** Protected/immutable tags and release assets for internally published actions, templates and packages. Proof-of-presence/step-up auth for token creation and security-setting changes.
14. **Developer endpoint scope.** Manage IDE extensions and AI-agent configs as supply-chain inputs, e.g. extension allowlists and an update cooldown. This reflects the Nx Console incident and Shai-Hulud persistence via `.claude/settings.json`/`.vscode/tasks.json` (the latter is **UNVERIFIED** vendor detail).
