# 02 — Identity, permission boundaries, policy-as-code, secrets, audit

Research date: 2026-10-06. Primary sources only (vendor docs, specs, project repos/releases). Page "last updated" dates are recorded where the page shows one. Anything I could not confirm from a primary source is marked **UNVERIFIED**.

## TL;DR

- **Guardrails, not gatekeepers.** All three hyperscalers split *granting* (team-owned IAM) from *capping* (centrally-owned boundaries: AWS permissions boundaries + SCPs + RCPs; GCP IAM deny + org policy; Azure constrained role-assignment delegation + PIM). Teams self-serve inside the cap. That is the model to copy.
- **Tencent Cloud has the primitives**: CAM permissions boundaries (users + roles), Organization service control policies (allow/deny, inherited through departments), OIDC role SSO via `sts:AssumeRoleWithWebIdentity`, TKE pod identity webhook, SSM with rotation, CloudAudit tracking sets shipping org-wide to COS/CLS, COS object lock (allowlist only).
- **Tencent gaps that matter**: the CAM OIDC IdP stores a **static, base64 JWKS** (`IdentityKey`), so it does not fetch keys itself; no documented condition key that *forces* a boundary onto roles a delegate creates; no native PIM/JIT; upstream External Secrets Operator has **no Tencent provider** (TKE ships its own add-on); COS object lock is allowlist-only; CloudAudit console retention is documented as 30, 90 and 180 days on different pages.
- **CI identity**: GitHub OIDC `sub` became **immutable (owner-ID/repo-ID based) for repos created after 2026-07-15**. Repo custom properties can be emitted as `repo_property_*` claims, which makes ABAC on property claims possible.
- **Policy-as-code in 2026**: Kubernetes VAP is GA (1.30) and **MutatingAdmissionPolicy is GA in 1.36**. Kyverno 1.19 (Aug 2026) **deprecated ClusterPolicy, with removal planned in 1.20**, so new Kyverno work should use the CEL types. Gatekeeper 3.23 generates VAPs from templates. OPA is at 1.21 and Cedar at 4.13 (CNCF sandbox).
- **Secrets**: Vault is BUSL and OpenBao (MPL-2.0, OpenSSF) is at 2.7.1. ESO 2.11 removed unmaintained cloud providers in v2.0, which is a warning for any non-upstream Tencent provider. Prefer workload identity plus short-lived credentials over stored secrets.
- **Audit**: use OCSF 1.9.0 `API Activity` (class 6003) as the record shape and CloudEvents 1.0 as the envelope. Get tamper evidence from a signed hash-chain digest (CloudTrail model) plus WORM storage.

---

## 1. Zero trust (NIST SP 800-207, CISA ZTMM v2)

- SP 800-207 *Zero Trust Architecture* is final, published Aug 2020; related: SP 800-207A, CSWP 20. https://csrc.nist.gov/pubs/sp/800/207/final
- The seven tenets in §2.1, paraphrased: (1) all data sources and compute are resources; (2) all communication is secured regardless of network location; (3) access is per-session and least-privilege, and auth to one resource does not grant another; (4) access is decided by dynamic policy over identity, app and asset state plus behavioural/environmental attributes; (5) the enterprise monitors the integrity and posture of all assets, none inherently trusted; (6) authN/authZ is dynamic and strictly enforced before access, in a continuous cycle; (7) collect as much telemetry as possible to improve posture. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf
- The logical model separates a Policy Decision Point (Policy Engine + Policy Administrator) from a Policy Enforcement Point (§3). For us, OPA/Cedar/Kyverno are PDPs, while admission webhooks, CI gates and the platform API are PEPs. Same PDF.
- CISA Zero Trust Maturity Model **v2.0, April 2023**: five pillars (**Identity, Devices, Networks, Applications & Workloads, Data**), three cross-cutting capabilities (**Visibility & Analytics, Automation & Orchestration, Governance**) and four stages (**Traditional → Initial → Advanced → Optimal**). https://www.cisa.gov/zero-trust-maturity-model (PDF: https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf)
- ZTMM's new *Access Management* function runs from permanent access with periodic review (Traditional), to access that expires with automated review (Initial), to need- and session-based access (Advanced), to **automated just-in-time and just-enough access per action and resource** (Optimal). Same PDF, Identity pillar table.

## 2. Permission boundaries: hyperscaler patterns

**AWS**
- **Permissions boundary**: a managed policy that caps an IAM user or role. Effective permissions are identity policy ∩ boundary, and an explicit deny anywhere wins. https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
- **The delegation pattern** (same page) lets a delegate run `iam:CreateUser` / `PutUserPolicy` etc. only with the condition `iam:PermissionsBoundary == <boundary ARN>`. It also explicitly denies `iam:DeleteUserPermissionsBoundary` and any edit of the boundary policies. Result: teams can create principals but never above the cap.
- **Boundary caveat**: an implicit deny in a boundary does **not** limit resource-based policies that grant to an IAM user ARN or a role session ARN. The doc's example has a Secrets Manager resource policy still letting the user read a secret. Data perimeters therefore need RCPs or resource-policy hygiene too. Same page.
- **SCPs** grant nothing. They cap IAM users and roles in member accounts, **including the member root user**. They don't affect the management account or service-linked roles, and they *do* apply to delegated-admin member accounts. Effective permissions = SCP ∩ boundary ∩ identity policy. https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- **RCPs** cap what can be done *to resources* in member accounts, including by principals outside the org and by root users. They don't apply to service-linked roles, AWS-managed KMS keys or the management account. They cover a listed subset of services (S3, KMS, STS, Secrets Manager, SQS, ECR, CloudWatch Logs, …). AWS recommends rolling them out test account → OU → root. https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
- **Delegated admin pattern**: run security/audit services from a member account designated as delegated administrator, not the management account. SCPs and RCPs still constrain it. Sources: SCP and RCP pages above.

**GCP**
- **IAM deny policies** attach at org, folder or project, inherit downward, and are **evaluated before allow**. They support exception principals and tag-only denial conditions, and accept only supported permissions (permission groups like `service.googleapis.com/*.*`). Limit: 500 deny policies / 500 rules per resource. https://docs.cloud.google.com/iam/docs/deny-overview
- **Organization Policy** constrains *resource configuration*, not principals. It offers list/boolean managed constraints, newer parameterised managed constraints and **custom constraints in CEL**, with inheritance, tag-conditional enforcement and **dry-run**. https://docs.cloud.google.com/resource-manager/docs/organization-policy/overview

**Azure**
- **Management groups**: up to 6 levels below root and 10,000 per directory. Azure Policy and RBAC assignments inherit to subscriptions and resources. Changes appear in the Activity Log. ms.date 2024-07-18. https://learn.microsoft.com/en-us/azure/governance/management-groups/overview
- **Constrained delegation**: the *Role Based Access Control Administrator* role plus ABAC conditions limit **which roles** a delegate may assign, **to which principal types or principals**, and which assignments they may delete. It is free. This is Azure's equivalent of "self-serve IAM without escalation". ms.date 2026-03-30. https://learn.microsoft.com/en-us/azure/role-based-access-control/delegate-role-assignments-overview
- **PIM**: eligible vs active assignments; time-bound activation with MFA, justification, approval, notifications, access reviews and audit history; requires an Entra ID Governance licence. ms.date 2026-04-23. https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure

**Common shape**: (a) an org-level deny/cap layer owned by the platform team; (b) team-owned grants; (c) a delegate-can-only-create-with-cap rule; (d) dry-run or evaluate mode before enforcement; (e) explicit deny always wins.

## 3. Tencent Cloud specifics (ap-bangkok, TKE, multi-account)

**CAM basics**
- Policy syntax `version` must be `"2.0"`. Resources use the six-segment `qcs:project_id:service_type:region:account:resource` format. Evaluation is default deny, then any matching explicit deny, then allow. https://www.tencentcloud.com/document/product/598/10603
- Global condition keys include `qcs:ip`, `qcs:resource_tag`, `qcs:request_tag`, `qcs:current_time` and `qcs:BindToken` (updated 2024-01-23). Tag-based ABAC is therefore possible. https://www.tencentcloud.com/document/product/598/58421

**Permissions boundary: supported (verified)**
- Can be set on **sub-accounts (sub-users) and roles**. The entity can do only what both its policies *and* the boundary allow. The boundary limits permissions and never grants them. Updated 2024-01-23. https://www.tencentcloud.com/document/product/598/39425
- APIs `PutUserPermissionsBoundary` and `PutRolePermissionsBoundary` (20 req/s). https://intl.cloud.tencent.com/document/api/598/37927 , https://intl.cloud.tencent.com/document/api/598/37925
- **UNVERIFIED / likely gap**: I found no documented CAM condition key equivalent to AWS `iam:PermissionsBoundary`. Without one, a delegate can't be *forced* to attach a boundary when creating a role or user. Tencent docs also don't say whether a boundary caps resource-based policies (e.g. COS bucket policies).

**Organization (TCO): service control policies (verified)**
- Disabled by default. Once enabled, every department and member gets the system policy `FullQcloudAccess`, and new members get it automatically. https://www.tencentcloud.com/document/product/1031/51870
- SCPs **define boundaries only and grant nothing**. They are evaluated before CAM, a deny at any level ends evaluation, and they inherit down the department tree (parent A + child B both apply). **They don't apply to service-linked roles.** Doc example: forbid a member from deleting logs. Updated 2024-03-06. https://intl.cloud.tencent.com/document/product/1031/51869
- Custom SCPs support Allow/Deny, services, actions, resources and conditions (source IP, global and service conditions), via a visual or JSON editor. Bind them to a department or member. Updated 2024-03-06. https://intl.cloud.tencent.com/document/product/1031/51871
- **UNVERIFIED**: whether SCPs affect the organization admin (management) account and the root identity of member accounts; size and count limits.

**Organization Identity Center (CIC)**
- Users and groups, "permission configurations" (CAM system or custom policies) assigned per member account. On assignment, CIC deploys a CAM role, policy and role-SSO IdP into the target account. https://tencentcloud.com/document/product/1031/61831
- Only **one login method** at a time (username/password *or* external IdP SSO). Updated 2026-07-17. https://www.tencentcloud.com/document/product/1031/71657
- Supports **SCIM** user/group sync (intl endpoint `https://scim.tencentcloudssointl.com/scim/v2`, max 2 SCIM keys). Docs include Okta and Azure AD examples. https://intl.cloud.tencent.com/document/product/1031/61832
- Trusted-service / delegated admin exists for at least CloudAudit ("trusted service admin account"). https://intl.cloud.tencent.com/document/product/1021/45906

**OIDC federation for CI (verified API name)**
- **`AssumeRoleWithWebIdentity`** (STS, version `2018-08-13`, endpoint `sts.intl.tencentcloudapi.com`). Parameters: `ProviderId`, `WebIdentityToken`, `RoleArn`, `RoleSessionName`, `DurationSeconds` (default 7,200 s, max 43,200 s). The request is unsigned (`Authorization: SKIP`). Limit 80 req/s. Updated 2026-05-27. https://intl.cloud.tencent.com/document/api/1150/49454
- OIDC role SSO setup: create an OIDC IdP in CAM (issuer URL must be HTTPS with no `?`, `#` or `@`; one or more client IDs; **public signing key**), then create a role whose trust policy requires `oidc:iss` and `oidc:aud` (`string_equal`). `oidc:sub` is optional, accepts any string operator and up to 10 values. Updated 2024-01-23. https://intl.cloud.tencent.com/document/product/598/47191 , https://intl.cloud.tencent.com/document/product/598/58323
- `CreateOIDCConfig` takes `IdentityUrl`, `ClientId[]` and **`IdentityKey` (base64 of the JWKS)**. The console doc tells you to open the `jwks_uri` in a browser and paste the key. https://www.tencentcloud.com/document/api/598/47115
  - **Implication (inference)**: unlike AWS, which fetches JWKS from `jwks_uri` and validates TLS against trusted CAs (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html), Tencent pins a snapshot. GitHub's JWKS had **4 keys on 2026-10-06** (`https://token.actions.githubusercontent.com/.well-known/jwks`, fetched directly). When GitHub rotates, federation breaks unless something re-syncs the key via `UpdateOIDCConfig`. **UNVERIFIED** whether Tencent auto-refreshes.
- GitHub Actions is not named in Tencent docs. Third-party proof that the flow works with a non-Tencent issuer: HashiCorp documents Tencent dynamic credentials (client ID `tencentcloud.workload.identity`, `oidc:sub` = `organization:…:workspace:…:run_phase:…`). https://developer.hashicorp.com/terraform/cloud-docs/dynamic-provider-credentials/tencentcloud-configuration

**TKE workload identity (pod identity)**
- Enable "OIDC resource access control" on the cluster. This creates a CAM OIDC provider and installs the **`pod-identity-webhook`** add-on (default client ID `sts.cloud.tencent.com`). ServiceAccount annotations are `tke.cloud.tencent.com/role-arn`, `…/audience` and `…/token-expiration`; the webhook injects env vars and a projected token. Requires cluster ≥ v1.20.6-tke.27 / v1.22.5-tke.1. Updated 2025-12-29. https://www.tencentcloud.com/document/product/457/57285
- **UNVERIFIED**: the exact `oidc:sub` value TKE emits (presumably the standard `system:serviceaccount:<ns>:<sa>`) and whether role trust can pin it per SA. Docs only show the `oidc:aud` condition. Also unverified: availability in ap-bangkok.
- TKE versions: only even minors are released. The **Chinese** release-notes page lists **1.36.2-tke.1 (2026-08-26)**, while the international page still stops at 1.34.1-tke.1 (page updated 2025-12-15). https://cloud.tencent.com/document/product/457/9315 , https://www.tencentcloud.com/document/product/457/9315

**Secrets Manager (SSM)**
- Secret types: custom, database credential, CVM SSH key. Values up to 4,096 bytes, encrypted with a KMS CMK backed by an HSM. CAM resource-level authorisation; access is audited in CloudAudit. Updated 2024-01-02. https://intl.cloud.tencent.com/document/product/1078/38592
- `RotateProductSecret` rotates "Tencent Cloud services or **Tencent Cloud API key pairs**" (version 2019-09-23; updated 2026-05-27). Database credentials rotate on a 30–365-day cycle, and manual updates are blocked while auto-rotation is on. https://intl.cloud.tencent.com/document/api/1078/41515
- **TKE ExternalSecretOperator add-on** uses `provider: tencent` and supports AK/SK, AK/SK + AssumeRole and **TKE OIDC pod identity**. It can push back to SSM and generate STS/TCR credentials. Docs show `external-secrets.io/v1beta1`; x86 only. Updated 2025-12-22. https://www.tencentcloud.com/document/product/457/59102 , https://cloud.tencent.com/document/product/457/102120
  - Upstream ESO has **no Tencent provider** (provider docs list checked 2026-10-06; https://external-secrets.io/latest/introduction/stability-support/). ESO v2.0.0 (2026-02-06) removed the unmaintained Alibaba and Device42 providers. https://github.com/external-secrets/external-secrets/releases/tag/v2.0.0. The TKE add-on is therefore a Tencent-maintained distribution with its own lifecycle. **UNVERIFIED**: its version and how far it lags upstream.

**CloudAudit**
- Tracking sets ship to **COS or CLS** (region, bucket or topic, prefix), with Read/Write/All event types. `TrackForAllMembers` (org admin or trusted-service admin only) ships all members' logs centrally. Updated 2026-05-27. https://intl.cloud.tencent.com/document/product/1021/45906
- The Control Center / landing zone guide applies the tracking set across members and states 180-day in-account retention (updated 2024-12-11). https://intl.cloud.tencent.com/document/product/1220/57831
- **Conflicting retention**: the event-history page says the console keeps **30 days** (updated 2024-12-03; https://www.tencentcloud.com/document/product/1021/34384), and other pages say 90. Treat in-product retention as short and ship everything.
- `LookUpEvents` exposes `EventId`, `Username`, `EventName`, `EventTime`, `ErrorCode`, `RequestID`, `SecretId`, `SourceIPAddress`, `EventSource`, `EventRegion` and `Resources`, at max 50 per page. https://cloud.tencent.com/document/api/629/12362
- **COS object lock (WORM)**: requires versioning; retention of 1–36,500 days that can be extended but never shortened or removed; cannot be disabled once on; **allowlist-only ("contact us")**. Updated 2026-06-22. https://www.tencentcloud.com/document/product/436/40136

## 4. Just-in-time access / zero standing privilege / break-glass

- **Pattern**: eligible, not active. Activation is time-boxed and needs justification, MFA and optional approval, with notifications and an audit trail. Reference implementation: Azure PIM (see §2).
- **Google JIT Groups** (successor to *JIT Access*; release 2.5.0 on 2026-09-24): self-service, time-bound group membership with optional approval and justification, logged to Cloud Logging. It is stateless on App Engine or Cloud Run behind IAP. Google steers users to JIT Groups or native **Privileged Access Management**. https://github.com/GoogleCloudPlatform/jit-access
- **AWS TEAM** (v1.5.2, 2026-09-23; MIT-0): temporary elevated access to IAM Identity Center permission sets with automatic expiry. It is AWS *sample code*, not a service. https://github.com/aws-samples/iam-identity-center-team
- **Teleport** (v18.10.0, 2026-07-09): identity-aware proxy plus a CA issuing **short-lived certificates**. Source is AGPL-3.0 (API module Apache-2.0). **Community Edition binaries use a modified Apache 2.0 licence restricted to organisations with <100 employees and <$10M revenue.** https://github.com/gravitational/teleport (README §License; `build.assets/LICENSE-community`)
- **HashiCorp Boundary** (v0.21.3, 2026-04-30): BUSL since Aug 2023 (see §7). https://github.com/hashicorp/boundary , https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license
- **Vault/OpenBao dynamic secrets** as JIT for data planes: per-consumer database credentials with TTL leases and automatic revocation, static-role rotation (period or cron) and root-credential rotation. https://developer.hashicorp.com/vault/docs/secrets/databases ; OpenBao advertises the same, including hierarchical revocation. https://openbao.org/
- **Break-glass** (Microsoft guidance, updated 2026-06-04):
  - Keep ≥2 cloud-only accounts that don't depend on the federated IdP.
  - Use phishing-resistant auth (FIDO2 passkey or CBA) that differs from normal admin MFA.
  - Make them **permanent active, not PIM-eligible**, and exclude them from blocking Conditional Access.
  - Store credentials in separate physical safes and use a privileged access workstation.
  - **Alert on every sign-in**, run a post-mortem after each use, and **validate at least every 90 days** and after staff changes.
  - https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

## 5. Workload identity federation (CI → cloud, SPIFFE)

- **GitHub Actions OIDC**: issuer `https://token.actions.githubusercontent.com`, `jwks_uri` `/.well-known/jwks`; needs `permissions: id-token: write`. https://docs.github.com/en/actions/reference/security/oidc
  - `sub` examples: `repo:ORG/REPO:environment:NAME`, `…:pull_request`, `…:ref:refs/heads/BRANCH`.
  - **Repos created after 2026-07-15 use an immutable `sub`**: `repo:ORG@OWNER_ID/REPO@REPO_ID:…`. Older repos keep the old format until you opt in (org or repo, UI or REST), and renames or transfers after that date switch format. Not on GHES. Same page.
  - Claims include `repository_id`, `repository_owner_id`, `job_workflow_ref`, `environment`, `runner_environment`, `enterprise_id`, and **`repo_property_<name>`** for opted-in custom properties (multi-select values comma-joined). The `sub` template is customisable per org or repo (`include_claim_keys`). Same page; live discovery doc confirms the claim list.
- **GCP WIF guidance for GitHub**: an attribute condition restricting to your org is **required** ("you must use an attribute condition"). Prefer numeric `*_id` claims over names to defeat cyber- and typo-squatting. https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines
- **AWS**: the IAM OIDC provider fetches JWKS from `jwks_uri` (max 100 RSA + 100 EC keys) and verifies TLS with trusted root CAs, falling back to thumbprints. https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- **GitLab** `id_tokens:`: configurable `aud`. Default `sub` is `project_path:{group}/{project}:ref_type:{type}:ref:{name}`, customisable. Stable `project_id` and `namespace_id`; `ref_protected`, `environment` and `ci_config_ref_uri` claims. `CI_JOB_JWT*` is deprecated. https://docs.gitlab.com/ci/secrets/id_token_authentication/
- **SPIFFE/SPIRE**: SPIFFE ID, short-lived X.509 and JWT SVIDs, the Workload API, trust bundles and federation. SPIRE implements server/agent with node and workload attestation and auto-rotation. https://spiffe.io/docs/latest/spiffe-about/overview/ . SPIRE v1.15.3 released 2026-08-21. https://github.com/spiffe/spire/releases

## 6. Policy-as-code

| Engine | Current (2026-10-06) | Notes | Source |
|---|---|---|---|
| OPA / Rego | v1.21.1 (2026-09-29) | CNCF graduated. Core maintainers moved from Styra to Apple in Aug 2025, with no change to governance or licence. | https://github.com/open-policy-agent/opa/releases ; https://www.openpolicyagent.org/docs ; https://openpolicyagent.org/blog/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371 |
| Gatekeeper | v3.23.1 (2026-08-27) | `K8sNativeValidation` (CEL) is stable since 3.18. **VAP generation from ConstraintTemplates is beta and on by default since 3.20.** Needs K8s ≥1.30. | https://open-policy-agent.github.io/gatekeeper/website/docs/validating-admission-policy |
| Kyverno | v1.19.1 (2026-09-10) | 1.19 (2026-08-20) reached CEL feature parity: Validating, Mutating, Generating, ImageValidating and Deleting policies plus namespaced variants. **ClusterPolicy/Policy, CleanupPolicy and the legacy PolicyException are deprecated, with removal planned in 1.20 (~Nov 2026).** CEL storage version is still `v1beta1` and moves to `v1` in 1.20. | https://kyverno.io/blog/2026/08/20/announcing-kyverno-release-1.19/ |
| K8s ValidatingAdmissionPolicy | GA since **1.30** | `validationActions`: Deny / Warn / Audit (Deny and Warn are mutually exclusive); params via `paramKind`; bindings scope it. | https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/ |
| K8s MutatingAdmissionPolicy | **GA since 1.36** | Introduced in 1.30. | https://kubernetes.io/docs/reference/access-authn-authz/mutating-admission-policy/ |
| Cedar | v4.13.0 (2026-09-15) | CNCF sandbox (accepted 2025-10-08). RBAC, ABAC and ReBAC, analysable, formally verified in Lean. | https://github.com/cedar-policy/cedar/releases ; https://www.cncf.io/projects/cedar/ ; https://aws.amazon.com/blogs/opensource/cedar-joins-cncf-as-a-sandbox-project/ |
| Conftest | v0.71.1 (2026-10-06) | Rego over many formats (HCL2, YAML, JSON, Dockerfile, CODEOWNERS, SPDX, CycloneDX…). `deny`/`warn`/`violation` rules; `conftest verify` for unit tests. | https://www.conftest.dev/ ; https://github.com/open-policy-agent/conftest/releases |

**Where to evaluate** (synthesis; each control point is documented in the sources above):
1. **PR / pre-merge**: Conftest on IaC and manifests, plus Kyverno and Gatekeeper CLIs, as **required workflows or status checks via org rulesets** (§9). Cheapest point to fix.
2. **Plan**: Conftest or OPA on `terraform show -json` plan output, since the plan holds resolved values. This is the only stage that sees computed diffs.
3. **Admission**: native VAP/MAP where CEL suffices (in-process, no webhook availability risk). Use Kyverno or Gatekeeper for generate, mutate-existing, image verification and external data.
4. **Runtime / cloud control plane**: org guardrails (SCP/RCP/IAM deny, Tencent SCP) for anything that bypasses the pipeline. Kyverno and Gatekeeper background or audit scans catch drift.
5. **Application authZ**: Cedar or OPA as a PDP for the platform's own API ("can user X do Y to project Z").
- Roll out every layer in **audit/warn first** (VAP `Audit`/`Warn`, Kyverno `Audit`, ruleset *Evaluate*, GCP org-policy dry-run).

## 7. Secrets management

- **Vault licence**: HashiCorp moved Vault, Terraform, Boundary, Consul, Nomad and others from MPL-2.0 to **BUSL 1.1** on 2023-08-10. Each release converts to MPL-2.0 after 4 years. Internal use is unaffected; competing offerings are barred. https://www.hashicorp.com/en/blog/hashicorp-adopts-business-source-license . Vault is now on a **2.x** line (v2.1.1, 2026-09-16). https://github.com/hashicorp/vault/releases
- **OpenBao**: an MPL-2.0 fork of Vault and an OpenSSF (Linux Foundation) project. It offers dynamic secrets, encryption-as-a-service, leases and hierarchical revocation. Latest **v2.7.1 (2026-10-01)**, with 2.6.x still patched. https://openbao.org/ ; https://github.com/openbao/openbao/releases
- **External Secrets Operator**: latest **v2.11.0 (2026-09-18)**; only the current minor is supported. Stable providers: AWS SM/PS, Azure KV, GCP SM, Vault, IBM, Oracle, CyberArk, Akeyless and others; an OpenBao provider doc exists. https://external-secrets.io/latest/introduction/stability-support/ . No upstream Tencent provider (see §3).
- **SOPS**: encrypts values but not keys in YAML/JSON/ENV/INI/binary; `.sops.yaml` creation rules; key groups with Shamir threshold; MAC integrity. Backends: AWS KMS, GCP KMS, Azure KV, **HuaweiCloud KMS**, age, PGP. **No Tencent KMS backend**, so use age. CNCF sandbox since 2023. v3.13.3 (2026-07-23). https://getsops.io/docs/ ; https://github.com/getsops/sops
- **Sealed Secrets** v0.40.0 (2026-09-10): the controller holds the private key, and `kubeseal` encrypts with strict, namespace-wide or cluster-wide scope. The sealing key renews every 30 days by default (old keys kept), and `--re-encrypt` is available. The docs stress that **key renewal is not secret rotation**. https://github.com/bitnami-labs/sealed-secrets
- **Detection → revocation**:
  - GitHub secret scanning covers public repos for free; private repos need **GitHub Secret Protection** (Team/Enterprise).
  - **Partner program** alerts go directly to the issuing provider, which may revoke. **Validity checks** ask the issuer whether a secret is live. Custom regex patterns and AI-detected generic passwords are supported. https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
  - **Push protection** covers CLI pushes, web commits, uploads, REST and the MCP server. Bypass reasons (test, false positive, fix later) each create an audit event. Delegated bypass is available. Repo-level push protection requires Secret Protection and is off by default. https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection
  - **UNVERIFIED**: whether Tencent Cloud is a GitHub secret-scanning partner. If not, a leaked Tencent `SecretId/SecretKey` pair needs *our* revocation automation (CAM key disable + SSM `RotateProductSecret`).

## 8. Audit / activity logs

- **CloudEvents** (CNCF graduated 2024-01-25): required `id`, `source`, `specversion` (`1.0`), `type`; optional `datacontenttype`, `dataschema`, `subject`, `time`. `source`+`id` must be unique. Latest tagged spec is ce@v1.0.2; main is 1.0.3-wip. https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md ; https://www.cncf.io/announcements/2024/01/25/cloud-native-computing-foundation-announces-the-graduation-of-cloudevents/
- **OCSF** (Linux Foundation since 2024-11-19): schema **v1.9.0 (2026-08-03)**. https://www.linuxfoundation.org/press/open-cybersecurity-schema-framework-ocsf-joins-the-linux-foundation-to-optimize-critical-security-data ; https://github.com/ocsf/ocsf-schema/releases
  - **API Activity** = `class_uid 6003`, category 6 (Application Activity). `activity_id` values are Create 1 / Read 2 / Update 3 / Delete 4, and `type_uid = 6003*100 + activity_id`.
  - Required fields: `actor`, `api`, `src_endpoint`, `time`, `metadata`, `severity_id`, `status_id`. Recommended: `resources`, `status_code`, `status_detail`, `http_request`, `dst_endpoint`.
  - https://schema.ocsf.io/classes/api_activity
- **Tamper evidence: the CloudTrail model.** Each delivered log file gets a SHA-256 hash. An **hourly digest** lists the hashes, is signed with RSA (a separate key per region) and **includes the previous digest's signature**, forming a chain. Digests live in a separate prefix. This detects modification, deletion, and "no logs delivered" gaps. Pair with S3 MFA Delete or Object Lock. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
- **WORM**: on Tencent, COS object lock (allowlist; §3). On AWS, S3 Object Lock (referenced above).
- **GitHub audit log**: the org UI keeps **180 days**, and API access is Enterprise Cloud only. https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization
  - **Streaming is enterprise-level only** (no org-level streaming) to S3 (keys or OIDC), Azure Blob/Event Hubs, Datadog, GCS, Splunk and Purview. It includes Git events and optionally API-request events, with a 7-day buffer while paused. https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise
- **What a platform activity record should hold** (OCSF 6003 mapping):

| Question | Field (OCSF) | Notes |
|---|---|---|
| Who | `actor.user` (uid, type), `actor.session` (issuer, MFA, assumed-role/JIT grant id), `actor.app_name` | Distinguish human, CI (`job_workflow_ref`, run id) and workload (SPIFFE ID or SA) |
| What | `api.operation`, `activity_id`, `resources[]` (uid, type, owner/team, project) | Before/after for config changes (`unmapped` or a diff object) |
| When | `time` (ms epoch), `metadata.logged_time` | Producer time and ingest time |
| Where | `src_endpoint` (IP, UA), `cloud.region`, `cloud.account.uid` | Tencent `EventRegion` and member account UIN |
| Why | `metadata` extension: change ticket / PR URL / JIT justification | Not a first-class OCSF field. Carry it as a **profile/extension** (our design choice) |
| Outcome | `status_id`, `status_code`, `status_detail` | Include policy-deny reasons (which policy, which rule) |
| Integrity | `metadata.uid` + hash-chain pointer | Envelope as CloudEvent (`source`, `id`, `type`) |

## 9. GitHub org governance

- **Rulesets vs branch protection**: many rulesets can layer on one branch, and the most restrictive rule wins (only one branch protection rule can apply). Rulesets have Active/Disabled (and Evaluate) enforcement, bypass lists (users, roles, teams, apps) and read-only visibility for developers. Push rulesets restrict file paths, extensions, path length and size across the fork network. https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
- **Org-level rulesets** are available on **GitHub Team and Enterprise**. Targeting can use `fnmatch` names, **custom-property queries** (e.g. `props.team:infra -language:java`), manual selection, or `deployable/deployed` artifact state. https://docs.github.com/en/organizations/managing-organization-settings/creating-rulesets-for-repositories-in-your-organization
- **Available rules**: restrict create/update/delete; linear history; deployments must succeed; signed commits; require PR (with code-owner review and **team reviewers required for specific paths**); status checks; block force push; **secret-scanning alerts resolved**; code scanning results; code quality; coverage; file path, extension and size limits. https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- **Required workflows** moved into rulesets ("Require workflows to pass before merging"), GA 2023-10-11 for Enterprise Cloud. You can pin a workflow by branch, tag or SHA; the bypass list is the break-glass; evaluate mode is supported. https://github.blog/changelog/2023-10-11-requiring-workflows-with-repository-rules-is-generally-available/
- **CODEOWNERS**: looked up in `.github/`, then root, then `docs/`. The last matching pattern wins, owners need explicit write access, max 3 MB, invalid lines are skipped. Any single owner's approval satisfies the requirement. Protect the CODEOWNERS file itself. https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners
- **Custom properties**: string, single-select, multi-select or boolean. Can be required with a default; admin-managed or delegated via a fine-grained permission; can be synced from external systems. They feed ruleset targeting and OIDC claims (§5). https://docs.github.com/en/organizations/managing-organization-settings/managing-custom-properties-for-repositories-in-your-organization

---

## Implications for our platform (ordered by value)

1. **Keyless CI→Tencent federation as a managed product feature.**
   - Provision the CAM OIDC IdP for `token.actions.githubusercontent.com` per member account, and run a **JWKS sync job** that diffs `jwks_uri` against `IdentityKey` and calls `UpdateOIDCConfig` (Tencent stores a static key).
   - Generate role trust policies that pin `oidc:iss`, `oidc:aud` (a unique client ID per platform, not the default) and `oidc:sub`, using the **immutable `@ID` sub format** (opt the org in, since older repos keep the legacy format).
   - Prefer environment-scoped subs (`…:environment:prod`) for deploy roles.
   - Keep `DurationSeconds` at the minimum (≤3,600 s, tunable). Never issue long-lived `SecretId/SecretKey` to CI.
2. **Two-layer guardrails with team self-service.**
   - Platform-owned **Tencent SCPs** per department (deny log deletion, CloudAudit/tracking-set changes, CAM IdP/OIDC changes, region use outside ap-bangkok plus approved DR, disabling SCPs).
   - **CAM permissions boundaries** stamped on every role and sub-user the platform creates.
   - Because no Tencent condition key forces a boundary at creation, **the platform must be the only creator of CAM roles**: deny `cam:CreateRole`/`AddUser`/`PutRolePermissionsBoundary`/`Delete*PermissionsBoundary` via SCP for everyone except the platform's automation role, and expose role creation through our API with OPA/Cedar checks. This turns AWS's `iam:PermissionsBoundary` pattern into a platform-enforced one.
3. **Unified activity log** (platform + GitHub + Tencent + K8s audit), normalised to **OCSF 6003 inside CloudEvents**, with the who/what/when/where/why/outcome table above as the minimum schema.
   - Tamper evidence: a per-batch SHA-256 manifest, hourly signed digests chained to the previous one (CloudTrail design), stored in a separate log-archive account.
   - Request **COS object lock allowlisting** early; until it is granted, use a separate account with an SCP denying deletes.
   - Ship CloudAudit org-wide (`TrackForAllMembers`) to COS and CLS. Don't rely on 30–180-day in-product retention.
4. **Policy-as-code at four gates with one rule source.**
   - Conftest/OPA on IaC and plan JSON as an org **required workflow**.
   - Native **VAP (and MAP on TKE 1.36)** for simple CEL rules.
   - **Kyverno CEL policy types** (not ClusterPolicy, which is removed in 1.20) or Gatekeeper for mutate, generate and image verification.
   - Background audit for drift, and Cedar or OPA for the platform's own authZ.
   - Every policy ships with audit/warn mode, an exception mechanism with expiry (Kyverno honours expired CEL exceptions as of 1.19), and an owner.
5. **Org governance as code for GitHub.**
   - Require custom properties (`team`, `tier`, `data-class`, `tencent-account`). Target org rulesets by property: PR + code-owner review + path-scoped team reviewers, required status checks and workflows, signed commits for tier-1, **secret-scanning-alerts-resolved**, and push rules blocking `*.pem` / `.env`.
   - Emit selected properties as `repo_property_*` OIDC claims so Tencent role trust can key off them (Tencent `oidc:sub` holds at most 10 values, so a custom `sub` template that includes the property is the scalable route).
6. **JIT elevation with zero standing human admin.** Human access to member accounts goes through CIC permission configurations that are *eligible*. The platform grants a time-boxed assignment with justification, an approver, auto-revoke, and an activity-log entry carrying the justification. Build this ourselves (pattern: Google JIT Groups / AWS TEAM). **Break-glass**: ≥2 Tencent root/admin identities outside CIC with hardware MFA, credentials in split physical custody, an alert on every use, a post-mortem, and a 90-day drill.
7. **Secrets: identity first, then store.** Workloads use **TKE pod identity → CAM role** directly where the SDK supports it. Otherwise use SSM + the TKE ESO add-on with pod-identity auth (never AK/SK).
   - Use SSM rotation for DB credentials and `RotateProductSecret` for any unavoidable API keys.
   - For GitOps-encrypted files, use **SOPS + age** (no Tencent KMS backend) with keys held in SSM.
   - Evaluate **OpenBao** (not BUSL Vault) only if dynamic DB credentials beyond SSM rotation are needed.
   - Enable GitHub Secret Protection and push protection org-wide, and build a **Tencent key auto-revoke** flow fed by secret-scanning alerts (webhook → disable CAM key → rotate → audit event).

### Tencent Cloud constraints and gaps

| # | Constraint / gap | Status | Mitigation |
|---|---|---|---|
| T1 | CAM OIDC IdP stores a static base64 JWKS (`IdentityKey`); no documented auto-refresh | Verified API shape; auto-refresh UNVERIFIED | JWKS sync job + alert on `AssumeRoleWithWebIdentity` signature failures |
| T2 | No documented condition key to force a permissions boundary on created users/roles | UNVERIFIED (not found) | Platform is the sole CAM principal creator; SCP-deny others |
| T3 | SCP effect on the org admin account and member root identities undocumented; SCPs skip service-linked roles | Partly verified | Treat the admin account as a vault: no workloads, hardware MFA, monitored |
| T4 | No native PIM/JIT service found | UNVERIFIED (absence) | Platform-built JIT on CIC assignments |
| T5 | Upstream ESO has no Tencent provider; TKE add-on docs still use `v1beta1`; ESO dropped Alibaba as unmaintained | Verified | Pin the TKE add-on version, prefer direct SDK + pod identity for critical paths, keep an SSM→K8s sync fallback |
| T6 | SOPS has no Tencent KMS backend | Verified | age keys stored in SSM |
| T7 | COS object lock is allowlist-only and irreversible | Verified | Request the allowlist early; separate log-archive account meanwhile |
| T8 | CloudAudit retention documented as 30 / 90 / 180 days on different pages | Verified conflict | Ship everything; treat in-product retention as ephemeral |
| T9 | Intl docs lag Chinese docs (TKE 1.36 only on cloud.tencent.com) | Verified | Check both sites. **UNVERIFIED**: 1.36 and pod-identity availability in **ap-bangkok** |
| T10 | TKE pod identity `oidc:sub` format/scoping per ServiceAccount not documented | UNVERIFIED | Test in a sandbox cluster before designing per-SA roles |
| T11 | Tencent as a GitHub secret-scanning partner (auto-revoke) | UNVERIFIED | Build our own revoke flow |
| T12 | `oidc:sub` condition allows max 10 values | Verified | Use a custom GitHub `sub` template or a role per environment, not long allow-lists |
