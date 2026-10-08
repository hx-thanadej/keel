# Activity Log

Append-only record of what was done on this project, newest last. One entry per
working session or meaningful step. Decisions with lasting weight get an ADR in
[`adr/`](./adr/); this log links to them rather than repeating them.

Format: `YYYY-MM-DD — actor — what — why/outcome — links`

---

## 2026-10-06 — Claude (with thanadej@harmonyx.co) — Kick-off: research + plan + design

- **Request:** a product that handles all DevSecOps tasks — repository management,
  CI/CD, FinOps, permission boundaries and the rest — designed from world-class
  practice, with an activity log and ADRs. Plan and design only; no build yet.
- **Context inferred from the workspace** (not yet confirmed by the user):
  Tencent Cloud (TKE, ap-bangkok, multi-account organisation with a separate
  payer), GitHub + GitHub Actions + ghcr, FinOps already a live concern
  (CI build-cache egress investigation, Sep 2026).
- Created `devsecops-platform/` with `docs/research/`, `docs/adr/`, this log.
- Launched three parallel research passes against primary sources:
  1. Supply chain & CI/CD security → `research/01-supply-chain-and-cicd.md`
  2. Identity, permission boundaries, policy-as-code, secrets, audit →
     `research/02-identity-policy-secrets-audit.md`
  3. Platform engineering, repo mgmt, GitOps, FinOps/FOCUS, DORA, ADR practice →
     `research/03-platform-finops-metrics-decisions.md`

## 2026-10-06 — thanadej@harmonyx.co → Claude — New requirement: multi-cloud budgets + rightsizing

- **Request:** budget tracking across most cloud providers (AWS etc.), showing
  budget per project/environment per day/month/year. Cost optimisation is a top
  priority: every resource must be right-sized and the platform must suggest the
  right size.
- **Glossary:** introduced **Project** (client engagement/product grouping
  Services across Environments; primary Budget unit), plus Actual Spend,
  Forecast, Rightsizing Recommendation, Waste. Interpretation of "project" is an
  assumption pending user confirmation.
- Launched a 4th research pass: per-provider billing exports, budget APIs,
  native recommenders, K8s rightsizing → `research/04-multicloud-budgets-and-rightsizing.md`

## 2026-10-06 — thanadej@harmonyx.co → Claude — Requirement: multi-tenancy

- **Request:** multi-tenant for project/environment setup.
- Asked three clarifying questions; answers: Tenant = client organisation;
  client staff will sign in (read-mostly); one Cloud Account per Project
  Environment.
- **Glossary:** added Tenant and Tenant Member; tightened Project, Environment,
  Cloud Account to the Tenant → Project → Environment → Cloud Account hierarchy.
- **Decisions:** [ADR-0001](./adr/0001-tenant-is-a-client-organisation.md),
  [ADR-0002](./adr/0002-one-cloud-account-per-project-environment.md).

## 2026-10-06 — Claude — Research complete; design + ADRs written

- All four research notes landed in `docs/research/` (01 supply chain & CI/CD,
  02 identity/policy/secrets/audit, 03 platform/FinOps/DORA/ADRs, 04 multi-cloud
  budgets & rightsizing). Every claim cites a primary source; unverified items
  are marked.
- Findings that changed the design:
  - Tencent CAM has permission boundaries but no condition key to force them on
    delegated role creation → Keel is the sole IAM creator (ADR-0006).
  - Tencent's OIDC provider stores a static copy of GitHub's signing keys → Keel
    runs a key sync job (ADR-0007).
  - Tencent's FOCUS export leaves EffectiveCost/SkuId/ServiceCategory empty;
    Alibaba's FOCUS is preview-only; billing must be read from payer accounts
    (ADR-0011).
  - Only Keel can own cross-provider Budgets; Alibaba has no create-budget API
    (ADR-0012).
  - Tencent/Alibaba have no instance-size recommendation API → own rightsizing
    engine for Tencent, Alibaba and all Kubernetes (ADR-0013).
  - Kyverno ClusterPolicy is deprecated (removal ~Nov 2026) → CEL policy types
    from day one (ADR-0009).
  - 2026 incidents shipped malware with valid SLSA provenance → Release policy
    checks builder/repo/ref/workflow/trigger, not just signatures (ADR-0010).
  - DORA: CABs don't reduce change-fail rate → Activity Log is the change
    record (ADR-0005).
- Wrote ADRs 0003–0014 (all *proposed*), `docs/DESIGN.md` (scope, tenancy,
  architecture, flows, data shapes, NFRs, roadmap M0–M6, open questions, risks),
  `README.md`.

## 2026-10-06 — thanadej@harmonyx.co → Claude — Use GitHub repo + Projects

- **Request:** use `hx-thanadej/keel` as the repository and GitHub Projects for
  project management.
- Initialised git in `devsecops-platform/`, pushed design docs to `main`.
- Created labels (`epic`, `decision`, `area:*`), milestones M0–M6, epic
  issues #1–#7 (one per milestone, with task checklists) and decision issues
  #8–#15 (one per open question Q1–Q8 in DESIGN.md §10).
- User created GitHub Project [keel](https://github.com/users/hx-thanadej/projects/2)
  and granted the `project` scope. All 15 issues are on the board; set
  Priority (P0 = M0/M1 epics + the decisions blocking them; P1 = M2/M3 + Q1;
  P2 = M4–M6 + Q5) and Size (epics XL, decisions S); linked board to the repo.

## 2026-10-06 — thanadej@harmonyx.co → Claude — Break M0 and M1 into tickets

- Created 29 tickets as sub-issues of the epics: M0 → #16–#28 (13 tickets,
  under #1), M1 → #29–#44 (16 tickets, under #2). Each has acceptance criteria,
  "Blocked by" links and refs to ADRs/research; all added to the Project with
  Status, Priority and Size.
- Slicing: tracer bullets first — #19 (Catalog API → authZ → RLS → Activity)
  for M0, #31 (Tencent bill → cost facts → daily cost for tat-crm) for M1 —
  then widen.
- Critical path: #11 (stack) → #16 → #17 → #18 → #19; #9 (payer access) →
  #29 → #31 → #34 → #37 → #41 (Budget screen).

## 2026-10-06 — thanadej@harmonyx.co → Claude — Decisions + start of M0 build

- **Decided:** stack = Go + Postgres (RLS) + River job queue; **no Temporal or
  trigger.dev** (user asked why a workflow engine was needed; durable timers and
  multi-step flows fit in Postgres via River with no extra infrastructure).
  ClickHouse deferred. ADR-0014 rewritten and accepted; #11 closed.
- **Decided:** year-1 providers = Tencent + AWS (#10 closed); per-Tenant budget
  currency with daily FX (#14 closed); GitHub plan Free/unsure → design for the
  lowest common denominator (#8 left open).
- Started #16 on branch `feat/16-scaffold`: Go API (`/healthz`, test-first),
  React/Vite portal, distroless Dockerfile and Postgres compose (images pinned by
  digest), Makefile, CI with SHA-pinned actions + read-only token + no stored
  credentials, Renovate with 7-day minimum release age.
- Noted: local Go was 1.24.5 (out of support); `go.mod` now requires 1.26 so the
  toolchain auto-upgrades. Docker daemon was not running, so the image and
  compose were not built locally; CI builds the image.

## 2026-10-07 — Claude — CI fix on #45; #17 tenancy schema with RLS

- PR #45 CI failed on golangci-lint `errcheck` (unchecked `Body.Close` in a
  test). Root cause of the local/CI mismatch: `make lint` didn't run
  golangci-lint and CI used `latest`. Fixed; linter pinned to v2.14.0 in both.
  CI green.
- #17 on branch `feat/17-tenancy-schema` (stacked on #45): first migration
  (tenants, teams, projects, environments, cloud_accounts, services) with RLS
  enabled + forced on every table, fail-closed `keel.tenant_id` scoping,
  `create_tenant` SECURITY DEFINER function, `keel_app` role with no
  BYPASSRLS and no DELETE.
- Tests written first; each runs against a throwaway database as the real app
  role. Verified they go red by mutation: removing RLS from `teams` fails 5
  assertions; replacing a composite `(tenant_id, project_id)` FK with a plain
  FK lets Tenant A attach an Environment to Tenant B's Project (FK checks
  bypass RLS). The composite-FK pattern is therefore load-bearing.
- CI now runs Postgres 18 as a service and fails, not skips, if DB tests can't
  run.

## 2026-10-07 — thanadej@harmonyx.co → Claude — "Continue all things until finished": M0 built

- **Authorised:** continue through all tickets; Claude merges its own PRs once
  CI is green (squash), one PR per ticket, stacked where dependent.
- **Merged / open:** #45 scaffold, #46 RLS schema (#17), #47 Activity Log (#18),
  #48 OPA authz (#20), #49 Catalog API (#19), #50 OIDC sign-in (#21, #22),
  #51 isolation suite (#23), #52 signed digest chain (#24), #53 Tencent account
  discovery (#26), #54 catalog-info sync (#27), #55 portal (#28), #56 WORM
  archive export + offline verify (#25).
- **Decisions made while building** (recorded in PRs/commits, not ADR-worthy):
  OPA over cedar-go (same engine as Conftest/Gatekeeper); River deferred —
  hourly jobs use ticker + advisory locks; `keel_lookup` NOLOGIN BYPASSRLS
  role owns the only cross-Tenant lookup functions (FORCE RLS applies to
  owners, so SECURITY DEFINER alone sees nothing); per-Tenant digest chains so
  clients can verify their own log.
- **Bugs caught by tests/mutation/smoke runs:** OPA eval_conflict on multiple
  bindings; plain FKs bypass RLS (composite FKs now); gofmt version skew between
  PATH and toolchain; `tenant_ids()` column name; Postgres microsecond rounding
  breaking signatures; `json.Marshal` compacting RawMessage in the archive;
  portal overflow at 375px.
- **Blocked on the user:** #8 GitHub plan (main is unprotected on Free),
  #9 Tencent payer billing access, #15 COS object-lock allowlist, real IdP
  client registrations, archive account setup (runbook).

## 2026-10-07 — Claude — M1 started: cost ingest (#30, #31, #34)

- Verified Tencent's FOCUS 1.0 column list from its docs: EffectiveCost,
  ServiceCategory, SkuId, SkuPriceId, ResourceType, CapacityReservationStatus
  are empty; vendor columns x_ComponentName/Type, x_ExportTime, x_OwnerAccountID.
- Loads are append-only: a re-ingest is a new load whose facts become current
  only when fully written; a final load freezes the period. Facts are attributed
  by member account → Cloud Account → Environment/Project; unknown accounts go
  to the home Tenant as `unallocated` and are reported as a KPI.
- Open: whether Tencent daily bill files are per-day or month-to-date decides
  how files combine into a load; must be checked on the first real delivery (#29).

## 2026-10-07 — Claude — M1 built: multi-cloud cost, budgets, forecasting, rightsizing groundwork

- **Merged:** #57 cost facts + Tencent ingest + allocation by account (#30, #31,
  #34) · #58 effective cost, invoice reconciliation, finality, bill sync (#32,
  #33) · #59 budgets with Day/Month/Year status, alerts, per-Tenant currency
  (#36, #37, #43) · #60 seasonal-trend forecast with p10/p50/p90 (#38) · #61
  cost anomalies → Findings (#40) · #62 budget screen + Tenant cost view (#41,
  #42) · #63 AWS FOCUS 1.2 ingest (#44) · #64 shared-cost allocation (#35) ·
  #65 native budget mirrors for Tencent and AWS (#39).
- **Decisions taken while building** (in PRs, not ADR-worthy):
  - Prepaid purchases keep their billed cost (months reconcile to invoices) and
    are spread as zero-billed daily amortization rows for effective cost.
  - ECB reference rates for FX (free, keyless, has THB); 3 years, 4 currencies.
  - Forecast = classical decomposition (trend × day-of-week), withheld below
    28 days of history rather than guessed; bands from resampled errors.
  - Anomalies use median + MAD over 28 days; one open Finding per
    Project/Environment/service; auto-resolve after 3 normal days.
  - Shared costs: one `keel-scope` tag key (Tencent allows 15), weight rules,
    and OpenCost namespace shares; splits are exact to the cent.
  - The generic `findings` table now exists; M2 rightsizing and M4 security
    will reuse it.
  - River (ADR-0014) still not needed: hourly jobs are tickers + advisory
    locks. It comes in with Access Grant timers (M5).
- **Bugs found by tests, mutation checks and browser runs:** `missing_fx`
  counted history outside the window; 90-day FX feed too short; months before
  first spend counted as not final; breakdown summed past the as-of date;
  Postgres session time zone in a test literal; Tencent constraint name
  truncation; AWS deprecated budget fields.
- **Still needs the user / real accounts:** #29 Tencent payer billing role and
  COS bill delivery (then confirm per-day vs month-to-date files); #8 GitHub
  plan; #15 COS object lock; IdP client registrations; AWS management-account
  role if AWS is used. See `docs/runbooks/connect-billing.md`.

## 2026-10-07 — Claude — M2 built: rightsizing, waste, apply-as-PR, savings

- **Merged / in review:** #76 Recommendation record + Findings (#67) · #77
  utilisation store, Prometheus and Tencent Cloud Monitor collectors (#68) ·
  #78 Kubernetes request rightsizing (#69) · #79 Tencent CVM engine (#70) · #80
  AWS Cost Optimization Hub import (#71) · #81 idle/orphaned Waste with gated
  cleanup (#72) · #82 accepted advice → pull request (#74) · #83 savings
  tracker (#75) · #84 off-hours schedules for non-prod VMs (#73).
- **Decisions taken while building** (in PRs, not ADR-worthy):
  - One `recommendations` table for every source; identity is
    provider|resource|action; dismissals stick unless savings move >20% or the
    proposed size changes.
  - Utilisation is summarised per day (p50/p95/p99/max + per-hour maxima), not
    stored raw. Tencent Cloud Monitor is read at period=60 only: period=3600
    returns each hour's maximum, which would inflate every percentile.
  - Kubernetes: CPU = highest daily p95, memory = max × 1.15; ≥14 days of
    history (21 and confidence ≥0.8 in production); priced from the
    Environment's own compute spend.
  - Keel never changes cloud resources to rightsize them. Changes arrive as
    pull requests (Kubernetes requests) or are done by people; the only
    automatic action is Waste cleanup, off unless globally enabled, opted in
    per Environment, never production, and after a grace period.
  - Realised savings are measured from the resource's own cost lines (14 days
    after vs before); shared-cost resources (Kubernetes) keep the estimate and
    say so. Regressions (newer advice to grow, or requests >95% used) are
    flagged on the Finding for 30 days.
  - Off-hours schedules are proposed in the Tenant's time zone (new setting,
    default Asia/Bangkok) and only priced on usage-based charges.
- **Follow-ups filed:** TencentDB rightsizing (from #70), Kubernetes off-hours
  schedules (#85).
- **Still needs the user / real accounts:** everything listed for M1, plus a
  `KEEL_TENCENT_MEMBER_ROLE` role in each member account (read-only Cloud
  Monitor + CVM/CBS/CLB/VPC describe; delete only where Waste cleanup is
  wanted), Prometheus URLs per cluster, and a GitHub token for pull requests.
  See `docs/runbooks/rightsizing.md`.

## 2026-10-08 — Claude — M3–M6 built: delivery, supply chain, access, insights

- **M3 Golden Path delivery (#4):** durable flows on River (#87); Tencent
  account vending per Environment (#88); Landing Zone guardrails
  `keel-baseline@1` with drift Findings (#89); keyless CI identity per
  Environment via CAM OIDC (#90); GitHub organisation governance
  `keel-github@1` (#91); Service Templates (#92); GitOps promotion by pull
  request with `keel-promotion@1` and Argo CD sync (#93); TCR push through
  Keel-brokered one-hour tokens, ADR-0015 (#94); Delivery tab (#95).
- **M4 Supply chain & Policy (#5):** Finding SLAs (#107); time-boxed
  Exceptions (#108); SARIF ingest with pipeline OIDC (#109); SBOM + daily OSV
  re-match (#110); VEX (#111); Sigstore provenance verification and Keel-signed
  VSAs (#112); Kyverno admission policies (#113); reusable build workflow and
  ephemeral ARC runners (#114); Actions org policy (#115); Controls catalogue
  `keel-controls@1` (#116); Security tab (#117).
- **M5 Access (#6):** permission boundaries on every Keel-made principal
  (#131); role templates via Tencent CIC (#132); time-boxed Access Grants with
  approvals and durable revoke (#133); standing production access report
  (#134); break-glass registry, alerts, post-mortems, drills (#135); leaked
  key auto-disable (#136); workload secrets runbook (#137); Access tab (#138).
- **M6 Insights & compliance (#7):** DORA five metrics (#148); Service
  scorecards (#149); Decision Record index (#150); signed evidence export and
  the EU CRA clock from CISA KEV (#151); monthly Tenant report (#152); Azure,
  Google Cloud and Alibaba bill connectors incl. Parquet (#153); quarterly
  maturity self-assessment (#154); Insights tab (#155).
- **Decisions taken while building** (in PRs):
  - Keel never holds long-lived cloud or registry keys: CI gets CAM roles via
    GitHub OIDC, registry pushes get one-hour TCR tokens, Azure/GCP/Alibaba
    bills are read with workload identity federation / RRSA; GCP key files
    are refused.
  - SCTs are required on every Sigstore verification; VSAs are Keel-signed
    in-toto statements and production promotion needs one per image by
    default.
  - Human cloud access only through CIC role assignments that expire; any
    standing production write access is a critical Finding.
  - Reports and evidence are stored/signed snapshots, so they stay readable
    after the underlying figures change.
- **Follow-ups filed:** #121 GitHub alert sync, #85 Kubernetes off-hours,
  TencentDB rightsizing.
- **Still needs the user / real accounts:** #29 / #9 Tencent payer billing
  role and COS delivery; #8 GitHub plan; #15 COS object lock; #98 sandbox
  member account to verify guardrails; #145 TKE pod identity `oidc:sub` in
  ap-bangkok; #12 / #13 Tenant compliance scope and own-organisation
  accounts; IdP client registrations; tokens and roles listed in
  `docs/runbooks/vending.md`, `delivery.md`, `supply-chain.md`, `access.md`
  and `connect-billing.md`.
