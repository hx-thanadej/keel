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
