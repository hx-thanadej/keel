# Keel

A multi-tenant DevSecOps platform: repository management, CI/CD and supply-chain
security, policy and findings, permission boundaries and just-in-time access,
multi-cloud FinOps (budgets per Project × Environment per day/month/year,
forecasting, rightsizing), all recorded in one tamper-evident Activity Log.

**Status:** all six milestones (M0 foundations through M6 insights &
compliance) are built. What remains is connecting real accounts: billing
data, member-account roles, GitHub, Identity Center and the registry — see
the [runbooks](docs/runbooks/) and the open external issues in the
[Activity Log](docs/ACTIVITY-LOG.md).

What works today:

- **Tenancy:** Tenants (client organisations) → Projects → Environments →
  Cloud Accounts, isolated by Postgres row-level security and an every-route
  cross-Tenant test suite; each Tenant signs in through its own OIDC provider.
- **Record:** every change is an Activity (CloudEvents + OCSF), sealed hourly
  into a per-Tenant signed chain and shipped to WORM storage; `verify-log` /
  `verify-archive` prove nothing was altered.
- **Catalog:** Tencent account discovery, `catalog-info.yaml` sync from GitHub.
- **Cost:** FOCUS ingest from Tencent and AWS payer accounts (upload or bucket
  sync), effective cost with prepaid amortization, invoice reconciliation,
  finality per provider, allocation by account / `keel-scope` tag / weight
  rules / Kubernetes namespaces.
- **Budgets:** per Project or Project × Environment, Day / Month / Year, in
  THB or USD (ECB rates), seasonal forecast with p10–p90, threshold alerts
  (Activity + webhook), cost anomaly Findings, optional native Tencent/AWS
  budget mirrors.
- **Rightsizing & waste:** daily utilisation from Prometheus and Tencent Cloud
  Monitor; Kubernetes request and Tencent CVM size advice, AWS Cost
  Optimization Hub import, idle/orphaned resources with gated cleanup,
  off-hours schedules for non-prod; accepted advice becomes a pull request;
  realised savings and regressions tracked per Project.
- **Delivery:** Tencent account vending per Environment with Landing Zone
  guardrails, keyless CI roles, GitHub organisation governance, Service
  Templates, GitOps promotion with policy and Argo CD sync, keyless registry
  pushes.
- **Supply chain:** SARIF and SBOM ingest, OSV and VEX, Finding SLAs and
  Exceptions, Sigstore provenance with Keel-signed VSAs, Kyverno admission,
  reusable hardened build workflow, Controls catalogue.
- **Access:** permission boundaries, Identity Center role templates,
  time-boxed Access Grants with approvals, standing-access report,
  break-glass, leaked-key auto-disable.
- **Insights:** DORA, Service scorecards, Decision Record index, signed
  evidence export with the EU CRA clock, monthly Tenant reports, quarterly
  maturity self-assessment; Azure, Google Cloud and Alibaba bills too.
- **Portal:** Budgets, Costs (CSV export), Findings, Savings, Delivery,
  Security, Access, Insights, Projects, Activity.

## Develop

Requires Go ≥ 1.26 (auto-downloaded via `GOTOOLCHAIN`), Node 22, pnpm 10, Docker.

```bash
make dev    # API on :8080 + portal on :5173
make test   # go test -race
make lint   # go vet, gofmt, oxlint
docker compose up -d postgres   # local Postgres 18
export KEEL_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres
make test   # now also runs the tenant-isolation (RLS) tests; they skip without the URL
```

Database tests create a throwaway database per test, migrate it as
`keel_owner`, and query as `keel_app` (no BYPASSRLS), so row-level security is
exercised for real. CI sets `KEEL_REQUIRE_DB=1`, which turns a skip into a
failure.

## Run

```bash
# once per Postgres cluster (as superuser), then create the database
psql -f db/roles.sql && createdb -O keel_owner keel

export KEEL_DATABASE_URL=postgres://keel_app:…@host/keel
export KEEL_MIGRATE_URL=postgres://keel_owner:…@host/keel
export KEEL_BASE_URL=https://keel.example.com
export KEEL_COOKIE_KEY=$(openssl rand -base64 32)
export HOME_OIDC_SECRET=…      # named by -client-secret-ref below

# once: home Tenant + its identity provider + first admin group
keel-api bootstrap -slug harmonyx -name HarmonyX \
  -issuer https://login.example.com -client-id keel \
  -client-secret-ref HOME_OIDC_SECRET -admin-group keel-admins -email-domain harmonyx.co

keel-api   # sign in at $KEEL_BASE_URL/auth/login?tenant=harmonyx
```

Each Tenant signs in through its own OIDC provider
(`/auth/login?tenant=<slug>`); IdP groups map to roles via
`POST /v1/tenants/{tenant}/identity-providers/{idp}/group-roles`. CLIs and
pipelines can send `Authorization: Bearer <id_token>` instead of a cookie.

| Read | For |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | Product scope, architecture, flows, roadmap, open questions |
| [CONTEXT.md](CONTEXT.md) | Glossary: the words we use and the ones we avoid |
| [docs/adr/](docs/adr/) | Architecture Decision Records |
| [docs/ACTIVITY-LOG.md](docs/ACTIVITY-LOG.md) | What was done, when, by whom, why |
| [docs/research/](docs/research/) | Primary-source research behind the decisions |

## Working agreements

- New hard-to-reverse decision → new ADR (`docs/adr/NNNN-slug.md`). ADRs are
  superseded, never rewritten.
- Every working session or meaningful step → an entry in `docs/ACTIVITY-LOG.md`.
- New domain term → `CONTEXT.md` first, then use it everywhere.
- Work is tracked in GitHub issues + the [Keel GitHub Project](https://github.com/users/hx-thanadej/projects/2), one milestone per
  roadmap phase (M0–M6).
