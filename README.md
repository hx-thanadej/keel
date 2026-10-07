# Keel

A multi-tenant DevSecOps platform: repository management, CI/CD and supply-chain
security, policy and findings, permission boundaries and just-in-time access,
multi-cloud FinOps (budgets per Project × Environment per day/month/year,
forecasting, rightsizing), all recorded in one tamper-evident Activity Log.

**Status:** M0 in progress — repo scaffold (Go API + React portal).

## Develop

Requires Go ≥ 1.26 (auto-downloaded via `GOTOOLCHAIN`), Node 22, pnpm 10, Docker.

```bash
make dev    # API on :8080 + portal on :5173
make test   # go test -race
make lint   # go vet, gofmt, oxlint
docker compose up -d postgres   # local Postgres (used from #17 onwards)
```

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
