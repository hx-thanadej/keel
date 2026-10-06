# Keel

A multi-tenant DevSecOps platform: repository management, CI/CD and supply-chain
security, policy and findings, permission boundaries and just-in-time access,
multi-cloud FinOps (budgets per Project × Environment per day/month/year,
forecasting, rightsizing), all recorded in one tamper-evident Activity Log.

**Status:** design phase. No code yet.

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
