---
status: accepted
date: 2026-10-09
deciders: thanadej@harmonyx.co
---

# Compliance frameworks are ISO 27001, SOC 2 and PDPA; no change advisory board

## Context

Q5 in [DESIGN.md §10](../DESIGN.md#10-open-questions) asked whether Tenants
contractually require a change advisory board (CAB) or specific frameworks
(#12). Keel's Control catalogue (`internal/controls`) maps Policies to SSDF,
SLSA, CRA and OWASP CI/CD today. The evidence export (`internal/evidence`,
`keel-evidence@1`) and the CRA reporting clock cover those frameworks.

## Decision

Tenants require **ISO/IEC 27001:2022**, **SOC 2** (Trust Services Criteria)
and Thailand's **Personal Data Protection Act B.E. 2562 (PDPA)**. Keel maps
its Controls to all three and produces evidence for each, alongside the
existing frameworks.

No Tenant requires a formal CAB. The mechanism stays as
[ADR-0005](./0005-activity-log-is-the-change-record.md) describes. The
Activity Log is the change record. A Tenant that wants an extra sign-off gets
a per-Tenant Policy on Promotion to production.

PDPA adds obligations the other frameworks do not cover. Tenant personal data
and logs stay in an agreed region. Retention and deletion follow a documented
schedule. A personal data breach starts a 72-hour clock to notify the Office
of the Personal Data Protection Committee, run like the CRA clock.

## Considered options

- **Global CAB for production changes.** Rejected in ADR-0005 and not
  required by any Tenant.
- **Adopt a GRC product for the mapping.** Keel already owns the Controls and
  the evidence. A GRC tool can import the export later.

## Consequences

- Epic M8 adds ISO 27001 Annex A, SOC 2 and PDPA Controls, per-framework
  evidence and a portal compliance view.
- Keel produces evidence. It does not certify. Auditors still assess the
  operating company and each Tenant.
- Some Annex A and SOC 2 criteria are organisational (HR, physical
  security). Keel lists them as Controls with no Policy so the gap is visible.
- Data residency for the log archive interacts with ADR-0019.
