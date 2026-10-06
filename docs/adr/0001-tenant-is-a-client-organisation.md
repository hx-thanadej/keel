---
status: accepted
date: 2026-10-06
deciders: thanadej@harmonyx.co
---

# A Tenant is a client organisation, and its people can sign in

The operating company delivers Projects for several client organisations, so
Keel is multi-tenant with **Tenant = client organisation** (Tenant → Projects →
Environments). The home organisation is just another Tenant. Tenant Members
(client staff) sign in through their own identity provider and get read-mostly
access to their own Tenant's budgets, releases, Findings and reports. Every
record in Keel carries a Tenant, and cross-Tenant visibility is impossible by
construction, not by filter.

## Considered Options

- **Tenant = Project.** Simpler, but a client with several Projects would have
  no single place for consolidated budgets, users or SSO.
- **Tenant = internal business unit, internal users only.** Rejected because
  clients need to see their own cost and delivery data.

## Consequences

- Per-Tenant SSO (OIDC/SAML federation) and Tenant-scoped roles are core, not a
  later add-on.
- Keel's own datastore needs enforced Tenant isolation (e.g. row-level security
  keyed on tenant), and every query path, export, search index and cache must
  respect it. This is tested as a security property.
- Platform operators (home organisation) get cross-Tenant access only through
  audited Access Grants, which appear in the affected Tenant's Activity Log.
