---
status: proposed
date: 2026-10-06
---

# Own portal, Backstage-compatible Catalog model

Keel runs its own portal and API rather than Backstage, but its Catalog uses
Backstage's entity vocabulary and descriptor format (`catalog-info.yaml`:
Component/System/Domain/Group/Resource/API, `owner` required) so repos stay
portable and a Backstage front-end can be added later. Backstage is a
single-organisation portal: it has no hard tenant isolation and no model for
external Tenant Members signing in through their own identity provider, and
both are core requirements ([ADR-0001](./0001-tenant-is-a-client-organisation.md)).

## Considered Options

- **Backstage as the portal**, tenancy by plugin permissions: isolation would
  be a filter in plugin code, not a property of the data layer, which fails the
  "impossible by construction" bar for client data.
- **Commercial IDP (Port, Cortex)**: closed data model, per-seat cost for
  external client users, no Tencent coverage.

## Consequences

- Mapping: Keel *Project* ≈ Backstage *System*; *Service* ≈ *Component*;
  *Team* ≈ *Group*; *Tenant* has no Backstage equivalent (it is above Domain).
- Templates and descriptors follow Backstage formats, so teams can reuse
  community tooling.
