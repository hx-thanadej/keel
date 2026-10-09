---
status: accepted
date: 2026-10-09
deciders: thanadej@harmonyx.co
---

# Client-owned cloud organisations are read-only to Keel

## Context

Q6 in [DESIGN.md §10](../DESIGN.md#10-open-questions) asked whether any
Tenant's Cloud Accounts sit in the Tenant's own organisation (#13). They do.
Some Tenants own organisations on Tencent Cloud, AWS, Azure, Google Cloud and
Alibaba Cloud.
[ADR-0002](./0002-one-cloud-account-per-project-environment.md) assumes Keel
vends every Cloud Account in our organisation.
[ADR-0011](./0011-focus-cost-facts-ingested-from-payer-accounts.md) assumes
bills come from our payer accounts.

## Decision

A Cloud Account is either **platform-owned** or **client-owned**. The Tenant
records which of its Cloud Accounts are client-owned, and for each one the
read-only role the client grants.

In a client-owned organisation Keel is **read-only**. It assumes a read-only
role the client grants, keylessly as
[ADR-0007](./0007-no-long-lived-cloud-credentials-in-ci.md) requires. It reads:

- costs and bills, from the client's payer or management account;
- Budget status;
- Findings and Rightsizing Recommendations;
- Guardrail drift reports.

Keel does not vend accounts there. It does not apply Guardrails, Landing
Zones or CI identities. It makes no mutating API call. Remediation stays
manual or arrives as a pull request the client merges. Keel opens that pull
request in the Tenant's Git repositories through its existing repository
access. It never writes to the client's cloud.

This amends ADR-0002. Account vending applies to platform-owned accounts only.
A client-owned account is registered, not created.

This amends ADR-0011. Payer ingestion also runs against a client payer
through that client's read-only role. The same FOCUS adapters and finality
rules apply.

## Considered options

- **Treat client accounts like ours** and ask for an administrative role.
  Clients will not grant it, and Keel would carry their blast radius.
- **Skip client-owned organisations.** Leaves those Tenants without cost,
  Budget or Finding visibility.
- **Long-lived access keys from the client.** Violates ADR-0007.

## Consequences

- Ownership is a property of the Cloud Account. Every mutating flow checks it
  and refuses client-owned accounts. A test sweep keeps new flows honest.
- Guardrails in a client organisation are reported as drift, never enforced.
  Permission Boundaries and Access Grants there stay with the client.
- Cost allocation still starts from the Cloud Account. A client payer may
  hold accounts that are not Keel's, so ingestion keeps only registered ones.
- Each provider needs a documented read-only role for the client to create.
  Epic M7 delivers those roles, the guards, the portal status and an
  onboarding runbook.
