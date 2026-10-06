---
status: proposed
date: 2026-10-06
---

# The Activity Log is the change record (no change advisory board)

Every state change in Keel and in integrated systems (merge, Run, Promotion,
Deployment, Access Grant, Policy decision, Exception, Budget change, Decision
Record status change) is written to one append-only **Activity Log**. Its
records follow OCSF API Activity (class 6003) carried in a CloudEvents 1.0
envelope, extended with a `why` field (PR, ticket, Access Grant reason). The log
is the change-management evidence. We deliberately do **not** add a change
advisory board step: DORA's research found CABs do not lower change-fail rate and
correlate with low performance, while recorded peer review satisfies
segregation of duties.

## Consequences

- **Tamper evidence:** records are batched; each batch is hashed; an hourly
  digest listing batch hashes is signed and chained to the previous digest
  (CloudTrail's model). Digests and batches land in a platform-owned log-archive
  Cloud Account under WORM storage (COS object lock needs Tencent allowlisting,
  so request it early; until then an organisation policy denies deletes).
- Activities are Tenant-scoped; a Tenant sees its own log, including any
  operator access to it.
- Cloud audit trails (Tencent CloudAudit, AWS CloudTrail), GitHub audit events
  and Kubernetes audit logs are ingested and normalised into the same log.
  In-product retention (30–180 days) is not relied on.
- Regulated clients that require a CAB can get one as a Policy on Promotion to
  prod for their Tenant only.
