---
status: accepted
date: 2026-10-09
deciders: thanadej@harmonyx.co
---

# The Activity Log archive is WORM on AWS S3 Object Lock

## Context

ADR-0005 makes the Activity Log the change record. Sealed digests and the
activities they cover are shipped to a write-once archive in a platform-owned
log-archive Cloud Account (#25, #56). The plan was Tencent COS object lock.
COS object lock is allowlist-only and irreversible once enabled. Nobody has
filed the allowlist request, so the archive has been protected only by a
delete-deny bucket policy and an organisation policy (#15). A policy can be
lifted by an administrator. It is not WORM.

AWS S3 Object Lock is generally available. It is enabled per bucket at
creation, needs no allowlisting, and in COMPLIANCE mode no principal, including
the account root user, can shorten retention or delete a locked object version.
Keel already reads AWS with keyless credentials for the AWS bill sync
(ADR-0011, ADR-0007).

## Decision

New installs archive the Activity Log to an AWS S3 bucket with Object Lock.
`KEEL_ARCHIVE_PROVIDER` selects the store. `aws` is the default. `tencent`
keeps today's COS behaviour for existing deployments.

On `aws`:

- Every archived object is written with `x-amz-object-lock-mode: COMPLIANCE`
  and a retain-until date of now plus `KEEL_ARCHIVE_RETENTION_DAYS`. The
  default is 2555 days (seven years, DESIGN §8). Keel rejects less than 365.
- Every PUT carries `Content-MD5`, which S3 requires on Object Lock writes.
- Legal hold is not set.
- At startup Keel reads the bucket's Object Lock configuration and versioning
  status. It refuses to start archiving unless both are enabled.
- Credentials come from web identity or the instance role. There are no
  access keys (ADR-0007).
- `keel-api verify-archive` also prints each object's retention mode and
  retain-until date. An object without COMPLIANCE retention is a problem and
  fails verification.

## Considered options

- **Tencent COS object lock.** Keeps everything in one cloud. Blocked on an
  allowlist request with no date. Irreversible once granted. Remains
  available as `KEEL_ARCHIVE_PROVIDER=tencent`.
- **COS with delete-deny policies only.** What runs today. An organisation
  admin can lift it, so it is tamper-evident at best, not WORM.
- **S3 Object Lock in GOVERNANCE mode.** Principals with
  `s3:BypassGovernanceRetention` can delete. That defeats the purpose.

## Consequences

- The archive lives in a second cloud. The log-archive Cloud Account becomes
  an AWS member account under the AWS organisation.
- Object Lock cannot be turned off and COMPLIANCE retention cannot be
  shortened. A wrongly set retention costs storage until it expires. That is
  why Keel enforces a floor and has no way to set a mode other than COMPLIANCE.
- A misconfigured bucket stops Keel at startup instead of silently writing
  unlocked objects.
- Existing COS archives stay readable. Moving them follows the migration in
  `docs/runbooks/log-archive.md`.
- Supersedes the "COS object lock" clause of ADR-0005's tamper-evidence
  consequence.
