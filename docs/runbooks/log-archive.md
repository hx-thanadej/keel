# Runbook: Activity Log archive account (#25, ADR-0005)

The Activity Log is sealed hourly into a per-Tenant signed digest chain
(`internal/integrity`). Each sealed digest and the activities it covers are
shipped to an object-storage bucket in a **separate, platform-owned log-archive
Cloud Account** that nobody can delete from. The archive can be verified
without the database: `keel-api verify-archive`.

## 1. Account and bucket

1. Create a member account `keel-log-archive` in the Tencent Cloud organisation
   (platform-owned; no workloads; hardware MFA on its root).
2. In it, create a COS bucket in `ap-bangkok`, private, **versioning enabled**
   (an overwrite then keeps the original version).
3. Lifecycle: transition to archive tier after 90 days; **no expiration rule**
   (retention ≥ 7 years, DESIGN §8).

## 2. Deny deletes for everyone

Bucket policy (replace `<appid>` and `<bucket>`). Tencent COS policy syntax:
principal `qcs::cam::anyone:anyone`, effect `deny`, actions `name/cos:*`.
**Validate in a sandbox bucket before applying**: Keel has not applied it to a
real account yet.

```json
{
  "version": "2.0",
  "Statement": [
    {
      "Principal": { "qcs": ["qcs::cam::anyone:anyone"] },
      "Effect": "Deny",
      "Action": [
        "name/cos:DeleteObject",
        "name/cos:DeleteMultipleObjects",
        "name/cos:PutBucketVersioning",
        "name/cos:DeleteBucketPolicy",
        "name/cos:PutBucketPolicy",
        "name/cos:PutBucketLifecycle",
        "name/cos:DeleteBucket"
      ],
      "Resource": [
        "qcs::cos:ap-bangkok:uid/<appid>:<bucket>-<appid>/*",
        "qcs::cos:ap-bangkok:uid/<appid>:<bucket>-<appid>"
      ]
    }
  ]
}
```

Because the policy also denies changing itself, it can only be lifted by the
organisation admin through a break-glass procedure, which is itself audited by
CloudAudit.

Also add an **organisation service control policy** on the archive account
denying `cos:DeleteObject`, `cos:DeleteBucket*` and `cos:PutBucketPolicy` for
all principals (defence in depth if the bucket policy is misapplied).

## 3. WORM (object lock)

COS object lock is allowlist-only and irreversible once enabled. Request it for
this bucket (tracked in #15). Until granted, sections 2 and the SCP are the
protection.

## 4. Keel's write access

Keel writes with **short-lived STS credentials** (TKE pod identity or CVM role;
ADR-0007). Grant its role only `name/cos:PutObject`, `name/cos:GetObject`,
`name/cos:GetBucket` on this bucket. No delete.

```bash
KEEL_DIGEST_KEY=…            # Ed25519 seed; keep in the secret store
KEEL_ARCHIVE_BUCKET=<bucket>-<appid>
KEEL_ARCHIVE_ENDPOINT=cos.ap-bangkok.myqcloud.com
KEEL_ARCHIVE_REGION=ap-bangkok
```

Keel seals every hour, then exports. Failures log `ALERT activity log …`.
Route those to on-call.

## 5. Verify

```bash
keel-api digest-pubkey                       # publish key_id + pubkey; give clients theirs
keel-api verify-log     -tenant <id> -pubkey <base64>   # database copy
keel-api verify-archive -tenant <id> -pubkey <base64>   # archive copy, no database needed
```

Both exit non-zero and print `PROBLEM:` lines for altered or deleted
activities, removed digests, broken chains or bad signatures. After key
rotation pass old and new public keys, comma-separated.

## 6. Acceptance check (do once after setup)

1. Wait one hour; confirm objects under `activity-log/v1/<tenant>/` and run
   `verify-archive` → `OK`.
2. As the organisation admin, attempt `DeleteObject` on one archived object →
   denied, and the attempt appears in CloudAudit.
