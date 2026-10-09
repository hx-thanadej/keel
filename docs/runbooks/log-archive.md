# Runbook: Activity Log archive account (#25, ADR-0005, ADR-0019)

The Activity Log is sealed hourly into a per-Tenant signed digest chain
(`internal/integrity`). Each sealed digest and the activities it covers are
shipped to an object-storage bucket in a **separate, platform-owned log-archive
Cloud Account** that nobody can delete from. The archive can be verified
without the database: `keel-api verify-archive`.

New installs use **AWS S3 Object Lock** (`KEEL_ARCHIVE_PROVIDER=aws`, the
default; ADR-0019). Existing Tencent COS archives keep working with
`KEEL_ARCHIVE_PROVIDER=tencent` (section 7) until they are migrated
(section 8).

## 1. Account and bucket (AWS)

1. Create a member account `keel-log-archive` in the AWS organisation.
   Platform-owned. No workloads. Hardware MFA on its root user.
2. Create the bucket **with Object Lock enabled**. Object Lock can only be
   chosen at creation. Enabling it also enables versioning, which must stay on.

   ```bash
   aws s3api create-bucket --bucket <bucket> --region <region> \
     --create-bucket-configuration LocationConstraint=<region> \
     --object-lock-enabled-for-bucket
   ```

3. Set a **default retention** of COMPLIANCE for 2555 days. Keel sets
   retention on every object it writes. The default also locks anything
   copied in by hand, such as the migration in section 8.

   ```bash
   aws s3api put-object-lock-configuration --bucket <bucket> \
     --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":2555}}}'
   ```

4. Default encryption SSE-S3 (`AES256`). Block all public access.
5. Lifecycle: transition to Glacier Instant Retrieval or Deep Archive after 90
   days. **No expiration rule.** Locked versions cannot be expired before
   their retain-until date anyway.

COMPLIANCE mode cannot be shortened or removed by anyone, including the root
user. Test the commands in a throwaway account with `Days: 1` first.

## 2. Bucket policy

Replace `<bucket>` and `<keel-role-arn>`. The policy denies plain HTTP, denies
uploads that ask for an encryption other than the bucket's SSE-S3, denies
deletes for everyone (a delete on a versioned bucket adds a delete marker,
which would hide an object from `verify-archive`), and grants Keel's role its
access.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::<bucket>", "arn:aws:s3:::<bucket>/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyOtherEncryption",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::<bucket>/*",
      "Condition": {
        "Null": { "s3:x-amz-server-side-encryption": "false" },
        "StringNotEquals": { "s3:x-amz-server-side-encryption": "AES256" }
      }
    },
    {
      "Sid": "DenyDeletes",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:BypassGovernanceRetention",
        "s3:PutBucketObjectLockConfiguration",
        "s3:PutBucketVersioning",
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy"
      ],
      "Resource": ["arn:aws:s3:::<bucket>", "arn:aws:s3:::<bucket>/*"]
    },
    {
      "Sid": "KeelArchiveWriter",
      "Effect": "Allow",
      "Principal": { "AWS": "<keel-role-arn>" },
      "Action": [
        "s3:PutObject",
        "s3:PutObjectRetention",
        "s3:GetObject",
        "s3:GetObjectRetention",
        "s3:ListBucket",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketVersioning"
      ],
      "Resource": ["arn:aws:s3:::<bucket>", "arn:aws:s3:::<bucket>/*"]
    }
  ]
}
```

Also attach an **organisation service control policy** to the archive account
denying `s3:DeleteObject*`, `s3:DeleteBucket*`, `s3:PutBucketPolicy` and
`s3:PutBucketObjectLockConfiguration` for all principals. Lifting it is a
break-glass procedure recorded by CloudTrail.

## 3. Keel's role (keyless)

Keel never holds AWS access keys (ADR-0007). It reads credentials from web
identity (`AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE`, OIDC from Keel's
cluster) or the instance role. The AWS bill sync uses the same role
(`docs/runbooks/connect-billing.md`). When the bucket is in another account,
both that role's identity policy and the bucket policy above must allow the
actions. The role's minimal archive permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject", "s3:GetObjectRetention"],
      "Resource": "arn:aws:s3:::<bucket>/activity-log/*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketVersioning"],
      "Resource": "arn:aws:s3:::<bucket>"
    }
  ]
}
```

No delete. No `s3:BypassGovernanceRetention`.

```bash
KEEL_DIGEST_KEY=…                   # Ed25519 seed; keep in the secret store
KEEL_ARCHIVE_PROVIDER=aws           # default
KEEL_ARCHIVE_BUCKET=<bucket>
KEEL_ARCHIVE_REGION=<region>        # endpoint defaults to s3.<region>.amazonaws.com
KEEL_ARCHIVE_RETENTION_DAYS=2555    # default; Keel rejects < 365
AWS_ROLE_ARN=<keel-role-arn>
AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/…/token
```

Every object Keel writes carries `x-amz-object-lock-mode: COMPLIANCE`, a
retain-until date of now plus `KEEL_ARCHIVE_RETENTION_DAYS`, and
`Content-MD5`. Legal hold is not set.

At startup Keel reads the bucket's Object Lock configuration and versioning
status. If Object Lock or versioning is not enabled it exits with
`refusing to archive: archive bucket … does not have Object Lock enabled` (or
`… versioning enabled`). Recreate the bucket per section 1. An existing bucket
cannot be fixed by Keel.

Keel seals every hour, then exports. Failures log `ALERT activity log …`.
Route those to on-call.

## 4. Verify

```bash
keel-api digest-pubkey                       # publish key_id + pubkey; give clients theirs
keel-api verify-log     -tenant <id> -pubkey <base64>   # database copy
keel-api verify-archive -tenant <id> -pubkey <base64>   # archive copy, no database needed
```

Both exit non-zero and print `PROBLEM:` lines for altered or deleted
activities, removed digests, broken chains or bad signatures. After key
rotation pass old and new public keys, comma-separated.

On `aws`, `verify-archive` also prints one line per object:
`RETENTION <key> COMPLIANCE until <date>`, or `RETENTION <key> none`. An
object without COMPLIANCE retention is a `PROBLEM:` and fails verification.
The verifier needs the same read permissions as Keel's role.

## 5. Acceptance check (do once after setup)

1. Start Keel against a bucket created **without** Object Lock. It must refuse
   to start with the error in section 3.
2. Point it at the real bucket. Wait one hour. Confirm objects under
   `activity-log/v1/<tenant>/` and run `verify-archive`. Every `RETENTION`
   line says `COMPLIANCE` and the result is `OK`.
3. As the archive account's root user, attempt
   `aws s3api delete-object --version-id <id>` on one archived version. It is
   denied, and the attempt appears in CloudTrail.

## 6. What is still unverified

Keel's tests run against a local S3 fake. They prove the headers Keel sends
and how it reads the lock and versioning responses. They do not prove that AWS
accepts them. The acceptance check in section 5 is that proof.

## 7. Existing Tencent COS archives (`KEEL_ARCHIVE_PROVIDER=tencent`)

This is the behaviour before ADR-0019. Keel writes without object-lock
headers and does not check the bucket. Protection is the delete-deny bucket
policy and organisation policy only.

1. A COS bucket in `ap-bangkok` in a `keel-log-archive` member account,
   private, **versioning enabled**, no expiration rule.
2. Bucket policy denying, for `qcs::cam::anyone:anyone`:
   `name/cos:DeleteObject`, `name/cos:DeleteMultipleObjects`,
   `name/cos:PutBucketVersioning`, `name/cos:DeleteBucketPolicy`,
   `name/cos:PutBucketPolicy`, `name/cos:PutBucketLifecycle`,
   `name/cos:DeleteBucket` on the bucket and `/*`. Validate in a sandbox
   bucket first. An organisation policy on the account denies
   `cos:DeleteObject`, `cos:DeleteBucket*` and `cos:PutBucketPolicy`.
3. Keel writes with short-lived Tencent STS credentials (TKE pod identity or
   CVM role). Its role has only `name/cos:PutObject`, `name/cos:GetObject`,
   `name/cos:GetBucket`.

```bash
KEEL_ARCHIVE_PROVIDER=tencent
KEEL_ARCHIVE_BUCKET=<bucket>-<appid>
KEEL_ARCHIVE_ENDPOINT=cos.ap-bangkok.myqcloud.com
KEEL_ARCHIVE_REGION=ap-bangkok
```

An upgrade that leaves `KEEL_ARCHIVE_PROVIDER` unset selects `aws`. With a
COS endpoint still set, Keel exits and asks for
`KEEL_ARCHIVE_PROVIDER=tencent`.

## 8. Migrating a COS archive to S3

Use a **one-time copy**, not a dual-write window. Keel records each digest as
exported once (`activity_exports`), so after the switch new digests go only
to S3 and the key sets of the two buckets never overlap. `verify-archive`
checks the chain from its first digest, so the S3 copy verifies only once the
COS history is in it.

1. Create the S3 bucket per sections 1 to 3, including the default retention.
2. Switch Keel to `KEEL_ARCHIVE_PROVIDER=aws` and the new bucket. Restart.
   Keel must start (lock and versioning checked).
3. Copy every object under `activity-log/v1/` from COS to the same keys in S3,
   for example with `rclone copy cos:<bucket>-<appid>/activity-log/v1 s3:<bucket>/activity-log/v1`
   run as an operator. The bucket's default retention locks each copy in
   COMPLIANCE mode. The retain-until date counts from the copy, not the
   original write. That keeps it at least as long as required.
4. For every Tenant run `verify-archive` against S3. The result is `OK` and
   every `RETENTION` line says `COMPLIANCE`.
5. Keep the COS bucket and its delete-deny policies. Do not delete it. Note
   the migration date and the verify output in the Activity Log.
