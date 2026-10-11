# Runbook: onboard a client-owned cloud organisation

Some Tenants own their cloud organisation and pay its bill
([ADR-0018](../adr/0018-client-owned-organisations-read-only.md)). Keel is
read-only there. This runbook is for the Keel operator and the client's cloud
admin. It covers what main implements today: bill ingestion from a client's
**Tencent Cloud payer** (#182) and **AWS management account** (#183).
[connect-billing.md](connect-billing.md) holds the full provider detail; this
page is the onboarding order and the client's security-review summary.

## What Keel does and never does

Keel reads, through one role the client creates in its payer or management
account:

- FOCUS bill files from the client's Bill Storage bucket (Tencent) or Data
  Exports folder (AWS);
- on Tencent, the invoice totals (`finance:DescribeBill*`) used to reconcile.

Nothing else on main uses the role yet. Budgets, Security Hub, Config,
Compute Optimizer, Advisor and Cloud Monitor are not read from client
organisations.

Keel never does these:

- **No writes into the client's cloud.** Keel does not create or change the
  role, Bill Storage, the export, the bucket, its policy or its key. Every
  flow that writes to a Cloud Account (vending, Landing Zone, Permission
  Boundaries, CI identities, Access Grants, waste cleanup, leak response)
  calls `catalog.RequirePlatformOwned` first. On a client-owned account it
  refuses and records a `keel.cloud_account.change_refused` Activity.
  Remediation stays manual or arrives as a pull request the client merges.
- **No keys.** Keel assumes the role from its own keyless identity. On AWS
  that is web identity, an instance role or container credentials, and
  `aws.Keyless` refuses access keys. On Tencent it is TKE pod identity or the
  CVM role. This is the production configuration. With `KEEL_ENV=dev`,
  Tencent also accepts environment and profile keys
  (`tencent.Credentials()`), so a dev Keel may run on keys. The client never
  hands Keel a secret; `read_only_role` stores only a role ARN.
- **No reads outside the export on AWS.** Every AWS session carries a
  session policy built from the payer's record. It allows `s3:ListBucket` on
  the bucket only for the recorded prefix, `s3:GetObject` only under it, and
  `kms:Decrypt` only on the recorded key via S3 in the bucket's region. AWS
  grants the intersection, so an over-broad role still reads only the export.
- **No spend leaves the Tenant.** A client payer's lines are kept only for
  that Tenant's registered client-owned accounts. Every other line is dropped
  and counted in `dropped_lines` and `dropped_billed`.

## 1. Keel operator: prepare

1. Create or pick the Tenant. Note Keel's base role ARN, the principal the
   client's trust policy names: the role behind Keel's AWS web identity, or
   Keel's Tencent TKE pod identity or CVM role.
2. Register the payer (Tencent payer UIN, or AWS management account id) as a
   client-owned Cloud Account. The role must be in that account. The API
   checks only the ARN's format; the sync refuses a role in any other
   account and raises `client_role_unusable`.

   ```
   POST /v1/tenants/{tenant}/cloud-accounts
   {"provider": "aws", "external_id": "<management account id>", "name": "management", "ownership": "client",
    "read_only_role": {"role_arn": "arn:aws:iam::<management account id>:role/KeelReadOnly"}, "why": "..."}
   ```

   For Tencent, `provider` is `tencent` and `role_arn` is
   `qcs::cam::uin/<payer uin>:roleName/<role>`. An existing platform-owned
   account moves with `PATCH /v1/tenants/{tenant}/cloud-accounts/{account}`
   and `{"ownership": "client", "read_only_role": {...}, "why": "..."}`. That
   PATCH is refused while an Access Grant in the account is requested or
   active; reject or revoke them first.
3. Record the payer. The bucket may be empty until the client has set up
   delivery.

   ```
   PUT /v1/tenants/{tenant}/cloud-accounts/{account}/client-payer
   {"bucket": "<bucket>", "prefix": "<folder>/", "region": "<bucket region>", "mode": "<mode>", "kms_key_arn": "<key ARN, AWS SSE-KMS only>", "why": "..."}
   ```

   **`PUT` replaces the whole record.** Every PUT, including one that
   changes a single field, must resend `bucket`, `prefix`, `region`, `mode`
   and (AWS SSE-KMS) `kms_key_arn`. A field you omit is cleared or reset to
   its default, and an empty `bucket` makes the next sync raise
   `bill_delivery_missing`. Drop `kms_key_arn` on Tencent (it is refused) and
   `mode` on AWS unless you want the default.

   `prefix` is a folder with **no leading slash and a trailing slash**,
   `focus/` or `reports/export/`, or empty for the whole bucket. For AWS
   Keel adds the trailing slash if you leave it off (`cost.FolderPrefix`), so
   `reports/export` and `reports/export/` behave alike; Tencent uses the
   value as sent, so send the slash. A leading slash names a different key
   and matches nothing.

   Defaults: Tencent `region` `ap-bangkok`, `mode` `cumulative` (or
   `per-day`); AWS `region` `us-east-1`, `mode` `export-folder`. The
   **first** PUT returns `role_external_id`, a 32-character hex value Keel
   generates. Later PUTs never return it and no API reads it back, so send it
   to the client now. Nobody can choose or change it (#213).
4. Give Keel's base role `sts:AssumeRole` on the client's role ARN. This is a
   change in Keel's own account, not the client's.

## 2. Client admin: create the read-only role and delivery

### AWS management account

1. **Data Exports.** Billing and Cost Management, Data Exports, Create
   export: Standard data export, FOCUS 1.2 with AWS columns, all columns,
   "Overwrite existing data export file", gzip text/csv, an S3 bucket in this
   account under its own prefix. Leave the bucket policy Data Exports writes.
2. **Role.** IAM, Create role, Another AWS account (Keel's account id),
   Require external ID with `role_external_id`. Then narrow the principal to
   Keel's base role ARN. Final trust policy:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {"AWS": "<Keel's base role ARN>"},
       "Action": "sts:AssumeRole",
       "Condition": {"StringEquals": {"sts:ExternalId": "<role_external_id>"}}
     }]
   }
   ```

   Inline permissions policy, nothing else. `<prefix>` is the same value as
   the payer's `prefix`, trailing slash included (`focus/`), so the resource
   reads `arn:aws:s3:::<bucket>/focus/*`. For an empty prefix write
   `arn:aws:s3:::<bucket>/*`.

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::<bucket>"},
       {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::<bucket>/<prefix>*"}
     ]
   }
   ```

3. **KMS (only if the bucket uses SSE-KMS).** Add this statement, make sure
   the key policy lets the role use the key, and give Keel the key ARN (not
   an alias) for `kms_key_arn`. It must be in the bucket's region.

   ```json
   {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "<key ARN>",
    "Condition": {"StringEquals": {"kms:ViaService": "s3.<bucket region>.amazonaws.com"}}}
   ```

### Tencent Cloud payer

1. **Bill Storage.** Billing Center, Bill Overview, Bill Storage: deliver
   only the Standard bill (FOCUS) to a private COS bucket in the payer, under
   its own prefix.
2. **Role.** A CAM role whose trust policy allows `sts:AssumeRole` from
   Keel's base role ARN only, with the console's external ID option set to
   `role_external_id`. The hand-written fallback condition is
   `{"string_equal": {"sts:external_id": "<role_external_id>"}}`. Tencent
   does not document that key; a wrong key fails closed
   ([connect-billing.md](connect-billing.md#tencent-cloud-client-owned-payer-adr-0018-182)).
   Permissions:

   ```json
   {
     "version": "2.0",
     "statement": [
       {"effect": "allow", "action": ["finance:DescribeBill*"], "resource": ["*"]},
       {"effect": "allow", "action": ["cos:GetBucket", "cos:HeadBucket", "cos:GetObject", "cos:HeadObject"],
        "resource": ["qcs::cos:<region>:uid/<appid>:<bucket>/*", "qcs::cos:<region>:uid/<appid>:<bucket>"]}
     ]
   }
   ```

   connect-billing.md also lists `monitor:` and `advisor:` read actions for
   future reads. Nothing on main uses them, so leave them off until it does.

The client then sends Keel the bucket, prefix, region and, on AWS, any KMS
key ARN. The operator records them with the same `PUT .../client-payer`,
sending the full body (step 1.3), not only the new fields.

## 3. Keel operator: register member accounts

Register every member account whose spend the Tenant should see, as a
client-owned Cloud Account of the same provider (`POST .../cloud-accounts`
with `"ownership": "client"`). The API requires a `read_only_role` on every
client-owned account. On main Keel assumes only the payer's role, so a
member's role is recorded but unused. Lines for unregistered accounts are
dropped from that Tenant.

## 4. Verify

The client sync runs at keel-api start and then hourly. It needs no
environment variable; client payers are data.

1. **Role health.** Open the Tenant page in the portal. Each client-owned
   account shows a read-only role panel, under "Unassigned client-owned
   accounts" until the account is assigned to a project. The same data is at
   `GET /v1/tenants/{tenant}/cloud-accounts/role-health`.
   - **Last successful assume** is `client_payers.last_assumed_at`. Every
     client bill sync stamps it when a real AssumeRole succeeds. Resolving a
     Finding by hand never moves it. It reads "never" until the first
     success. Only the payer's role is ever assumed, so a member account
     always reads "never".
   - **Last bill ingested** is the latest cost load that carried the
     account's lines.
   - **Open role and delivery Findings** lists the open
     `client_role_unusable`, `bill_delivery_missing` and `bill_sync_blocked`
     Findings for the account.
2. **Role Finding.** `GET /v1/tenants/{tenant}/findings?kind=client_role_unusable`
   lists a Finding while Keel cannot assume the role (missing role, wrong
   principal, wrong or missing ExternalId). Its `detail.configure` says what
   to fix. It resolves on the next successful AssumeRole.

   **Known gap (#217).** Tencent has no readiness check for Keel's own
   identity like the AWS one. If Keel's Tencent credentials fail (for
   example `no credential found in every providers`), the same
   `client_role_unusable` Finding appears in the **client's** Tenant even
   though the client's role is fine. Check keel-api's own Tencent identity
   before sending the client to fix their role.
3. **Delivery.** `GET /v1/tenants/{tenant}/findings?kind=bill_delivery_missing`
   lists a Finding while no bucket is recorded, the bucket cannot be opened
   after the role was assumed, or it holds no bill files under the prefix. It
   resolves once bills arrive.
4. **First bill.** "Last bill ingested" fills in, and
   `GET /v1/tenants/{tenant}/activities?type=keel.cost.loaded` shows each
   load in the client Tenant. A home-Tenant operator sees the load itself,
   with `dropped_lines`, `dropped_billed` and `reconcile_status`, at
   `GET /v1/tenants/{home}/cost-loads`. AWS has no invoice source, so AWS
   client loads are not reconciled against an invoice.
5. **Keel's own side.** If Keel's AWS identity cannot load or is not
   keyless, keel-api logs `ALERT client bill sync failed` for provider `aws`
   once per run and raises no client Finding. Tencent sync carries on.

`bill_sync_blocked` means Keel refused to load a month because two bill
files charge the same sub-account for the same hours. That happens only in
Tencent `per-day` mode, usually because the month-to-date files need
`cumulative` or a second bill type is delivered to the prefix. Fix the
client payer's `mode` with `PUT .../client-payer` (resend `bucket`,
`prefix`, `region` and the new `mode`; the PUT replaces the whole record and
a bare `{"mode": ...}` clears the bucket), or have the client clean
the prefix; the next load resolves it. For a client payer this Finding is
raised in the **client's** Tenant and shows in its role health panel. Its
hint text still says to check `KEEL_TENCENT_BILL_MODE`. Ignore that for a
client payer: the variable sets only Keel's own payer's mode, and a client
payer's mode is the `mode` field above (#216).

## 5. Offboard

1. Archive the payer and member accounts:
   `POST /v1/tenants/{tenant}/cloud-accounts/{account}/archive` with
   `{"why": "..."}`. Sync skips archived payers, and ingestion stops
   attributing lines to archived accounts.
2. Resolve any open `client_role_unusable` or `bill_delivery_missing`
   Findings by hand
   (`POST /v1/tenants/{tenant}/findings/{finding}/resolve` with
   `{"resolution": "..."}`). Sync no longer visits the payer, so they will
   not resolve themselves.
3. The client deletes the role. Keel never does.
4. Remove `sts:AssumeRole` on that role from Keel's base role.

**ExternalId rotation is not supported.** Keel cannot issue a new
`role_external_id`, and an archived payer cannot be registered again because
`(provider, external_id)` is unique even across archived accounts. Tracked
in #213.

## Not yet supported

- **Azure, Google Cloud, Alibaba Cloud** (#184). The API accepts a
  client-owned account on these providers with its `read_only_role`
  (Azure `tenant_id` and `client_id`, GCP `workload_identity_provider` and
  `service_account`, Alibaba `role_arn`), and the mutating-flow guard
  applies. Nothing assumes those identities, and `PUT .../client-payer`
  refuses any provider but `tencent` and `aws`. There are no onboarding
  steps for them yet.
- **Findings, Budgets and rightsizing from client organisations** (#182,
  #183 follow-ups). Only bills are read today.
- **ExternalId rotation and re-onboarding** (#213).
