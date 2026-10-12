# Runbook: connect real billing data (Tencent first, AWS optional)

Everything in M1 is built and tested against fixtures. These steps connect it
to real money. Each needs someone with access to the payer / management account.

## Tencent Cloud (payer UIN 200045645249), ticket #29

**Use the wizard.** Run `scripts/wizards/tencent-payer-billing.sh` with
`tccli` signed in as the payer (`TCCLI_PROFILE=<name>` picks a profile). It
walks steps 1 to 5 below, verifies each with `tccli` where it can, probes the
`*ForOrganization` question for #9, and keeps its answers in `.keel/`
(git-ignored), so a re-run resumes. It never asks for an access key. The manual
steps below are the reference for what it does.

Keel signs its Tencent calls with one keyless base identity
(`tencent.Credentials()`: TKE pod identity, else the CVM role). The wizard asks
for that base role's ARN and creates a separate billing role in the payer,
`KEEL_TENCENT_BILL_ROLE`. Its trust policy allows `sts:AssumeRole` from that
ARN alone. It needs no OIDC provider in the payer, and keel-api's
ServiceAccount or CVM role stays as it is. Keel's base role needs
`sts:AssumeRole` on the billing role. The wizard writes that policy to
`.keel/base-assume.json` for the account that owns the base role. Budget
mirroring still runs as the base identity, so its budget permissions go on the
base role (`.keel/base-budgets.json`), never on the billing role.

`bash scripts/wizards/test-tencent-payer-billing.sh` dry-runs the wizard
against a stubbed `tccli` in a temp `HOME`, fresh and resumed, and checks the
config it prints. Run it with `/bin/bash` and a current bash after changing
the wizard.

1. **Bill delivery.** In the payer account, open Billing Center, Bill
   Overview, Bill Storage. Deliver only the **Standard bill (FOCUS)** to a
   private COS bucket in the payer account (`keel-bills-<appid>`), under its
   own prefix. Do not deliver the Cost Allocation Bill (FOCUS) or any other
   bill type to that prefix. Tick the 18-month historical sync. Tencent's daily
   FOCUS file is month-to-date, so step 4 sets `cumulative`.
2. **Read-only billing role.** Create a CAM role in the payer account and name
   it in `KEEL_TENCENT_BILL_ROLE`. Its trust policy allows `sts:AssumeRole`
   from Keel's base role ARN and nothing else. Attach these permissions.
   - The `QcloudFinanceBillReadOnlyAccess` preset. It covers
     `finance:DescribeBill*`, which includes `DescribeBillSummaryByPayMode`.
   - COS read on the bill bucket. That is `cos:GetBucket`, `cos:HeadBucket`,
     `cos:GetObject` and `cos:HeadObject`. The wizard puts these in a policy
     named `KeelBillBucketRead`.

   Budget mirroring (#39) needs `CreateBudget`, `ModifyBudget`, `DeleteBudget`
   and `DescribeBudget`. Those stay on the base identity and never go on the
   billing role. The CAM namespace is unverified, so take it from the visual
   editor.
3. **Configure Keel.**
   ```
   KEEL_TENCENT_BILL_BUCKET=keel-bills-<appid>
   KEEL_TENCENT_BILL_PREFIX=<folder of the Standard bill (FOCUS) files>
   KEEL_TENCENT_PAYER_UIN=200045645249
   KEEL_TENCENT_BILL_ROLE=<role name>    # recommended: payer role for bill sync
   KEEL_TENCENT_REGION=ap-bangkok
   KEEL_TENCENT_BILL_MODE=cumulative     # daily FOCUS files are month-to-date; see step 4
   KEEL_TENCENT_BUDGETS=1                # optional: mirror Budgets
   ```

   `KEEL_TENCENT_BILL_ROLE` is the role name from step 2, not an ARN. Keel
   builds the ARN from `KEEL_TENCENT_PAYER_UIN`. Keel's base identity assumes
   the role with STS AssumeRole, renews it before expiry, and uses it only for
   bill sync and invoice reconciliation. Unset, bill sync uses the base
   identity and Keel logs a warning at startup.

   Keel parses every bill file under the prefix as FOCUS. It skips Cost
   Allocation Bill files by name and any file that is not FOCUS, and records a
   `keel.cost.bill_file_skipped` Activity per file. In `per-day` mode it also
   fails the run on overlapping per-day files (#201), so a wrong prefix or
   mode does not double count silently.

4. **Confirm the file mode on the first delivery.** Tencent documents the
   daily FOCUS file as month-to-date, so use `cumulative` for daily delivery.
   Open two consecutive daily files to confirm. If day 2's file also contains
   day 1, keep `cumulative`. If it holds only day 2's lines, set `per-day`
   instead. A wrong mode double-counts or drops days.
   `GET /v1/tenants/{home}/cost-loads` shows the reconciliation against the
   invoice total, which says `mismatch` if the mode is wrong.
5. **Check.** Within an hour, `GET …/cost-loads` lists loads with
   `reconcile_status: ok`. The Budgets tab shows spend for Projects whose
   Cloud Accounts are registered (`POST …/discoveries/tencent`, then register
   the suggested accounts).

Until then, a FOCUS export downloaded from the console can be uploaded:
`POST /v1/tenants/{home}/cost-loads?provider=tencent&billing_account=200045645249&period=YYYY-MM`.

## Tencent Cloud client-owned payer (ADR-0018, #182)

Some Tenants own their Tencent Cloud organisation and pay its bill. Keel reads
that payer's bills through a read-only role the client creates. It never
writes there: it does not set up Bill Storage, touch the bucket or change the
role. Each client payer is data, not an environment variable, so one Keel runs
any number of them.

[onboard-client-org.md](onboard-client-org.md) gives the end-to-end
onboarding order, verification and offboarding for Tencent and AWS client
payers.

1. **The client creates a read-only CAM role in its payer account.** The
   trust policy allows `sts:AssumeRole` from Keel's base role ARN and nothing
   else, and requires Keel's ExternalId for this payer (step 3 returns it as
   `role_external_id`). Keel's base role needs `sts:AssumeRole` on the
   client's role ARN. The role carries only read actions.

   Set the ExternalId in the Tencent console. When creating or editing the
   role, turn on its "external ID" option and enter the `role_external_id`
   value ([Creating a Role](https://www.tencentcloud.com/document/product/598/19381)).
   Keel generates it per payer and sends it on every AssumeRole
   ([STS AssumeRole `ExternalId`](https://www.tencentcloud.com/document/api/1150/49456)).
   Nobody can choose or change it, so a payer and role registered again in
   another Tenant gets a different ExternalId and cannot assume this role.

   Fallback, if the console has no such option: write the condition into the
   trust policy by hand.

   ```json
   {
     "version": "2.0",
     "statement": [
       {"effect": "allow", "action": "name/sts:AssumeRole",
        "principal": {"qcs": ["<Keel's base role ARN>"]},
        "condition": {"string_equal": {"sts:external_id": "<role_external_id from step 3>"}}}
     ]
   }
   ```

   Tencent's docs do not print the condition key, so `sts:external_id` is
   unverified. Check it: after saving, open the role's trust policy and compare
   it with what the console's external ID option writes for a test role. A
   wrong key fails closed. AssumeRole is refused and Keel raises
   `client_role_unusable`.
   The role's permissions:

   ```json
   {
     "version": "2.0",
     "statement": [
       {"effect": "allow", "action": ["finance:DescribeBill*"], "resource": ["*"]},
       {"effect": "allow", "action": ["cos:GetBucket", "cos:HeadBucket", "cos:GetObject", "cos:HeadObject"],
        "resource": ["qcs::cos:<region>:uid/<appid>:<bucket>/*", "qcs::cos:<region>:uid/<appid>:<bucket>"]},
       {"effect": "allow", "action": ["monitor:Describe*", "monitor:GetMonitorData"], "resource": ["*"]},
       {"effect": "allow", "action": ["advisor:Describe*"], "resource": ["*"]}
     ]
   }
   ```

   `finance:DescribeBill*` matches the `QcloudFinanceBillReadOnlyAccess`
   preset and covers `DescribeBillSummaryByPayMode`, which Keel uses to
   reconcile. The monitor and advisor statements are for Budget, Advisor and
   rightsizing reads. Their namespaces are unverified, so take the exact names
   from the CAM visual editor and keep only `Describe`, `Get` and `List`
   actions. No statement may grant a `Create`, `Modify`, `Put`, `Delete` or
   `Update` action.
2. **The client sets up delivery.** In the payer, Billing Center, Bill
   Overview, Bill Storage, deliver only the Standard bill (FOCUS) to a private
   COS bucket in the payer account, under its own prefix, as in step 1 of the
   section above.
3. **Register the payer in Keel.** Register the payer as a client-owned Cloud
   Account of the Tenant with the role from step 1. The role must be in the
   payer account itself.
   ```
   POST /v1/tenants/{tenant}/cloud-accounts
   {"provider": "tencent", "external_id": "<payer uin>", "name": "payer", "ownership": "client",
    "read_only_role": {"role_arn": "qcs::cam::uin/<payer uin>:roleName/<role>"}, "why": "..."}
   PUT /v1/tenants/{tenant}/cloud-accounts/{account}/client-payer
   {"bucket": "<bucket>-<appid>", "prefix": "<folder>", "region": "ap-bangkok", "mode": "cumulative", "why": "..."}
   ```
   The first PUT returns `role_external_id`, once. It is not the Cloud
   Account's `external_id`, which is the payer UIN. Later PUTs do not show it. The
   client adds it to the trust-policy condition from step 1. Until then, or
   whenever Keel cannot assume the role, the hourly sync raises a
   `client_role_unusable` Finding in the Tenant naming the role and the
   ExternalId the condition needs, and resolves it on the next successful
   AssumeRole. Only role and trust-policy failures raise it. A bucket error
   after a successful AssumeRole raises `bill_delivery_missing` instead.
   A payer recorded with no bucket is allowed. The hourly sync then raises a
   `bill_delivery_missing` Finding in the Tenant that says what to configure.
   It also raises it when the bucket holds no bill files under the prefix, and
   resolves it once bills arrive.
4. **Register the member accounts.** Keel keeps a client payer's lines only for
   that Tenant's client-owned Cloud Accounts. Every other line is dropped, and
   the load counts it in `dropped_lines` and `dropped_billed`
   (`GET /v1/tenants/{home}/cost-loads`). Reconciliation adds the dropped
   amount back, because the invoice covers the whole payer. Tags and
   allocation rules cannot move a client payer's spend into another Tenant.
   Keel's own payers never attribute spend to a client-owned account: such a
   line stays in the home Tenant unallocated, whatever its tags or the home
   Tenant's allocation rules say.

## AWS client-owned management account (ADR-0018, #183)

Some Tenants own their AWS Organization and pay its bill. Keel reads the
management account's Data Exports through a read-only IAM role the client
creates there. It never writes: it does not create or change the export, the
bucket, the bucket policy or the role. As on Tencent, each client payer is
data, so one Keel reads any number of them.

Keel assumes the role from its own keyless identity (web identity from Keel's
cluster, or an instance or container role; access keys are refused) with
`sts:AssumeRole`, sending its ExternalId for this payer
([AssumeRole `ExternalId`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)).
If Keel's own identity is not keyless, or its AWS config cannot load, each
hourly run with AWS client payers logs one `ALERT client bill sync failed`
for provider `aws` and tries no client role, so no client gets a Finding for
Keel's fault. The Tencent client sync carries on.
Every session also carries a session policy built from the payer's record
in Keel. It allows `s3:ListBucket` on the bucket only with the condition
`StringLike` `s3:prefix` `<prefix>/*`, and `s3:GetObject` only on
`arn:aws:s3:::<bucket>/<prefix>/*`. When the payer records an SSE-KMS key, it
also allows `kms:Decrypt` on that key ARN only, with the condition
`StringEquals` `kms:ViaService` `s3.<region>.amazonaws.com`, so the key
decrypts only for S3 in the bucket's region and never for a direct KMS call
([kms:ViaService](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html#conditions-kms-via-service)).
AWS grants the intersection of the role's policy and the session policy, so
even an over-broad role lists and reads only the export prefix through Keel.
A payer recorded with an empty prefix gets the whole bucket: `ListBucket`
without a condition and `GetObject` on `<bucket>/*`. Record the export's folder as the prefix.

The role needs exactly these actions:

- `s3:ListBucket` on the bucket. `ListObjectsV2` requires it
  ([ListObjectsV2, Permissions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html)).
- `s3:GetObject` on the export's objects. `GetObject` requires it
  ([GetObject, Permissions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)).
- Only for an SSE-KMS bucket, `kms:Decrypt` on the bucket's key. Downloading
  an SSE-KMS object requires it, and the key is in the bucket's region
  ([Using SSE-KMS, Permissions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)).
  A bucket on the default SSE-S3 needs no KMS permission.

Keel also reads Budgets, Security Hub findings (which include Config rule
findings) and Cost Optimization Hub recommendations (which include Compute
Optimizer's) with the same role, in a session limited to
`budgets:ViewBudget`, `securityhub:GetFindings` and
`cost-optimization-hub:ListRecommendations`. Add those three actions to the
role for them; [onboard-client-org.md](onboard-client-org.md#aws-management-account)
has the full policy.

1. **The client sets up the export.** In the management account, open
   Billing and Cost Management, Data Exports, Create export
   ([Creating a standard export](https://docs.aws.amazon.com/cur/latest/userguide/dataexports-create-standard.html)).
   Choose Standard data export, the table FOCUS 1.2 with AWS columns, all
   columns, file versioning "Overwrite existing data export file",
   compression "gzip - text/csv", and an S3 bucket in **This account**, under
   its own S3 path prefix. Data Exports writes its own bucket policy for
   delivery; leave it.
2. **The client creates the read-only role**, console first. In IAM, Roles,
   Create role, choose **AWS account**, **Another AWS account**, and enter the
   account id of Keel's base role. Tick **Require external ID** and enter the
   `role_external_id` from step 3
   ([Creating an IAM role (console)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html);
   [Access to AWS accounts owned by third parties](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html)).
   Skip the managed policies, name the role (for example `KeelReadOnly`), and
   add the inline permissions policy below. Then edit the trust policy so the
   principal is Keel's base role ARN rather than the whole account. The JSON
   it should end with:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {"AWS": "<Keel's base role ARN>"},
       "Action": "sts:AssumeRole",
       "Condition": {"StringEquals": {"sts:ExternalId": "<role_external_id from step 3>"}}
     }]
   }
   ```

   `sts:ExternalId` is the condition key AWS documents for this
   ([IAM and AWS STS condition context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-sts);
   [the confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)).
   Keel generates the ExternalId per payer and nobody can change it, so the
   same role registered in another Tenant gets a different ExternalId and is
   refused. Keel's base role needs `sts:AssumeRole` on the client's role ARN.
   The role's permissions policy:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::<bucket>"},
       {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::<bucket>/<prefix>/*"}
     ]
   }
   ```

   If the bucket uses SSE-KMS, add this statement, and make sure the key's
   key policy lets the role use it (a customer managed key's policy that
   delegates to IAM in the account does):

   ```json
   {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "<key ARN>",
    "Condition": {"StringEquals": {"kms:ViaService": "s3.<bucket region>.amazonaws.com"}}}
   ```

   No statement may grant a `Put`, `Delete`, `Create`, `Update` or `Modify`
   action.
3. **Register the management account in Keel.** The role must be in the
   management account itself.
   ```
   POST /v1/tenants/{tenant}/cloud-accounts
   {"provider": "aws", "external_id": "<management account id>", "name": "management", "ownership": "client",
    "read_only_role": {"role_arn": "arn:aws:iam::<management account id>:role/KeelReadOnly"}, "why": "..."}
   PUT /v1/tenants/{tenant}/cloud-accounts/{account}/client-payer
   {"bucket": "<bucket>", "prefix": "<S3 path prefix>/<export name>/", "region": "<bucket region>",
    "kms_key_arn": "<the bucket's SSE-KMS key ARN, or omit for SSE-S3>", "why": "..."}
   ```
   The prefix is the export's folder: Keel treats a non-empty prefix as ending
   in `/`, so `reports/export` and `reports/export/` both read only
   `reports/export/...` and never a sibling such as `reports/export2/`. An
   empty prefix means the whole bucket, so leave it empty only when the bucket
   holds nothing but this export.
   `kms_key_arn` must be a key ARN (`arn:aws:kms:<bucket region>:<account>:key/<id>`),
   not an alias. The prefix may not contain `*`, `?` or `$`, since it becomes
   part of the session policy.
   `mode` defaults to `export-folder`, the only AWS mode, and `region` to
   `us-east-1`. The first PUT returns `role_external_id`, once; later PUTs do
   not show it. The `client_role_unusable` and `bill_delivery_missing`
   Findings work as for a Tencent client payer (step 3 above), worded for
   AWS: the first names the role and the `sts:ExternalId` condition, the
   second says how to create the export and what to grant.
4. **Register the member accounts** as client-owned AWS Cloud Accounts of the
   Tenant. As on Tencent, lines for any other account are dropped and counted
   in `dropped_lines` and `dropped_billed`, tags and allocation rules cannot
   move the spend into another Tenant, and Keel's own AWS export never
   attributes spend to a client-owned account.

## AWS (optional, #44)

1. Data Exports in the management account: **FOCUS 1.2 with AWS columns**,
   **CSV, gzip**, overwrite, daily, to S3.
2. An IAM role Keel assumes by web identity (OIDC from Keel's cluster) with
   `s3:GetObject`/`s3:ListBucket` on the export, and for mirroring
   `budgets:ViewBudget`, `budgets:ModifyBudget`.
3. `KEEL_AWS_BILL_BUCKET`, `KEEL_AWS_BILL_PREFIX`, `KEEL_AWS_PAYER_ACCOUNT`,
   `KEEL_AWS_REGION`, `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`;
   optionally `KEEL_AWS_BUDGET_ACCOUNT` and `KEEL_AWS_BUDGET_EMAIL`.

## Shared clusters (#35, optional)

Run OpenCost in each shared TKE cluster and set
`KEEL_OPENCOST=shared-tke=http://opencost.opencost:9003`; then map namespaces
(`PUT /v1/tenants/{home}/k8s-namespaces/{cluster}/{namespace}`) and add a
`k8s` allocation rule for the cluster's account.

## Azure (FOCUS export to Blob Storage)

1. Cost Management → Exports → *Cost and usage details (FOCUS)*, daily,
   month-to-date, CSV (gzip) or Parquet (snappy), **Overwrite data on** so
   each month folder keeps only the latest run. Scope: billing account (EA/MCA;
   pay-as-you-go MOSA accounts cannot export FOCUS).
2. Give Keel's workload identity (Entra app with a federated credential for
   the `keel-api` service account) *Storage Blob Data Reader* on the container.
   No client secret, no storage key.
3. Set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`
   (the workload identity webhook does this), `KEEL_AZURE_BILL_STORAGE_ACCOUNT`,
   `KEEL_AZURE_BILL_CONTAINER`, `KEEL_AZURE_BILL_PREFIX`,
   `KEEL_AZURE_BILLING_ACCOUNT` and `KEEL_AZURE_BILL_EXPORT_REGION` (the
   storage account's region, e.g. `southeastasia`). The PDPA residency check
   places the export there; Keel refuses to start without it.
4. Register Cloud Accounts with the **subscription id** (GUID); Keel strips
   the `/subscriptions/` ARM prefix from `SubAccountId`.
5. Finality: final from the 6th (Azure can change charges until the 5th).

## Google Cloud (FOCUS table → Cloud Storage)

1. Enable the detailed usage cost and pricing exports, then the FOCUS dataset
   (`gcp_billing_export_focus_<BILLING_ACCOUNT_ID>`, Pre-GA).
2. Google does not deliver to Cloud Storage: schedule a BigQuery query that
   runs `EXPORT DATA OPTIONS(uri='gs://<bucket>/focus/<YYYY-MM>/*.parquet',
   format='PARQUET', overwrite=true)` for the current and previous month.
   Parquet keeps `x_Tags`/`x_Labels` nested and Keel reads them as Tags; for
   CSV, select them as `TO_JSON_STRING(x_Tags)`.
3. Keel authenticates with workload identity federation
   (`GOOGLE_APPLICATION_CREDENTIALS` pointing at an `external_account` config,
   or GKE Workload Identity) with *Storage Object Viewer* on the bucket.
   Keel accepts only keyless credentials. These are workload identity
   federation (`external_account`), impersonation whose source is keyless,
   and the metadata server. It refuses service-account key files and
   `authorized_user` refresh tokens.
4. Set `KEEL_GCP_BILL_BUCKET`, `KEEL_GCP_BILL_PREFIX`, `KEEL_GCP_BILLING_ACCOUNT`
   and `KEEL_GCP_BILL_BUCKET_REGION` (the bucket's location, e.g.
   `asia-southeast1`). The PDPA residency check places the bucket there;
   Keel refuses to start without it. Cloud Accounts are GCP **project ids**
   (`SubAccountId`).
5. Finality: Google gives no hard close (invoice by the 5th business day,
   late adjustments booked to later months); Keel treats a month final from
   the 16th.

## Alibaba Cloud (bill subscription to OSS)

1. Expenses and Costs → Bills → Bill Subscription → OSS Subscription. Use
   *Standard Bill FOCUS* if the account is in the preview (parsed as FOCUS;
   `X_` columns kept), otherwise the new-version standard detailed bill,
   which Keel maps to FOCUS (gaps listed in `internal/cost/alibaba.go`: daily
   charge periods, categories by keyword, no amortized cost).
2. Keel uses RRSA on ACK: a RAM role trusting the cluster's OIDC provider with
   `oss:GetObject` and `oss:ListObjects` on the bucket. Set
   `ALIBABA_CLOUD_ROLE_ARN`, `ALIBABA_CLOUD_OIDC_PROVIDER_ARN`,
   `ALIBABA_CLOUD_OIDC_TOKEN_FILE` (the RRSA webhook does this), and
   `KEEL_ALIBABA_BILL_BUCKET`, `KEEL_ALIBABA_REGION`, `KEEL_ALIBABA_BILL_PREFIX`,
   `KEEL_ALIBABA_PAYER_ACCOUNT`.
3. Cloud Accounts are Alibaba account (UID) numbers.
4. Finality: 12:00 UTC+8 on the 6th (bill final on the 3rd/4th, amortized
   cost on the 6th).
5. Verify on the first real delivery: the FOCUS file name token and whether
   `ResourceTag` uses the `key:k value:v;` format.
