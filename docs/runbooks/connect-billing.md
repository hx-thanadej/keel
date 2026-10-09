# Runbook: connect real billing data (Tencent first, AWS optional)

Everything in M1 is built and tested against fixtures. These steps connect it
to real money. Each needs someone with access to the payer / management account.

## Tencent Cloud (payer UIN 200045645249) — ticket #29

**Run the wizard:** `scripts/wizards/tencent-payer-billing.sh`, with `tccli`
signed in as the payer (`TCCLI_PROFILE=<name>` to pick a profile). It walks
steps 1–5 below, verifies each with `tccli` where it can, probes the
`*ForOrganization` question for #9, and keeps its answers in `.keel/`
(git-ignored), so a re-run resumes. It never asks for an access key.

Keel signs its Tencent calls with one keyless base identity
(`tencent.Credentials()`: TKE pod identity, else the CVM role). The wizard asks
for that base role's ARN and creates a separate billing role in the payer,
`KEEL_TENCENT_BILL_ROLE`, whose trust policy allows `sts:AssumeRole` from that
ARN alone. It needs no OIDC provider in the payer, and keel-api's
ServiceAccount or CVM role stays as it is. Keel's base role needs
`sts:AssumeRole` on the billing role; the wizard writes that policy to
`.keel/base-assume.json` for the account that owns the base role. Budget
mirroring still runs as the base identity, so its budget permissions go on the
base role (`.keel/base-budgets.json`), never on the billing role.

`bash scripts/wizards/test-tencent-payer-billing.sh` dry-runs the wizard
against a stubbed `tccli` in a temp `HOME`, fresh and resumed, and checks the
config it prints. Run it with `/bin/bash` and a current bash after changing
the wizard.

1. **Bill delivery.** In the payer account: Billing Center → Bill Overview →
   Bill Storage → deliver **Standard bill (FOCUS)** and **Cost Allocation Bill
   (FOCUS)** to a private COS bucket in the payer account (`keel-bills-<appid>`).
   Tick the 18-month historical sync.
2. **Read-only role for Keel.** A CAM role trusted only by Keel's identity
   (OIDC provider `TKE_PROVIDER_ID` with `oidc:aud`/`oidc:sub` for pod
   identity, or `cvm.qcloud.com`) with:
   - `QcloudFinanceBillReadOnlyAccess` (covers `finance:DescribeBill*`, which
     includes `DescribeBillSummaryByPayMode`), plus `cos:GetBucket`,
     `cos:HeadBucket`, `cos:GetObject`, `cos:HeadObject` on the bill bucket;
   - for budget mirroring (#39): `CreateBudget`, `ModifyBudget`, `DeleteBudget`,
     `DescribeBudget` (CAM namespace unverified; take it from the visual editor).
3. **Configure Keel.** `KEEL_TENCENT_BILL_PREFIX` must hold only Standard bill
   (FOCUS) files: Keel parses every bill file under it as FOCUS.
   ```
   KEEL_TENCENT_BILL_BUCKET=keel-bills-<appid>
   KEEL_TENCENT_BILL_PREFIX=<folder of the Standard bill (FOCUS) files>
   KEEL_TENCENT_PAYER_UIN=200045645249
   KEEL_TENCENT_BILL_ROLE=<role name>    # recommended: payer role for bill sync
   KEEL_TENCENT_REGION=ap-bangkok
   KEEL_TENCENT_BILL_MODE=per-day        # see step 4
   KEEL_TENCENT_BUDGETS=1                # optional: mirror Budgets
   ```

   `KEEL_TENCENT_BILL_ROLE` names a CAM role in the payer UIN
   (`KEEL_TENCENT_PAYER_UIN`). Give it `QcloudBillingReadOnlyAccess` (or
   `billing:DescribeBillSummaryByPayMode`) and `cos:GetObject`/`cos:GetBucket`
   on the bill bucket. The role must trust Keel's base identity, and the base
   identity needs `sts:AssumeRole` on it. Keel assumes it with STS AssumeRole,
   renews it before expiry, and uses it only for bill sync and invoice
   reconciliation. Budget mirroring (#39) still runs as the base identity, so
   `billing:DescribeBudget` and the `billing:*Budget` write permissions from
   step 2 stay on the base identity, not on the payer role. Unset, bill sync
   uses the base identity and Keel logs a warning at startup.

   Subscribe only **Standard bill (FOCUS)** to the prefix. Keel skips the
   *Cost Allocation Bill (FOCUS)* and other bill types it finds there, records
   a `keel.cost.bill_file_skipped` Activity per file, and never ingests them.

4. **Confirm the file mode on the first delivery.** Open two consecutive daily
   files. If day 2's file contains only day 2's lines → `per-day` (default).
   If it also contains day 1 → `cumulative`. A wrong mode double-counts or
   drops days; `GET /v1/tenants/{home}/cost-loads` shows the reconciliation
   against the invoice total, which will say `mismatch` if the mode is wrong.
5. **Check.** Within an hour: `GET …/cost-loads` lists loads with
   `reconcile_status: ok`; the Budgets tab shows spend for Projects whose
   Cloud Accounts are registered (`POST …/discoveries/tencent` then register
   the suggested accounts).

Until then, a FOCUS export downloaded from the console can be uploaded:
`POST /v1/tenants/{home}/cost-loads?provider=tencent&billing_account=200045645249&period=YYYY-MM`.

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
   `KEEL_AZURE_BILL_CONTAINER`, `KEEL_AZURE_BILL_PREFIX` and
   `KEEL_AZURE_BILLING_ACCOUNT`.
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
4. Set `KEEL_GCP_BILL_BUCKET`, `KEEL_GCP_BILL_PREFIX`, `KEEL_GCP_BILLING_ACCOUNT`.
   Cloud Accounts are GCP **project ids** (`SubAccountId`).
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
