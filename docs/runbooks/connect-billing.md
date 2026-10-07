# Runbook: connect real billing data (Tencent first, AWS optional)

Everything in M1 is built and tested against fixtures. These steps connect it
to real money. Each needs someone with access to the payer / management account.

## Tencent Cloud (payer UIN 200045645249) — ticket #29

1. **Bill delivery.** In the payer account: Billing Center → Bill Storage →
   deliver **Standard bill (FOCUS)** daily to a COS bucket in the payer account
   (e.g. `keel-bills-<appid>`, prefix `focus/`). Ask for the 18-month backfill.
2. **Read-only role for Keel.** Create a CAM role Keel can assume (TKE pod
   identity or the CVM role of Keel's node) with:
   - `QcloudBillingReadOnlyAccess` (or `billing:DescribeBillSummaryByPayMode`,
     `billing:DescribeBudget`), plus `cos:GetObject`/`cos:GetBucket` on the bill bucket;
   - for budget mirroring (#39): `billing:CreateBudget`, `ModifyBudget`, `DeleteBudget`.
3. **Configure Keel.**
   ```
   KEEL_TENCENT_BILL_BUCKET=keel-bills-<appid>
   KEEL_TENCENT_BILL_PREFIX=focus/
   KEEL_TENCENT_PAYER_UIN=200045645249
   KEEL_TENCENT_REGION=ap-bangkok
   KEEL_TENCENT_BILL_MODE=per-day        # see step 4
   KEEL_TENCENT_BUDGETS=1                # optional: mirror Budgets
   ```
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
