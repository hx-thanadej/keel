# 04 — Multi-cloud billing data, budgets and rightsizing (AWS, GCP, Azure, Tencent, Alibaba, Kubernetes)

Status: research note, compiled 2026-10-06. Scope: provider data sources, budget APIs, native recommenders, Kubernetes rightsizing, OSS tools to integrate. FinOps Framework / FOCUS basics / OpenCost overview are covered in a sibling note and not repeated here.
Method: every claim is followed by the primary source it came from (provider docs, API references, project source). Anything not confirmed on a primary page is marked **UNVERIFIED**.

## TL;DR

- **All five providers can now emit FOCUS-shaped billing files**, but maturity differs: AWS FOCUS 1.2 GA (Nov 2025); Azure FOCUS 1.0 GA + 1.2-preview; GCP FOCUS export Preview (1.2); Tencent "Standard bill (FOCUS)" to COS; Alibaba FOCUS 1.0 invitational preview, "not for reconciliation". Ingest FOCUS where available, keep a native-schema adapter per provider for gaps (split K8s cost, credits detail).
- **Read billing from the payer.** AWS member exports only see the member; Tencent bills are "issued under the payer UIN" (member APIs return zero in admin-pays mode — documented, not a bug); Alibaba trusteeship consolidates under the main account. GCP is per billing account; Azure per EA/MCA billing scope.
- **Daily is the honest finest grain for cross-cloud.** AWS/GCP are hourly; Azure exports are daily; Tencent/Alibaba files are daily (Alibaba console has an hourly view, no hourly file). Finality: AWS on invoice (+ up to 2 weeks of edits), Azure ~72 h after month end (changes to day 5), Tencent 19:00 on the 1st, Alibaba 12:00 on the 3rd/4th (amortised on the 6th), GCP has no guarantee (`invoice.month` may roll over).
- **Budgets are native everywhere but enforcement is weak**: only AWS Budgets Actions (IAM/SCP/stop EC2+RDS) and GCP spend caps (Gemini/Vertex/Cloud Run only, Preview) enforce. Azure needs action group → Logic App/runbook. Alibaba has **no create-budget API** (read-only, whitelisted). Our platform must own budget objects and evaluate them itself, mirroring to native budgets where APIs exist.
- **Recommenders**: AWS Cost Optimization Hub (deduplicated, discount-aware, org-wide) is the best single feed; GCP Recommender (+ BigQuery export at org level); Azure Advisor (+ Resource Graph `AdvisorResources`) and `benefitRecommendations`; Tencent Smart Advisor (3 APIs, cost checks enumerated at runtime); Alibaba Advisor cost-check APIs. Native recommenders disagree on thresholds and lookbacks — normalise them into one record shape with confidence + risk + savings basis.
- **Kubernetes**: in-place pod resize is GA since v1.35; VPA 1.8 supports `InPlaceOrRecreate`. VPA = p90 CPU, p90 of daily memory peaks, +15 % margin, 24 h half-life. KRR = p95 CPU, max memory +15 %, 14 d. OpenCost does **allocation, not rightsizing** — we need a recommender (VPA-Off/KRR-style) plus Karpenter/CA for nodes.
- **OSS to integrate rather than build**: OpenCost (K8s allocation + AWS/Azure/GCP/OCI cloud costs), Cloud Custodian (AWS/GCP/Azure/K8s/**Tencent**; no Alibaba) for idle/orphan policies, Steampipe thrifty mods (incl. Alicloud), OptScale (incl. Alibaba). Avoid Komiser (ELv2, dormant) and Crane (dormant since 2023).

## Provider comparison

| | AWS | GCP | Azure | Tencent Cloud | Alibaba Cloud |
|---|---|---|---|---|---|
| Export mechanism | Data Exports (`bcm-data-exports`): CUR 2.0, FOCUS 1.0/1.2 → S3 (CSV/Parquet) | Cloud Billing export → BigQuery (standard, detailed, pricing, CUD, FOCUS) | Cost Mgmt Exports (actual, amortised, FocusCost, price sheet, reservations) → Storage (CSV/Parquet) | Bill Storage → COS (standard, cost-allocation, consumption, FOCUS) + `billing` API 2018-07-09 | `SubscribeBillToOSS` (BssOpenApi 2017-12-14) → OSS / MaxCompute; FOCUS 1.0 preview |
| Finest grain | Hourly, resource-level | Hourly, resource-level (detailed) | Daily, resource-level | Per record; daily/monthly files | Daily (API/file); hourly console view only |
| Refresh | ≥1×/day | "regular intervals, no guarantee" | data within 8–24 h; estimates 6×/day | L3 ~20–30 min; L0–L2 T+1; files D+1 | API 24 h lag; files D+1 by 18:00 UTC+8 |
| Final | On invoice; may change ≤2 wks | No guarantee; late usage rolls to next invoice | ~72 h after month end; changes to day 5 | 19:00 on 1st | 12:00 on 3rd/4th; amortised 6th |
| FOCUS | 1.2 GA, 1.0 | 1.2 Preview | 1.0 GA, 1.2-preview | Yes (Standard bill FOCUS) | 1.0 invitational preview |
| Amortised/net | Yes (`*_effective_cost`, `*_net_*`) | Credits array + `cost_at_effective_price_default` | AmortizedCost export | Consumption bill (prepaid spread daily) | `Describe*AmortizedCost*` APIs |
| Budgets API | `budgets:CreateBudget` + Actions | `billingbudgets` v1 + Pub/Sub, spend caps | `Microsoft.CostManagement/budgets` 2026-06-01 | `CreateBudget` etc. | Read-only `DescribeCostBudgetsSummary` (beta) |
| Recommender API | Compute Optimizer, Cost Optimization Hub, TA (paid support) | `recommender.googleapis.com` v1 + BQ export | Advisor `Microsoft.Advisor/recommendations` 2025-01-01, ARG | Smart Advisor `advisor` 2020-07-21 | Advisor 2018-01-20 (`DescribeCostCheckResults`…) |
| Payer-only? | Mgmt account for all members; member sees self | Billing-account scoped | EA/MCA billing scope for all subs | Yes in admin-pays (代付) mode | Yes under trusteeship |

## 1. AWS

**Billing export.**
- Data Exports offers CUR 2.0, FOCUS 1.2 with AWS columns, FOCUS 1.0, Cost Optimization Recommendations, Carbon, Cost and Usage Dashboard. https://docs.aws.amazon.com/cur/latest/userguide/what-is-data-exports.html
- CUR 2.0 (`COST_AND_USAGE_REPORT`, 125-column fixed schema): `TIME_GRANULARITY` HOURLY/DAILY/MONTHLY, `INCLUDE_RESOURCES` (adds `line_item_resource_id`), `INCLUDE_SPLIT_COST_ALLOCATION_DATA`, capacity-reservation data (from 2025-11-01). https://docs.aws.amazon.com/cur/latest/userguide/table-dictionary-cur2.html
- FOCUS 1.2 table `FOCUS_1_2_AWS` = 57 FOCUS columns + `x_Discounts`, `x_Operation`, `x_ServiceCode`; GA Nov 2025. https://docs.aws.amazon.com/cur/latest/userguide/table-dictionary-focus-1-2-aws.html , https://aws.amazon.com/about-aws/whats-new/2025/11/aws-data-exports-focus-1-2-available/
- Split cost allocation (EKS/ECS) is in CUR 2.0 but "not currently available in FOCUS 1.2". https://aws.amazon.com/aws-cost-management/aws-data-exports/faqs/ — EKS split adds 2 rows per pod per hour (3 with accelerators) and `aws:eks:namespace|workload-name|…` tags; allocation by requests, AMP, or Container Insights. https://docs.aws.amazon.com/cur/latest/userguide/split-cost-allocation-data.html , https://docs.aws.amazon.com/cur/latest/userguide/enabling-split-cost-allocation-data.html
- Account scope: a management-account export covers all members; a member export covers only that member and only for its time in the org. https://docs.aws.amazon.com/cur/latest/userguide/table-dictionary-cur2.html
- Refresh "at least once a day"; prior period may be updated "within the first two weeks"; Parquet + `Manifest.json`; Athena/Redshift helper artefacts. https://docs.aws.amazon.com/cur/latest/userguide/dataexports-export-delivery.html — a line is final when `bill/InvoiceId` is populated. https://docs.aws.amazon.com/cur/latest/userguide/view-finalized-cur.html
- Amortised: `reservation_effective_cost`, `savings_plan_savings_plan_effective_cost`; `*_net_*` columns appear only when a discount exists. https://docs.aws.amazon.com/cur/latest/userguide/table-dictionary-cur2-reservation.html , https://docs.aws.amazon.com/cur/latest/userguide/table-dictionary-cur2-savings-plan.html
- Quotas: 5 CUR 2.0 exports, 2 FOCUS 1.2. https://docs.aws.amazon.com/cur/latest/userguide/dataexports-quotas.html — backfill up to 14 months via support case (blog). https://aws.amazon.com/blogs/aws-cloud-financial-management/how-and-why-you-should-move-to-cost-and-usage-report-cur-2-0/
- Cost Explorer API: `GetCostAndUsage` (HOURLY/DAILY/MONTHLY; Amortized/NetAmortized/NetUnblended/Unblended…, ≤2 GroupBy) at $0.01/request; 13 months + current (38 months with multi-year, 14 days hourly/resource-level, enabled from mgmt account). https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostAndUsage.html , https://docs.aws.amazon.com/cost-management/latest/userguide/ce-what-is.html , https://docs.aws.amazon.com/cost-management/latest/userguide/ce-configuring-data.html

**Budgets.**
- Types: cost, usage, RI/SP utilisation & coverage; updated up to 3×/day; can track unblended/amortised/net amortised. https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html
- Alerts on actual or **forecasted**, absolute or %; SNS, ≤10 emails, Chatbot/Q Developer. Periods daily→annual/custom. https://docs.aws.amazon.com/cost-management/latest/userguide/create-cost-budget.html
- Filters incl. linked account, tag (activated, `user:` prefix), cost category, service, region. https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-create-filters.html
- Methods: fixed, planned, **auto-adjusting** (historical/forecast baseline). https://docs.aws.amazon.com/cost-management/latest/userguide/budget-methods.html
- `CreateBudget`: ≤5 notifications per budget, 1 SNS + 10 emails each; `FilterExpression`, `BillingViewArn`. https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_budgets_CreateBudget.html
- **Budgets Actions** enforce: attach IAM policy, SCP (mgmt only), stop EC2/RDS (same account); auto or approval. https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-action-configure.html — 2 free action budgets then $0.10/day; 20,000 budgets per mgmt account. https://aws.amazon.com/aws-cost-management/aws-budgets/pricing/ , https://docs.aws.amazon.com/cost-management/latest/userguide/management-limits.html
- Budgets are visible only in the creating account. https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html
- Cost Anomaly Detection: ML, ~3×/day on net unblended, ≤24 h detection, monitors by service/account/tag/cost category. https://docs.aws.amazon.com/cost-management/latest/userguide/manage-ad.html , https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html

**Recommenders.**
- Compute Optimizer covers EC2, ASG, EBS, Lambda, ECS-on-Fargate, RDS/Aurora, SQL Server licences, NAT Gateway, DynamoDB, ElastiCache, MemoryDB, DocumentDB, WorkSpaces, SageMaker; 14-day default lookback, 93 days with paid enhanced metrics (~$0.25/resource-month). https://docs.aws.amazon.com/compute-optimizer/latest/ug/what-is-compute-optimizer.html , https://aws.amazon.com/compute-optimizer/pricing/
- Rightsizing preferences (EC2): CPU threshold P90/P95/**P99.5 default**; CPU headroom 0/20/30 % (20 default); memory headroom 10/20/30 %; lookback 14/32/93; preferred families; Graviton (`aws-arm64`) preference. Presets: Max savings P90/0/10, Balanced P95/30/30, Default P99.5/20/20. https://docs.aws.amazon.com/compute-optimizer/latest/ug/rightsizing-preferences.html
- Memory needs CloudWatch agent (or Datadog/Dynatrace ingestion). Findings Under/Over-provisioned/Optimized with per-dimension reasons; performance risk 0–4; migration effort Very low→High. https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-ec2-recommendations.html
- Data minimums: EC2 ≥30 h metrics in 14 d; Lambda ≥50 invocations. https://docs.aws.amazon.com/compute-optimizer/latest/ug/requirements.html — Idle: EC2 peak CPU <5 % and net <5 MB/day over 14 d; EBS <1 IO/day or unattached 32 d. https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-idle-recommendations.html
- Savings estimation mode `AfterDiscounts` (SP/RI-aware), requires Cost Optimization Hub. https://docs.aws.amazon.com/compute-optimizer/latest/ug/savings-estimation-mode.html — org-wide opt-in from mgmt/delegated admin. https://docs.aws.amazon.com/compute-optimizer/latest/ug/account-opt-in.html
- APIs: `Get*/Export*Recommendations` (EC2, ASG, EBS, ECS, Lambda, License, RDS, Idle), `PutRecommendationPreferences`; new **Automation** (`CreateAutomationRule`, rollback). https://docs.aws.amazon.com/compute-optimizer/latest/APIReference/API_Operations.html , https://docs.aws.amazon.com/compute-optimizer/latest/ug/automation.html
- **Cost Optimization Hub**: rightsizing + idle + SP/RI recs across org, using your pricing; dedups to the highest-saving action per resource. APIs `ListRecommendations`, `GetRecommendation`, `ListRecommendationSummaries`. https://docs.aws.amazon.com/cost-management/latest/userguide/cost-optimization-hub.html , https://docs.aws.amazon.com/cost-management/latest/userguide/coh-savings-opportunities.html , https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_Operations_Cost_Optimization_Hub.html . Data Exports can also deliver "Cost Optimization Recommendations" to S3 (above).
- Trusted Advisor cost checks (low-util EC2 ≤10 % CPU 4 of 14 days, idle LB, unassociated EIP, underused EBS, idle RDS); API needs Business Support+/Enterprise/Unified Ops. https://docs.aws.amazon.com/awssupport/latest/user/cost-optimization-checks.html , https://docs.aws.amazon.com/awssupport/latest/user/get-started-with-aws-trusted-advisor-api.html
- Cost Explorer `GetRightsizingRecommendation` is a subset; AWS recommends COH instead. SP/RI purchase recs: lookback 7/30/60 d. https://docs.aws.amazon.com/cost-management/latest/userguide/understanding-rr-calc.html , https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetSavingsPlansPurchaseRecommendation.html

**Tags.** Activated only in mgmt account; up to 24 h to appear + 24 h to activate; backfill activation up to 12 months; 500 active keys. https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/activating-tags.html , https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-allocation-backfill.html , https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/billing-limits.html — Cost categories (rules on account/tag/service, split charges, 12-month retro) flow into CUR, Budgets, Anomaly. https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/manage-cost-categories.html

## 2. Google Cloud

**Billing export.**
- Five export types: standard, detailed (resource-level), pricing (GA); CUD metadata, FOCUS (Preview). https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery — FOCUS supports 1.2 in Preview (2026-06-08), immutable dataset, documented conformance gaps (e.g. ServiceCategory, ResourceType missing). https://docs.cloud.google.com/billing/docs/release-notes , https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables/focus-export
- Loads "at regular intervals (there are no delivery or latency guarantees)"; backfill up to 5 days; services report on own schedules. https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables
- Backfill from previous month only for US/EU multi-region datasets; regional = from enable date. Needs Billing Account Costs Manager/Admin. Covers all projects on the billing account. https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-setup
- Hourly `usage_start_time`; `cost_type` regular/tax/adjustment/rounding; `credits[]` types incl. CUD, SUD, PROMOTION, FREE_TIER, DISCOUNT; `invoice.month` may differ from usage month; `cost_at_effective_price_default` (from 2025-07-15). https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables/standard-usage
- Detailed export adds `resource.name/global_name` and system labels (`compute.googleapis.com/machine_spec`, cores, memory). https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables/detailed-usage
- Cloud Billing API v1 has **no cost query**; BigQuery is the only programmatic cost source. https://docs.cloud.google.com/billing/docs/reference/rest

**Budgets** (`billingbudgets.googleapis.com` v1).
- Scope: billing account, projects/folders/orgs, services, **one label** only, credit treatment (include/exclude/specified). https://docs.cloud.google.com/billing/docs/how-to/budgets , https://docs.cloud.google.com/billing/docs/reference/budget/rest/v1/billingAccounts.budgets
- `thresholdRules.spendBasis` CURRENT_SPEND or FORECASTED_SPEND (calendar periods only); MONTH/QUARTER/YEAR/custom; `lastPeriodAmount`; 50,000 budgets per billing account. Same URLs.
- Pub/Sub notifications "multiple times per day", at-least-once, unordered; disable-billing pattern documented with large caveats. https://docs.cloud.google.com/billing/docs/how-to/budgets-programmatic-notifications , https://docs.cloud.google.com/billing/docs/how-to/disable-billing-with-notifications
- **Spend caps** (Preview): pause usage for Gemini API, Vertex/Agent Platform, Cloud Run only; monthly. https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps
- Cost anomaly detection GA 2025-10-30. https://docs.cloud.google.com/billing/docs/release-notes

**Recommenders** (`recommender.googleapis.com` v1).
- IDs: `google.compute.instance.MachineTypeRecommender`, `...instanceGroupManager.MachineTypeRecommender`, idle VM/disk/address/image `IdleResourceRecommender`s, `google.compute.commitment.UsageCommitmentRecommender`, `google.cloudbilling.commitment.SpendBasedCommitmentRecommender`, `google.cloudsql.instance.IdleRecommender|OverprovisionedRecommender`, `google.container.DiagnosisRecommender` (idle GKE cluster), `google.run.service.CostRecommender`. https://docs.cloud.google.com/recommender/docs/recommenders
- Machine type: last **8 days**, 60 s averages, no rec if saving < $10/mo, excludes GKE nodes/GPU. https://docs.cloud.google.com/compute/docs/instances/apply-machine-type-recommendations-for-instances
- Idle VM: 1–14 day window (default 14). Idle disk/IP/image: 15 days. CUD: 30 days. Cloud SQL: 30 days. https://docs.cloud.google.com/compute/docs/instances/idle-vm-recommendations-overview , https://docs.cloud.google.com/compute/docs/disks/viewing-and-applying-idle-pd-recommendations , https://docs.cloud.google.com/docs/cuds-recommender , https://docs.cloud.google.com/sql/docs/mysql/recommender-sql-overprovisioned
- GKE workload insights: over-provisioned if <50 % for 90 % of 15 days; under if >150 % for 10 %. https://docs.cloud.google.com/kubernetes-engine/docs/how-to/optimize-workload-resource-utilization
- Recommendation fields: `primaryImpact.costProjection`, `priority` P1–P4, `stateInfo` (ACTIVE/CLAIMED/SUCCEEDED/FAILED/DISMISSED), `etag`, `xorGroupId`; methods `markClaimed/Succeeded/Failed/Dismissed`. https://docs.cloud.google.com/recommender/docs/reference/rest/v1/projects.locations.recommenders.recommendations
- **BigQuery export** of all recommendations/insights at org level via Data Transfer Service (daily). https://docs.cloud.google.com/recommender/docs/bq-export/export-recommendations-to-bq

**Labels.** `labels`, `project.labels`, `system_labels`, `tags[]` (inherited from org/folder/project) in export; not retroactive. https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables/standard-usage — GKE cost allocation labels (`k8s-namespace`, `k8s-workload-*`) detailed export only, request-based, no backfill. https://docs.cloud.google.com/kubernetes-engine/docs/how-to/cost-allocations

## 3. Azure

**Billing export.**
- Exports: actual, amortised, **FocusCost**, price sheet, reservation details/recs/transactions; Exports API latest `2026-06-01`; CSV(gzip)/Parquet(snappy); partitioned <1 GB files + `manifest.json`. https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-improved-exports , https://learn.microsoft.com/en-us/rest/api/cost-management/exports/create-or-update
- Daily month-to-date schedule; for days 1–5 a hidden re-run refreshes prior month. Scopes: EA enrollment/department/account, MCA billing account/profile/invoice section, subscription, RG; mgmt-group exports EA-only, actual only, no FOCUS; PAYG has no FOCUS. Same tutorial URL.
- FOCUS schema versions: 1.2-preview, 1.0r2, 1.0. https://learn.microsoft.com/en-us/azure/cost-management-billing/dataset-schema/cost-usage-details-focus
- Latency 8–24 h (EA/MCA), up to 72 h PAYG; month closes ~72 h after period, charges may change to day 5; open-month estimates exclude credits. https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/understand-cost-mgt-data
- Cost Details API (`generateCostDetailsReport`, async, 1 month/report, <2 GB/month) for small scopes; Query API throttled 12 QPU/10 s, 60/min, 600/h. https://learn.microsoft.com/en-us/azure/cost-management-billing/automate/get-small-usage-datasets-on-demand , https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/manage-automation
- Consumption Usage Details API "planned for deprecation". https://learn.microsoft.com/en-us/azure/cost-management-billing/automate/migrate-consumption-usage-details-api

**Budgets.**
- Scopes: mgmt group, subscription, RG, EA/MCA billing scopes; evaluated every 24 h; budgets track **actual not amortised**; ≤5 thresholds; do not stop resources. https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets
- `Microsoft.CostManagement/budgets` 2026-06-01: 5 Actual + 5 **Forecasted** notifications; tag and dimension filters. https://learn.microsoft.com/en-us/rest/api/cost-management/budgets/create-or-update
- Action groups only at subscription/RG scope → Logic App → runbook stops VMs (documented pattern). https://learn.microsoft.com/en-us/rest/api/consumption/budgets/create-or-update , https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/cost-management-budget-scenario
- Anomaly alerts: daily, WaveNet model on 60 days, subscription scope only. https://learn.microsoft.com/en-us/azure/cost-management-billing/understand/analyze-unexpected-charges

**Recommenders.**
- Advisor VM shutdown: P95 max CPU <3 %, P100 avg CPU ≤2 % last 3 d, outbound net <2 % over 7 d (no memory). Resize: target P95 CPU ≤40 %, P99 memory ≤60 % (user-facing) / 80 % (non-user-facing); B-series rule; lookback 7/14/21/30/60/90 d (default 7); savings at **retail, ignoring RI/SP**. https://learn.microsoft.com/en-us/azure/advisor/advisor-cost-recommendations
- Advisor config API `lowCpuThreshold` 5/10/15/20. https://learn.microsoft.com/en-us/rest/api/advisor/configurations/create-in-subscription — list: `Microsoft.Advisor/recommendations?api-version=2025-01-01&$filter=Category eq 'Cost'`, `extendedProperties.savingsAmount`. https://learn.microsoft.com/en-us/rest/api/advisor/recommendations/list — cross-subscription via Resource Graph `AdvisorResources`. https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/samples-by-category
- Commitments: `Microsoft.CostManagement/benefitRecommendations` (Last7/30/60Days, P1Y/P3Y, Single/Shared/MG). https://learn.microsoft.com/en-us/rest/api/cost-management/benefit-recommendations/list
- AKS cost analysis add-on is OpenCost-based (Standard/Premium tier). https://learn.microsoft.com/en-us/azure/aks/cost-analysis

**Tags.** Not retroactive; RG tags excluded unless **tag inheritance** is on (writes tags onto usage records, current month only). https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/enable-tag-inheritance — cost allocation rules (EA/MCA) move/split cost by sub/RG/tag. https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/allocate-costs

## 4. Tencent Cloud

**Billing data** (`billing.tencentcloudapi.com`, version 2018-07-09; intl `billing.intl.tencentcloudapi.com`). Catalogue with rate limits: https://cloud.tencent.com/document/api/555/19170
- `DescribeBillDetail`: 5 req/s, `Limit` ≤300, single month per call, 18 months history, `PayerUin` lets an admin read a member's **self-paid** bills; >200k rows/month → use COS storage. https://www.tencentcloud.com/document/product/555/30756
- `DescribeBillResourceSummary` (monthly per resource, `Limit` ≤1000, Tags, ProjectName). https://cloud.tencent.com/document/api/555/19181 — `DescribeBillSummary` `GroupType`=business/project/region/payMode/tag, 20 req/s. https://cloud.tencent.com/document/api/555/93162
- Bill vs consumption: the "bill" is the reconciliation basis (prepaid booked in full); the "consumption" bill amortises prepaid daily. https://cloud.tencent.com/document/product/555/37321 — `DescribeCostDetail` (5 req/s, `Limit` ≤100) and `DescribeCostExplorerSummary` (day/month, BillType bill|consumption, dimensions incl. tag/project). https://cloud.tencent.com/document/product/555/41010 , https://cloud.tencent.com/document/product/555/103991
- Latency: L0–L2 T+1; L3 detail ~20–30 min behind deduction; previous month final 19:00 on the 1st. https://cloud.tencent.com/document/product/555/96169 , https://cloud.tencent.com/document/faq/555/7465
- **Bill Storage → COS**: standard, cost-allocation, consumption and **Standard bill (FOCUS)** / **Cost Allocation bill (FOCUS)**, daily (D+1, 03:00–22:00) and monthly (2nd/4th); 18-month one-off backfill; admin can store members' files. https://www.tencentcloud.com/document/product/555/43521 , https://cloud.tencent.com/document/product/555/61275 . No hourly file documented (UNVERIFIED that none exists).
- **Payer-only behaviour (documented)**: "账单按照支付者 UIN 归集出账" — bills are issued under the payer UIN; in admin-pays (代付) mode members see their bills only under Organization > Finance, not via Billing Center APIs. https://cloud.tencent.com/document/faq/555/7465 , https://cloud.tencent.com/document/product/850/67267 . Org APIs: `DescribeBillDetailForOrganization`, `DescribeBillSummaryForOrganization`, `DescribeBillResourceSummaryForOrganization`. https://cloud.tencent.com/document/api/555/98858 — China docs describe these as *member* fetching admin-paid bills; intl wording differs (treat direction as needing a live test).

**Budgets.** Full API: `CreateBudget`, `ModifyBudget`, `DeleteBudget`, `DescribeBudget`, `DescribeBudgetRemindRecordList` (20 req/s). `CycleType` DAY/MONTH/QUARTER/YEAR, `BillType` BILL/CONSUMPTION, scope by product, region, `ProjectIds`, `Tags`, `PayerUins`/`OwnerUins`, allocation units. https://cloud.tencent.com/document/api/555/123661 — ≤3 threshold + 3 fluctuation alerts; email/SMS/WeCom. https://intl.cloud.tencent.com/zh/document/product/555/44232 — forecast alerts exist (not on daily budgets). https://cloud.tencent.com/document/product/555/65784 . No enforcement action documented.

**Recommenders.** Smart Advisor `advisor.tencentcloudapi.com` 2020-07-21: only `DescribeStrategies`, `DescribeTaskStrategyRisks` (`Limit` ≤200, `Risks` JSON string), `CreateAdvisorAuthorization`. https://cloud.tencent.com/document/api/1264/63122 , https://intl.cloud.tencent.com/document/api/1079/63103 — cost pillar among 440+ strategies, free. https://cloud.tencent.com/product/advisor . Specific cost checks/thresholds: **UNVERIFIED** (enumerate via `DescribeStrategies`). No Tencent rightsizing API for CVM sizes. TKE Cost Insights offers request recommendations (estimates, not bills). https://cloud.tencent.com/document/product/457/64169

**Tags.** ≤15 cost allocation tags (`CreateAllocationTag`), effective next day, apply to whole current month, retro backfill up to 12 months for standard bills; in orgs the admin designates allocation keys. Projects are a first-class billing dimension. https://cloud.tencent.com/document/product/555/37959

## 5. Alibaba Cloud

**Billing data** (BssOpenApi 2017-12-14). Catalogue: https://www.alibabacloud.com/help/en/user-center/developer-reference/api-bssopenapi-2017-12-14-overview
- `DescribeInstanceBill`: MONTHLY/DAILY, `MaxResults` ≤300, `NextToken`, 10 QPS, 18 months, 24 h data lag, `BillOwnerId`, fields `PretaxGrossAmount`, `InvoiceDiscount`, `DeductedByCoupons`, `PretaxAmount`, `Tag`, `CostUnit`, `ResourceGroup`. https://www.alibabacloud.com/help/en/user-center/developer-reference/api-bssopenapi-2017-12-14-describeinstancebill
- `QueryAccountBill` (per owner), `DescribeSplitItemBill` (12 months, 48–72 h lag). https://www.alibabacloud.com/help/en/user-center/developer-reference/api-bssopenapi-2017-12-14-queryaccountbill , https://www.alibabacloud.com/help/en/user-center/developer-reference/api-bssopenapi-2017-12-14-describesplititembill
- Amortised: `DescribeInstanceAmortizedCostByAmortizationPeriod` (final after 12:00 on the 6th, "cannot be used for settlement"). https://www.alibabacloud.com/help/en/user-center/developer-reference/api-bssopenapi-2017-12-14-describeinstanceamortizedcostbyamortizationperiod
- Console: PAYG lag 1–3 h (split products ≤72 h); By Hour view exists; monthly final after 12:00 on the 4th. https://www.alibabacloud.com/help/en/user-center/bill-view , https://www.alibabacloud.com/help/en/user-center/bill-details-2
- `SubscribeBillToOSS` types `BillingItemDetailForBillingPeriod`, `InstanceDetailForBillingPeriod`, `*Monthly`, `SplitItemDetailDaily`; `MultAccountRelSubscribe=MA`; role `AliyunConsumeDump2OSSRole`. https://www.alibabacloud.com/help/en/user-center/developer-reference/api-bssopenapi-2017-12-14-subscribebilltooss
- FOCUS 1.0: **invitational preview**, CSV to OSS, "analysis only… cannot be used for reconciliation". https://www.alibabacloud.com/help/en/user-center/exporting-alibaba-cloud-focus1-0-preview
- Multi-account: **trusteeship** consolidates all orders/bills under the main account (filter by owner); finance-management members settle themselves. https://www.alibabacloud.com/help/en/user-center/trusteeship , https://help.aliyun.com/zh/caf/multi-account-enterprise-payment-management-solution . That `BillOwnerId` works for every relationship type: UNVERIFIED.

**Budgets.** Console cost budgets (by cost centre, account, region, product), monthly/quarterly/annual, ≤5 alert groups, actual or **forecast** alerts, data T+2, email/internal message only. https://www.alibabacloud.com/help/en/user-center/budget-management — API: only read-only `DescribeCostBudgetsSummary`, beta, whitelisted. https://www.alibabacloud.com/help/en/user-center/developer-reference/api-bssopenapi-2017-12-14-describecostbudgetssummary . Cost Centres (`CreateCostUnit`, `AllocateCostUnitResource`) allocate by account/tag/RG. https://www.alibabacloud.com/help/en/user-center/cost-center-1

**Recommenders.** Advisor API 2018-01-20: `DescribeAdvices`, `DescribeAdvisorChecks`, `RefreshAdvisorCheck`, plus cost APIs `DescribeCostCheckResults`, `DescribeCostCheckAdvices`, `RefreshAdvisorCostCheck`, `DescribeCostOptimizationOverview`. https://help.aliyun.com/zh/document_detail/3064352.html — cost scan covers idle ECS, low-util ECS, idle SLB, unattached disks, idle EIP with user-defined window/thresholds; manual scan, current account only. https://help.aliyun.com/zh/document_detail/2693292.html . ECS spec-recommendation API: UNVERIFIED (not found). ACK resource profiling: CPU P95 / memory P99 + margin over 14 d, as `Recommendation` CRDs (ACK Pro). https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/resource-profiling

**Tags.** ≤100 cost allocation tag keys, effective T+1, **not retroactive**, no enable API documented. https://www.alibabacloud.com/help/en/user-center/cost-label

## 6. Kubernetes rightsizing

- **VPA recommender** defaults (`config.go`): CPU target p90; memory target p90 of per-interval **peaks**; lower p50 / upper p95; +15 % margin; min 25 m CPU / 250 MiB per pod; 1 m loop. https://github.com/kubernetes/autoscaler/blob/master/vertical-pod-autoscaler/pkg/recommender/config/config.go
- Decaying histograms, half-life 24 h; memory peaks over 8 × 24 h intervals; buckets grow 5 %; OOM bump ×1.2 (≥100 Mi). https://github.com/kubernetes/autoscaler/blob/master/vertical-pod-autoscaler/pkg/recommender/model/aggregations_config.go
- Confidence: `base·(1+m/conf)^e` with conf = min(history days, samples/1440); upper bound ×2 at 24 h, ×1.14 at 1 week. https://github.com/kubernetes/autoscaler/blob/master/vertical-pod-autoscaler/pkg/recommender/logic/estimator.go , https://github.com/kubernetes/autoscaler/blob/master/vertical-pod-autoscaler/pkg/recommender/logic/recommender.go
- Prometheus history provider (`--storage=prometheus`, 8 d, 1 h resolution). Modes Off/Initial/Recreate/**InPlaceOrRecreate** (default-on from VPA 1.5)/InPlace (alpha)/Auto (deprecated). Latest VPA 1.8.0 (2026-09-23). https://github.com/kubernetes/autoscaler/blob/master/vertical-pod-autoscaler/docs/features.md , https://github.com/kubernetes/autoscaler/releases/tag/vertical-pod-autoscaler-1.8.0
- **In-place resize (KEP-1287)**: alpha 1.27, beta 1.33, **GA 1.35**; `--subresource=resize`, `resizePolicy` NotRequired/RestartContainer, cannot change QoS class. https://kubernetes.io/blog/2025/12/19/kubernetes-v1-35-in-place-pod-resize-ga/ , https://kubernetes.io/docs/tasks/configure-pod-container/resize-container-resources/ — 1.37 adds alpha preemption for resize. https://kubernetes.io/blog/2026/09/10/kubernetes-v1-37-scheduler-preemption-for-in-place-pod-resize-alpha/
- **Goldilocks**: one VPA per workload in Off mode + dashboard; v4.16.2 (2026-09). https://github.com/FairwindsOps/goldilocks
- **Robusta KRR** `simple`: CPU request p95, no CPU limit, memory max +15 %, ≥100 points, history 336 h (14 d) in code (README says a week). https://github.com/robusta-dev/krr/blob/main/robusta_krr/strategies/simple.py , https://github.com/robusta-dev/krr/blob/main/robusta_krr/core/abstract/strategies.py
- **Kubecost** `requestSizingV2`: target util 0.7, `max` or `quantile` algorithms. https://github.com/kubecost/docs/blob/v1.x/apis/apis-overview/api-request-right-sizing-v2.md . **OpenCost has no request rightsizing** (absence inferred from source). https://github.com/opencost/opencost
- **Karpenter**: `consolidationPolicy` WhenEmpty / WhenEmptyOrUnderutilized (default) / Balanced; `consolidateAfter` 0s default; disruption budget default 10 %; spot-to-spot behind gate (≥15 candidate types). https://github.com/kubernetes-sigs/karpenter/blob/main/pkg/apis/v1/nodepool.go , https://karpenter.sh/docs/concepts/disruption/
- **Cluster Autoscaler**: scale-down-utilization-threshold 0.5 (of requests), unneeded-time 10 m. https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/FAQ.md

## 7. Rightsizing methodology (authoritative)

- AWS WA **COST06-BP03**: target resources whose max CPU and memory are <40 % over four weeks. https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_type_size_number_resources_metrics.html
- AWS rightsizing whitepaper (historical): observe ≥2 weeks, ideally a month; vCPU, memory, network, disk; switch only if observed peak <80 % of new size; avoid older generations; apply a minimum-savings threshold. https://docs.aws.amazon.com/whitepapers/latest/cost-optimization-right-sizing/identifying-opportunities-to-right-size.html
- Percentile + headroom pairs used by providers: AWS P99.5+20 % (default) / P95+30 % (balanced); Azure P95 CPU ≤40 %, P99 mem ≤60 %; VPA p90 + 15 %; KRR p95 CPU / max mem +15 %; ACK P95 CPU / P99 mem. (sources above)
- Lookbacks in the wild: GCP 8 d, VPA 8 d, AWS 14/32/93 d, KRR 14 d, GKE workloads 15 d, Azure 7–90 d, CUD/SP 30–60 d. Short windows miss monthly peaks (GCP explicitly warns). https://docs.cloud.google.com/compute/docs/instances/apply-machine-type-recommendations-for-instances
- Burstable: Azure B-series rule (avg CPU < baseline, P95 < 2× baseline, credits cover 7-day average). https://learn.microsoft.com/en-us/azure/advisor/advisor-cost-recommendations
- ARM migration: AWS Graviton preference + migration-effort scale. https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-ec2-recommendations.html . Azure Cobalt / GCP Axion guidance: UNVERIFIED (not found on primary pages).
- Risk/confidence expression: AWS performance risk 0–4 + migration effort; GCP priority P1–P4 + `xorGroupId`; Azure impact H/M/L; VPA confidence-scaled bounds.
- Savings basis matters: Azure Advisor uses retail and ignores RI/SP; AWS `AfterDiscounts`; COH dedups overlapping actions. Always store the basis.

## 8. OSS / commercial tools to integrate

| Tool | Covers | Use for | Status |
|---|---|---|---|
| OpenCost | K8s allocation (pricing: AWS, GCP, Azure, Alibaba, OCI, …); Cloud Costs ingest AWS/Azure/GCP/OCI; MCP server | K8s cost per namespace/workload | Apache-2.0, v1.121.3 (2026-09) https://www.opencost.io/docs/configuration/ , https://github.com/opencost/opencost |
| Cloud Custodian | aws, azure, gcp, k8s, oci, **tencentcloud**; no Alibaba | idle/orphan policies (`mark-for-op`, `offhours`, `unused`, `metrics`) | Apache-2.0, 0.9.53 (2026-10) https://github.com/cloud-custodian/cloud-custodian/tree/main/tools , https://cloudcustodian.io/docs/aws/examples/ebsgarbagecollect.html |
| Infracost | AWS/Azure/GCP only; Terraform/CFN/CDK | shift-left cost in PRs | Apache-2.0 CLI https://github.com/infracost/infracost |
| Steampipe + thrifty mods | aws, gcp, azure, **alicloud**, oci; no Tencent | SQL-based waste checks | AGPL-3.0 https://github.com/turbot/steampipe-mod-aws-thrifty , https://github.com/turbot/steampipe-plugin-alicloud |
| OptScale | AWS, Azure, GCP, **Alibaba**, K8s | reference / possible embedded engine | Apache-2.0, active https://github.com/hystax/optscale |
| KRR / Goldilocks | K8s requests | recommendation engine for workloads | MIT / Apache-2.0 (above) |
| CloudQuery | asset inventory ELT | inventory for orphan detection | MPL-2.0 https://github.com/cloudquery/cloudquery |
| Komiser | incl. Tencent | **avoid**: ELv2, last release 2024-12 | https://github.com/mlabouardy/komiser |
| Crane (gocrane) | K8s recs (VPA-style p99) | **avoid**: last release 2023-07 | https://github.com/gocrane/crane |

Commercial (UNVERIFIED, not checked): Vantage, CloudHealth, Apptio Cloudability, IBM Kubecost 3.x, CAST AI.

## 9. Forecasting

- AWS `GetCostForecast`: DAILY (3 months) or MONTHLY (18 months), `PredictionIntervalLevel` 51–99 (80 default), returns mean + bounds; no forecast with < 1 billing cycle. https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostForecast.html , https://docs.aws.amazon.com/cost-management/latest/userguide/ce-forecast.html . Model type not documented ("ML" UNVERIFIED).
- Azure: "time series linear regression", ≤1 year; lookback 28 d for ≤28 d horizons, capped at 90 d; Forecast API `Microsoft.CostManagement/forecast`; no confidence bands documented. https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/quick-acm-cost-analysis , https://learn.microsoft.com/en-us/rest/api/cost-management/forecast/usage
- GCP: ML model on all history, daily/weekly/monthly seasonality, ≤12 months; console only, no API. https://docs.cloud.google.com/billing/docs/how-to/reports/forecasted-costs
- Tencent: forecast alerts in budgets (ML-predicted). https://cloud.tencent.com/document/product/555/65784 — Alibaba: budget forecast for current cycle. https://www.alibabacloud.com/help/en/user-center/budget-management
- Self-hosted option with primary doc: BigQuery ML `ARIMA_PLUS` / `ARIMA_PLUS_XREG`. https://docs.cloud.google.com/bigquery/docs/arima-plus-xreg-single-time-series-forecasting-tutorial . Prophet/ETS as common choices: UNVERIFIED.

## 10. Implications for our platform

Requirements, ordered by value:

1. **Payer-account connectors first.** One read-only connector per payer/billing scope: AWS mgmt account (Data Exports CUR 2.0 hourly + resources + split cost, and FOCUS 1.2), GCP billing account (detailed + FOCUS export, US/EU multi-region dataset for backfill), Azure EA/MCA billing scope (FocusCost + amortised daily Parquet), Tencent payer UIN (COS Standard bill FOCUS + cost-allocation daily; API fallback), Alibaba main account (OSS `InstanceDetailForBillingPeriod` + `SplitItemDetailDaily`; FOCUS preview if enrolled). Member-account credentials are for inventory/metrics only. Detect and warn when a connector is a member account that returns zero spend.
2. **Normalise to FOCUS-based fact table** with provider extensions, daily grain canonical, hourly retained where present; store both billed and amortised (`EffectiveCost`) and list cost; idempotent re-ingest per (provider, billing period) until finality — then freeze, with a per-provider finality rule (table above).
3. **Project/Environment mapping layer** independent of provider tags: resolve `project` and `environment` from (a) tag/label keys (`project`, `env`), (b) account/subscription/GCP project/Tencent project/Alibaba resource group or cost centre, (c) K8s namespace/labels via OpenCost and AWS split cost data. Track **untagged/unallocated spend** as a first-class KPI. Remind admins that AWS/Tencent/Alibaba tags must be activated in the payer, are not (or only 12-month) retroactive, and Alibaba allows ≤100 keys, Tencent ≤15.
4. **Own the budget objects.** Budget (scope = project × env × provider set; period day/month/year; amount; thresholds on actual and forecast). Evaluate on our data after each ingest; optionally mirror to native budgets (AWS `CreateBudget`, GCP `billingbudgets`, Azure budgets, Tencent `CreateBudget`; Alibaba not possible). Enforcement via opt-in actions: AWS Budgets Actions, GCP spend caps / Pub/Sub, Azure action groups, Cloud Custodian `stop` on Tencent.
5. **Forecast** daily series per budget scope with our own model (seasonal ARIMA/ETS-class; store `p10/p50/p90`), show native forecasts (AWS `GetCostForecast`, Azure forecast API) as comparison. Require ≥1 full cycle before showing; flag partial-month estimates.
6. **Recommendation ingestion**: AWS COH + Compute Optimizer exports (set preferences: P95/30 % Balanced, 32 d lookback org-wide; consider paid 93 d for prod), GCP Recommender BigQuery export (org), Azure Advisor via Resource Graph + `benefitRecommendations`, Tencent `DescribeTaskStrategyRisks` (cost pillar), Alibaba `DescribeCostCheckResults`. Dedup per resource (COH-style: keep highest-saving mutually-exclusive action).
7. **Own rightsizing engine where natives are missing/weak**: Tencent/Alibaba VMs and managed DBs (no native size recs), all K8s workloads (KRR/VPA-style on Prometheus, ≥14 d), K8s nodes (Karpenter/CA config advice). Re-price savings with our own effective rates (not retail) so cross-provider numbers are comparable.
8. **Idle/orphan cleanup** via Cloud Custodian policies (mark-for-op → notify → delete after N days) for AWS/GCP/Azure/Tencent; Steampipe alicloud thrifty or custom checks for Alibaba.
9. **Commitments**: ingest SP/RI/CUD recommendations; compute coverage/utilisation from FOCUS `CommitmentDiscount*` columns.

Normalised cost fact (FOCUS-based sketch):

```yaml
cost_fact:            # one row per provider line, daily (hourly kept where available)
  provider: aws|gcp|azure|tencent|alibaba     # FOCUS ProviderName
  billing_account_id / sub_account_id         # payer / member (AWS account, GCP project, Azure sub, Tencent OwnerUin, Ali BillOwnerId)
  charge_period_start, charge_period_end      # FOCUS ChargePeriodStart/End (UTC)
  billing_period, invoice_id, is_final        # finality per provider rule
  service_category, service_name, sku_id, region_id
  resource_id, resource_name, resource_type
  charge_category: usage|purchase|tax|credit|adjustment
  pricing_quantity, pricing_unit, consumed_quantity, consumed_unit
  list_cost, billed_cost, effective_cost, contracted_cost, billing_currency
  commitment_discount_id, commitment_discount_type, commitment_discount_status
  tags: {..}                                  # raw provider tags/labels
  # platform extensions (x_)
  x_project_id, x_environment, x_allocation_method: tag|account|k8s|rule|unallocated
  x_k8s: {cluster, namespace, workload, workload_type}
  x_source: {export: focus|cur2|bq_detailed|azure_focus|tencent_cos|ali_oss, file, ingested_at}
budget:
  id, scope: {projects[], environments[], providers[], accounts[], tags{}}
  period: day|month|quarter|year, amount, currency, cost_basis: billed|effective
  thresholds: [{pct, basis: actual|forecast, channels[]}], actions: [{type, approval_required}]
  native_mirrors: [{provider, native_id}]
budget_status (per evaluation): budget_id, as_of, actual, forecast_p50, forecast_p90, data_completeness
```

Rightsizing recommendation record:

```yaml
recommendation:
  id, fingerprint                         # hash(provider, resource_id, action, target) for dedup across runs
  source: native:{aws_coh|aws_co|gcp_recommender|azure_advisor|tencent_advisor|ali_advisor} | engine:{vm|k8s|db|storage|idle}
  native_ref: {id, etag}                   # for GCP markClaimed / AWS COH id
  provider, account_id, region, resource_id, resource_type: vm|asg|k8s_workload|k8s_node|db|disk|ip|lb|commitment
  x_project_id, x_environment
  action: resize|change_family|migrate_arm|delete|stop|schedule_offhours|purchase_commitment|resize_requests
  current: {sku, vcpu, mem_gib, requests{cpu,mem}, monthly_cost}
  recommended: {sku, vcpu, mem_gib, requests{cpu,mem}, monthly_cost}
  evidence:
    lookback_days, sample_count, metrics: {cpu_p95, cpu_p99, cpu_max, mem_max, mem_p99, net_p95, iops_p95}
    method: {percentile, headroom_pct, algorithm: vpa_hist|krr_simple|provider_native}
  savings: {monthly_estimate, currency, basis: list|retail|effective_after_discounts, deduped: bool}
  confidence: 0..1                         # data coverage × history length (VPA-style)
  risk: {performance: very_low..very_high, migration_effort: very_low..high, reversible: bool}
  conflicts_with: [recommendation_id]      # mutually exclusive actions (GCP xorGroupId analogue)
  state: open|accepted|applied|dismissed|failed|expired, owner, ticket_ref
  generated_at, expires_at
```

### UNVERIFIED items (re-check before relying on them)

AWS forecast model being ML-based; Data Exports / COH pricing (free); GCP numeric idle-VM thresholds and forecast confidence bands; Azure forecast bands; Tencent DescribeBillDetail record granularity, Smart Advisor cost checks and thresholds, budget limits; whether Tencent `*ForOrganization` APIs are called by admin or member; Alibaba hourly file export, ECS spec-recommendation API, `BillOwnerId` across all relationship types; Azure Cobalt / GCP Axion migration guidance; Goldilocks label/QoS mapping; Kubecost free-tier size; Infracost self-hosted pricing API; commercial tool descriptions; Prophet/ETS as "typical".
