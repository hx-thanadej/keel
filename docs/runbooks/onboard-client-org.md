# Runbook: onboard a client-owned cloud organisation

Some Tenants own their cloud organisation and pay its bill
([ADR-0018](../adr/0018-client-owned-organisations-read-only.md)). Keel is
read-only there. This runbook is for the Keel operator and the client's cloud
admin. It covers what main implements today: bill ingestion from a client's
**Tencent Cloud payer** (#182) and **AWS management account** (#183), and
Budget status, security Findings and Rightsizing Recommendations read
through the same role (Tencent #182, AWS #183).
[connect-billing.md](connect-billing.md) holds the full provider detail; this
page is the onboarding order and the client's security-review summary.

## What Keel does and never does

Keel reads, through one role the client creates in its payer or management
account:

- FOCUS bill files from the client's Bill Storage bucket (Tencent) or Data
  Exports folder (AWS);
- on Tencent, the invoice totals (`finance:DescribeBill*`) used to reconcile;
- on AWS, the management account's Budgets (`DescribeBudgets`), active
  Security Hub findings (`GetFindings`, which includes AWS Config rule
  findings when the client has Security Hub's Config integration on) and
  Cost Optimization Hub recommendations (`ListRecommendations`, which
  carries Compute Optimizer's cost-saving rightsizing and idle advice, but
  not its under-provisioned findings; see the coverage note in step 2);
- on Tencent, the payer's active Budgets (`DescribeBudget`), its Smart
  Advisor risks (`DescribeStrategies`, `DescribeTaskStrategyRisks`), and,
  for rightsizing its own CVM instances, Cloud Monitor CPU and memory
  (`GetMonitorData`) and the instances' current types (`DescribeInstances`).
  Keel's VM engine turns those into Recommendations, as for Keel's own
  accounts; Tencent has no native size recommender (ADR-0013). Only Tencent's
  public CVM price list (`DescribeZoneInstanceConfigInfos`) is read as Keel.

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
- **No reads beyond the listed ones.** Every AWS session carries a
  session policy. The bill session's is built from the payer's record. It
  allows `s3:ListBucket` on the bucket only for the recorded prefix,
  `s3:GetObject` only under it, and `kms:Decrypt` only on the recorded key
  via S3 in the bucket's region. The reads session's allows only
  `budgets:ViewBudget` on the payer's own budgets, `aws-portal:ViewBilling`,
  `securityhub:GetFindings` on the payer's hub in its recorded region, and
  `cost-optimization-hub:ListRecommendations` (`aws.ReadActions`). AWS grants
  the intersection, so an over-broad role still does only these reads. The
  Tencent reads session carries a session policy (the AssumeRole `Policy`
  parameter) allowing only `finance:DescribeBudget`,
  `advisor:DescribeStrategies`, `advisor:DescribeTaskStrategyRisks`,
  `monitor:GetMonitorData` and `cvm:DescribeInstances`
  (`tencent.ReadActions`). Tencent says it grants the session "based on" that
  policy; its docs do not state the intersection rule AWS documents, so the
  role's own policy must still be read-only. The Tencent bill session carries
  no session policy.
- **Nothing leaves the Tenant.** A client payer's lines are kept only for
  that Tenant's registered client-owned accounts. Every other line is dropped
  and counted in `dropped_lines` and `dropped_billed`. Security findings and
  recommendations follow the same rule: one on any other account is dropped
  and counted in the `client reads` log line's `dropped`, never sent to the
  home Tenant.

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
   to the client now. Nobody can choose it. If it is lost before the client
   saves it, issue a new one (see "Rotate the ExternalId" below).
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
       {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::<bucket>/<prefix>*"},
       {"Effect": "Allow", "Action": "budgets:ViewBudget", "Resource": "arn:aws:budgets::<management account id>:budget/*"},
       {"Effect": "Allow", "Action": "aws-portal:ViewBilling", "Resource": "*"},
       {"Effect": "Allow", "Action": "securityhub:GetFindings", "Resource": "arn:aws:securityhub:<region>:<management account id>:hub/default"},
       {"Effect": "Allow", "Action": "cost-optimization-hub:ListRecommendations", "Resource": "*"}
     ]
   }
   ```

   The last four statements are for the non-bill reads. `<region>` is the
   payer's recorded `region`. Each action is one the Service Authorization
   Reference names for the call Keel makes, and each is Read or List access:

   - `DescribeBudgets` authorizes `budgets:ViewBudget`, whose resource type
     is `budget` (`arn:${Partition}:budgets::${Account}:budget/${BudgetName}`)
     ([AWS Budgets](https://docs.aws.amazon.com/service-authorization/latest/reference/list_budgets.html)).
     AWS's guide says that for actions on a budget resource you specify the
     budget ARN
     ([policy examples](https://docs.aws.amazon.com/cost-management/latest/userguide/billing-example-policies.html)),
     so the statement names the management account's budgets only.
   - The same reference's operations table also lists the legacy
     `aws-portal:ViewBilling` against `DescribeBudgets`. AWS says the
     `aws-portal` actions reached end of standard support in July 2023
     ([policy examples](https://docs.aws.amazon.com/cost-management/latest/userguide/billing-example-policies.html))
     and that API access to AWS Budgets is unaffected by the move to the
     fine-grained billing actions
     ([fine-grained access](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/migrate-granularaccess-whatis.html));
     the fine-grained replacement for viewing budgets is `budgets:ViewBudget`
     itself. AWS's own `AWSBudgetsReadOnlyAccess` managed policy still grants
     `aws-portal:ViewBilling` with `budgets:ViewBudget`
     ([policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSBudgetsReadOnlyAccess.html)).
     Keel's position: grant it, because the reference still lists it and a
     session policy that left it out could not be fixed from the client's
     side. In an account on the fine-grained actions it grants nothing more.
     `aws-portal` defines no resource types, so it stays on `*`. A client
     that refuses it loses nothing else; if `DescribeBudgets` is then denied,
     the budget read alone fails.
   - `GetFindings` authorizes `securityhub:GetFindings`, whose resource type
     is `hub` (`arn:${Partition}:securityhub:${Region}:${Account}:hub/default`)
     ([Security Hub](https://docs.aws.amazon.com/service-authorization/latest/reference/list_securityhub.html)).
     Keel calls it only in the payer's recorded region, so the statement names
     that hub.
   - `ListRecommendations` authorizes `cost-optimization-hub:ListRecommendations`.
     Cost Optimization Hub does not support a resource ARN in `Resource`
     ([Cost Optimization Hub](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cost-optimization-hub.html)),
     so it stays on `*`.

   Keel's session policy carries the same four statements for the payer
   (`aws.ReadsRole`), so a client role written with `Resource: "*"` is still
   narrowed to them. Leave the statements off to have Keel read bills only;
   each read it cannot make is logged as `ALERT client reads failed` and the
   other reads carry on.

   Keel reads Security Hub in the payer's recorded `region`, so aggregate
   findings into that region. It sees what Security Hub in the management
   account sees: when the Security Hub administrator is a different account,
   only the management account's own findings arrive. Cost Optimization Hub
   and Compute Optimizer must be enrolled for the organisation, or the list
   is empty.

   **Coverage gap: under-provisioned resources.** Cost Optimization Hub
   lists cost optimization recommendations: rightsizing, idle deletion,
   Savings Plans and Reserved Instances, each with estimated savings
   ([Cost Optimization Hub](https://docs.aws.amazon.com/cost-management/latest/userguide/cost-optimization-hub.html)).
   Compute Optimizer's under-provisioned finding is a performance one: a
   specification that does not meet the workload's needs
   ([EC2 findings](https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-ec2-recommendations.html)),
   with no saving to list. From these two pages we infer that Cost
   Optimization Hub does not carry under-provisioned findings. No AWS page
   states that gap, so treat it as an inference. On that inference Keel
   never shows a client's under-provisioned instances. Keel does not read Compute Optimizer directly; a client that
   wants under-provisioning watched reads it in the Compute Optimizer
   console. Reading it through Keel would add `compute-optimizer` read
   actions to the role and the session policy.

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

   Add this statement for the Budget, Smart Advisor and rightsizing reads.
   Leave it off to have Keel read bills only; each read it cannot make is
   logged as `ALERT client reads failed` and the other reads carry on.

   ```json
   {"effect": "allow", "action": ["finance:DescribeBudget", "advisor:DescribeStrategies", "advisor:DescribeTaskStrategyRisks",
     "monitor:GetMonitorData", "cvm:DescribeInstances"], "resource": ["*"]}
   ```

   Each action is the read the CAM docs name for the call Keel makes:
   `DescribeBudget` is a Read action of the `finance` service
   ([finance actions](https://www.tencentcloud.com/document/product/598/77527)),
   `DescribeStrategies` and `DescribeTaskStrategyRisks` are Read actions of
   `advisor`, operation level, resource `*`
   ([Smart Advisor actions](https://www.tencentcloud.com/document/product/598/57056)),
   `monitor:GetMonitorData` is the action Tencent's read-only monitoring
   policy example grants
   ([custom policy example](https://www.tencentcloud.com/document/product/1045/53784)),
   and `cvm:DescribeInstances` is the action CAM's own example grants to let
   a user view CVM instances
   ([CAM users and permissions](https://www.tencentcloud.com/document/product/598/18795)).

   Smart Advisor assesses only the account that calls it, so its risks are
   the payer account's. Smart Advisor must be authorised in the payer
   (console, service authorisation), or `DescribeStrategies` fails. Keel
   reads Cloud Monitor and instance types only for CVM instances the payer
   account itself was billed for: member accounts' instances are not
   rightsized, because Keel holds no session in them.

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
5. **Budget, finding and rightsizing reads.** Right after each bill sync,
   Keel reads every payer that sync visited through a second session of the
   same role, and logs one `client reads` line per payer with `budgets`,
   `budgets_over`, `findings`, `recommendations`, `dropped` and `withdrawn`. In the
   client's Tenant:
   - `GET /v1/tenants/{tenant}/findings?kind=cloud_budget` lists one Finding
     per budget whose spend is over its limit (high) or whose forecast is
     (medium). A budget under both raises nothing. Keel stores no other
     budget status. On Tencent only active budgets are read; a planned
     (`CYCLE`) budget's limit is the current period's quota, and amounts are
     taken as USD, since Tencent reports no currency on a budget.
   - `GET /v1/tenants/{tenant}/findings?kind=cloud_security` lists one
     Finding per active Security Hub finding (Critical, High, Medium or Low,
     workflow New or Notified) on AWS, or per Smart Advisor risky instance
     (medium or high risk, any category) on Tencent, on one of the Tenant's
     client-owned accounts, with that account's Project and Environment.
   - Rightsizing Recommendations appear with the Tenant's others, source
     `native:aws_coh` on AWS and `engine:vm` on Tencent. The Tencent ones
     need 14 days of Cloud Monitor data; the first read backfills the last
     14 days, and each later read fills any missing day and refreshes the
     last two.

   A `cloud_budget` or `cloud_security` Finding resolves on the first read
   that no longer reports it. On AWS, an open `native:aws_coh`
   Recommendation that a complete Cost Optimization Hub listing for its
   payer no longer holds is withdrawn: its state becomes `superseded` with
   `decision_reason` "no longer reported by native:aws_coh", its Finding
   resolves, and the log line counts it in `withdrawn`. A listing is
   complete only when every page arrived with no error. Each payer's
   listing withdraws only advice read through that payer, so two payers in
   one Tenant never withdraw each other's. Accepted advice is left to its
   pull request. Tencent `engine:vm` advice is never withdrawn this way:
   the engine reports only the instances it could evaluate. A read that
   fails resolves and withdraws nothing. Keel's own Cost Optimization Hub
   import (`KEEL_AWS_COH=1`) withdraws its own advice by the same rule,
   never a client payer's.

   Withdrawal began with the #234 deploy. Advice AWS had already stopped
   reporting before that deploy stays `open`, and Keel does not withdraw
   it. Dismiss each by hand: list the Tenant's recommendations
   (`GET /v1/tenants/{tenant}/recommendations`), pick the open
   `native:aws_coh` ones the payer's Cost Optimization Hub no longer lists,
   and `POST /v1/tenants/{tenant}/recommendations/{id}/dismiss` with a JSON
   body `{"reason": "..."}`. The caller needs `recommendation.decide`.
6. **Keel's own side.** Before trying any client role, each run checks
   Keel's own identity for that provider once: it must load (on AWS, from a
   keyless source) and STS must accept it (`GetCallerIdentity`). If either
   fails, keel-api logs `ALERT client bill sync failed` for the provider
   once per run and raises `keel_identity_unusable` in Keel's **home**
   Tenant (`GET /v1/tenants/{home}/findings?kind=keel_identity_unusable`).
   Its `detail.reason` says whether the identity did not load or STS
   rejected it (expired, revoked or untrusted credentials). No client role is
   tried, for bills or for the AWS reads, no client Finding is raised and no
   client's "Last successful assume" moves. The Finding resolves on the next run whose identity check
   passes, or once the provider has no client payers left. The other
   provider's sync carries on. An AssumeRole refused after STS accepted
   Keel's identity is a `client_role_unusable` in the client's Tenant. That
   includes Keel's base role lacking `sts:AssumeRole` on the client's role
   (step 4), which STS reports the same way as a refusing trust policy.

`bill_sync_blocked` means Keel refused to load a month because two bill
files charge the same sub-account for the same hours. That happens only in
Tencent `per-day` mode, usually because the month-to-date files need
`cumulative` or a second bill type is delivered to the prefix. Fix the
client payer's `mode` with `PUT .../client-payer` (resend `bucket`,
`prefix`, `region` and the new `mode`; the PUT replaces the whole record and
a bare `{"mode": ...}` clears the bucket), or have the client clean
the prefix; the next load resolves it. For a client payer this Finding is
raised in the **client's** Tenant and shows in its role health panel, and
its hint names `client_payers.mode` and the `PUT .../client-payer` route.
`KEEL_TENCENT_BILL_MODE` sets only Keel's own payer's mode.

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

## 6. Rotate the ExternalId

Rotate when the id was lost before the client saved it, when it may have
reached someone it should not have, or when re-onboarding a client whose
role was deleted.

1. A platform admin bound in the client's Tenant calls
   `POST /v1/tenants/{tenant}/cloud-accounts/{account}/client-payer/rotate-external-id`
   with `{"why": "..."}`. The action is `cloud_account.rotate_external_id`,
   a permission of its own, not part of `cloud_account.update`. The response
   carries the new `role_external_id` once; no call reads it back. Keel draws
   it from a CSPRNG (128 bits). It works only on an active, client-owned
   payer. On a payer whose Cloud Account was made platform-owned it fails
   with 400 and records nothing, as `PUT .../client-payer` does: sync assumes
   no client role for that account, so a new id would never be used.
2. The Tenant's Activity Log records
   `keel.cloud_account.client_payer_external_id_rotated` with the actor and
   `why`. It never carries the old or the new id. A refused attempt is
   recorded as `keel.cloud_account.rotate_external_id.denied`.
3. Send the new id to the client. They replace the trust policy's
   `sts:ExternalId` (AWS) or `sts:external_id` (Tencent) value with it.

The old id stops working at once. The next hourly sync assumes the role
with the new id, so until the client updates the trust policy the role
refuses Keel and `client_role_unusable` opens in the client's Tenant. Its
`detail.configure` names the new id, so a Tenant reader can also read it
there while the Finding is open. It resolves on the next successful
AssumeRole. Bills wait in the client's bucket until that sync.

The ExternalId stays visible in that Finding to every reader in the
client's Tenant, not only to admins. The client's own engineers need it to
fix the trust policy, and the ExternalId is not a secret. It guards against
the confused deputy problem by tying Keel's AssumeRole to this client; it
grants nothing without Keel's base role. AWS says so directly: "AWS does
not treat the external ID as a secret", and it is shown to anyone who can
view the role
([AWS IAM, external IDs for third-party access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html#id_roles_third-party_external-id)).
Keel still returns it from the API only once and keeps it out of
Activities, so it does not spread further than the client needs.

Keel keeps no grace period in which both ids work. A rotation is usually
done because the old id should stop working, and a grace window would keep
it working. It would also need a second column and a second AssumeRole per
failed sync. The cost of no grace is a sync gap of at most the time the
client takes to edit one condition, which the Finding reports. To avoid
even that gap, ask the client to accept both values in the condition
right after you rotate, then drop the old one. On AWS this is confirmed:
`StringEquals` on `sts:ExternalId` takes a list of values. On Tencent it is
unconfirmed whether `string_equal` on `sts:external_id` accepts a value
list. Until that is tested on a real Tencent account, do not rely on it:
rotate when the client is ready to replace the single value, and expect a
`client_role_unusable` Finding until they do.

## 7. Re-onboard an archived payer

An archived Cloud Account comes back with
`POST /v1/tenants/{tenant}/cloud-accounts/{account}/unarchive` and
`{"why": "..."}` (`cloud_account.unarchive`, platform admin only, recorded
as `keel.cloud_account.unarchived`). The account keeps its id, its
ownership, its read-only role, its client payer record and its ExternalId,
so its cost history and Activities stay attributed to it, and the
client-owned guards hold as before. Sync visits it again from the next
run. Unarchiving an account that is already active returns it unchanged
and records no Activity, so a retried call is safe.

1. Unarchive the payer and each member account you archived in section 5.
2. If the client deleted the role, have them recreate it (section 2). If you
   no longer hold the ExternalId, rotate it (section 6) and send the new one.
3. Restore Keel's `sts:AssumeRole` on the role (section 1, step 4).
4. Verify as in section 4.

Registering the account again with `POST .../cloud-accounts` still fails
with 409: `(provider, external_id)` is unique across archived rows too.
That keeps exactly one Cloud Account per provider account, active or not,
so an account cannot be active twice or move into another Tenant by
re-registration. Moving a payer to another Tenant is not supported.

## Not yet supported

- **Azure, Google Cloud, Alibaba Cloud** (#184). The API accepts a
  client-owned account on these providers with its `read_only_role`
  (Azure `tenant_id` and `client_id`, GCP `workload_identity_provider` and
  `service_account`, Alibaba `role_arn`), and the mutating-flow guard
  applies. Nothing assumes those identities, and `PUT .../client-payer`
  refuses any provider but `tencent` and `aws`. There are no onboarding
  steps for them yet.
- **Tencent member accounts' rightsizing.** Only the payer account's own CVM
  instances are rightsized. A member account's recorded `read_only_role` is
  still unused.
