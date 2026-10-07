# Runbook: turn on rightsizing (M2)

Rightsizing runs once a day inside `keel-api`, after utilisation is collected.
Every engine is optional and switched on by configuration. Nothing here lets
Keel resize a resource; only Waste cleanup deletes, and only when every gate
below is open.

## 1. Utilisation

| Source | Configure | Notes |
|---|---|---|
| Kubernetes | `KEEL_PROMETHEUS=cluster=https://prom…[@tenant/project/env],…` | cAdvisor + kube-state-metrics; the optional scope owns namespaces the Catalog doesn't map |
| Tencent CVM | `KEEL_TENCENT_MEMBER_ROLE=<role name>` (+ `KEEL_TENCENT_REGION`, default `ap-bangkok`) | Keel assumes this role in each member account with STS; memory needs the CVM monitoring agent |

Member-account role, read-only part: `monitor:GetMonitorData`,
`cvm:DescribeInstances`, `cvm:DescribeZoneInstanceConfigInfos`,
`cbs:DescribeDisks`, `clb:DescribeLoadBalancers`, `clb:DescribeTargets`,
`vpc:DescribeAddresses`.

## 2. Engines

| Engine | Needs | Raises |
|---|---|---|
| Kubernetes requests | Prometheus | `resize_requests` (≥20% cut, ≥14 days, prod ≥21 days) |
| Tencent CVM size | member role | `resize` (new type ≤80% of the price) |
| AWS Cost Optimization Hub | `KEEL_AWS_COH=1`, AWS credentials for the management account | imported as-is |
| Waste | member role | `delete` for unattached disks, unbound EIPs, empty load balancers; `stop` for idle VMs |
| Off-hours | hourly utilisation | `schedule` for non-prod VMs, in the Tenant's time zone |
| Savings tracker | cost facts | realised savings, regressions |

Set a Tenant's time zone: `PATCH /v1/tenants/{tenant}` with
`{"time_zone": "Asia/Bangkok", "why": "…"}`.

## 3. Pull requests

`KEEL_GITHUB_WRITE_TOKEN` (fine-grained: contents + pull requests write on the
repositories that hold manifests). "Open pull request" on a Finding patches
the workload's requests; merged PRs mark the recommendation applied, closed
ones reopen it.

## 4. Waste cleanup (off by default)

All must hold before Keel deletes anything:

1. `KEEL_WASTE_CLEANUP=1`;
2. the Environment opted in (`waste_cleanup`), and it is not production;
3. the item has been open for `KEEL_WASTE_GRACE_DAYS` (default 7) without
   being dismissed;
4. the member role also allows `cbs:CreateSnapshot`, `cbs:TerminateDisks`
   and `vpc:ReleaseAddresses`.

Only two kinds are ever cleaned automatically: pay-as-you-go unattached disks
(snapshotted first, `keel-before-delete-<disk>`) and unbound EIPs. Load
balancers and VMs are always left to people. Each cleanup marks the
recommendation applied and is recorded in the Activity Log.
