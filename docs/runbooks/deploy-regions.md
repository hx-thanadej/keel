# Runbook: region settings for a Keel deploy

Set these before a deploy. The PDPA residency check (`keel-pdpa-residency@1`,
PDPA s.28) places every platform store at the region these variables name.
A store Keel cannot place is either refused at startup or named in each
day's residency Activity as not checked, which marks that run failed.

A default is a guess. If a bucket lives somewhere other than its default,
set the variable: Keel cannot see the bucket's real region, so residency
would check the default instead.

## Prerequisites

| Variable | Set it to | When unset |
|---|---|---|
| `KEEL_DB_REGION` | The region of Keel's Postgres, e.g. `ap-bangkok`. | Keel starts. Every daily residency run, in every Tenant, records the database as `not checked: database keel-postgres (KEEL_DB_REGION unset)` and is marked failed. No Finding is raised, and a database Finding that is already open stays open. |
| `KEEL_PDPA_REGIONS` | Comma-separated default data region set for Tenants with no PDPA settings. | `ap-bangkok,ap-southeast-7` (Tencent and AWS Bangkok). |
| `KEEL_ARCHIVE_REGION` | The Activity Log archive bucket's region. | With `KEEL_ARCHIVE_BUCKET` set, Keel refuses to start, for both the AWS and the COS archive. See [log-archive.md](log-archive.md). |
| `KEEL_TENCENT_REGION` | The region of the Tencent billing API and of `KEEL_TENCENT_BILL_BUCKET`. | `ap-bangkok`. Also the region for TCR, Tencent budgets, the STS identity check and CVM utilisation (`KEEL_TENCENT_MEMBER_ROLE`). |
| `KEEL_AWS_REGION` | The region of `KEEL_AWS_BILL_BUCKET`. | `us-east-1`. Bill sync reads the bucket at `s3.us-east-1.amazonaws.com`, and residency places it there, outside the default Thailand set, so each Tenant gets a Finding. |
| `KEEL_ALIBABA_REGION` | The region of `KEEL_ALIBABA_BILL_BUCKET`. | `ap-southeast-1`. Bill sync and residency both use it. |
| `KEEL_GCP_BILL_BUCKET_REGION` | The location of `KEEL_GCP_BILL_BUCKET`, e.g. `asia-southeast1`. | With `KEEL_GCP_BILL_BUCKET` set, Keel refuses to start. |
| `KEEL_AZURE_BILL_EXPORT_REGION` | The region of the storage account holding the Azure bill export. | With `KEEL_AZURE_BILL_CONTAINER` set, Keel refuses to start. |
| `KEEL_TENCENT_ORG_REGION` | The Tencent organisation API region, e.g. `ap-bangkok`. | Not a residency input. Tencent organisation discovery, account vending, Identity Center access grants (with `KEEL_CIC_ZONE_ID`), break-glass audit and Tencent leaked-key revocation are off. See [vending.md](vending.md) and [access.md](access.md). |

## Client payers

A client payer's bill bucket region is data, not environment. It is the
`region` stored with the payer when it is registered
([onboard-client-org.md](onboard-client-org.md)). The residency check places
each active client payer's bucket there, in the client's Tenant. A payer
whose account is archived, or whose delivery has no bucket yet, is not
checked.

## Check after a deploy

The next residency run (daily) records `keel.pdpa.residency.checked` in each
Tenant. Its detail names every store it could not place under `not checked`.
After setting `KEEL_DB_REGION`, the database is gone from that list.
