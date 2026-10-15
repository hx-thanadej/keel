---
status: accepted
date: 2026-10-15
deciders: thanadej@harmonyx.co
---

# A stored Tencent key is an accepted long-lived credential, and it only reads

## Context

[ADR-0007](./0007-no-long-lived-cloud-credentials-in-ci.md) says no
long-lived credentials. Keel follows it for Tencent by taking its base
identity from TKE pod identity or the CVM instance role, and assuming roles
from there.

Not every deployment has either. Keel may run outside Tencent Cloud, or in a
cluster where pod identity is not set up yet. Such a deployment has no
Tencent identity at all, so discovery, billing and member-account reads stay
off. The only way in is a CAM key pair (SecretId and SecretKey) that an
administrator creates.

On 2026-10-15 the user decided that a platform admin may paste such a key
into Keel's portal ([#251](https://github.com/hx-thanadej/keel/issues/251)).
Like the GitHub App key ([ADR-0020](./0020-github-app-key-exception.md)), it
is a credential with no expiry that Keel holds.

## Decision

A stored Tencent key is a documented exception to ADR-0007, and it is
read-only.

- **Scope.** One Tencent connection, in the home Tenant, created by a
  platform admin (`cloud_connection.manage`). When it exists it is Keel's
  base Tencent identity, ahead of TKE and CVM: discovery, member-role
  assumes, client-role assumes and bill reads all start from it. Without
  one, the keyless chain applies as before.
- **Read-only.** Keel never writes to Tencent with a stored key, or with a
  role session assumed from one. The rule sits at the Tencent client layer
  (`internal/cloud/tencent/readonly.go`). A stored key is a `readOnly`
  credential, and a session assumed from a `readOnly` credential is
  `readOnly` too, whatever the target role allows. Every Tencent SDK
  client in Keel, in any package, is built inside `guard`. When the
  client's credential is `readOnly`, `guard` installs a transport that
  sends only the exact `service:Action` reads Keel makes, plus
  `sts:AssumeRole` and `sts:GetCallerIdentity`, and refuses everything else
  with `ErrReadOnly` before a byte leaves Keel. The service comes from the
  request's TC3 signature scope. Actions that mint a credential without the
  mark (`sts:GetSessionToken`, `GetFederationToken`,
  `AssumeRoleWithWebIdentity`, `AssumeRoleWithSAML`, `cam:CreateAccessKey`,
  `tcr:CreateInstanceToken`) are refused even if someone lists them. Reads
  Keel does not make, including ones that hand out access such as
  `cvm:DescribeInstanceVncUrl`, are refused too. COS is not behind the SDK.
  Bill reads use `archive.Reader`, which has no write method and whose
  transport sends only GET and HEAD. The archive writer takes its
  credentials from `WriteSTS`, which refuses a `readOnly` credential.
  `TestStoredKeyRefusesEveryWritePath` and `TestStoredKeyMintsNoCredentials`
  prove each refused call sends nothing. `TestEverySDKClientIsGuarded`
  fails when any client in the module, `NewCommonClient` included, skips
  `guard`. `TestReadsAreExactlyKeelsReads` fails when the allow-list and
  the reads in Keel's code differ, so a write Keel adds later is refused
  without anyone naming it, and a new read fails a test rather than
  production.
- **No write jobs.** With a stored connection at start, Keel does not start
  vending, landing-zone, CI identity, boundary, leaked-key disable,
  Identity Center grant, TCR token, budget mirror, waste cleanup or COS
  archive jobs, and logs which it left off. The connection fills only the
  settings reads use; it never fills `KEEL_TENCENT_VENDING_ROLE`.
- **At rest.** The SecretId and SecretKey are sealed with AES-256-GCM under
  `KEEL_SECRETS_KEY`, a 32-byte key that lives in the platform secret store
  next to Keel's other secrets and never in the database. Each value has
  its own random nonce. The additional data binds it to its Tenant, row and
  column, so a value copied to another row, Tenant or column does not open.
  The database holds the last four characters of the SecretId in clear, for
  display.
- **Never shown again.** The API returns the SecretId masked to its last four
  characters and never returns the SecretKey. Neither appears in an
  Activity, a log line or an error: the key type prints masked, and a
  provider error that echoes the key is scrubbed before Keel stores it.
- **Every change is an Activity.** Create, update, key rotation, test,
  delete, and a reseal at start, each without key material.
- **Startup.** Keel refuses to start when a connection exists and
  `KEEL_SECRETS_KEY` is unset. A connection that opens with neither
  `KEEL_SECRETS_KEY` nor `KEEL_SECRETS_KEY_PREVIOUS` raises an alert at
  start and stays unusable, so a platform admin can delete it and add it
  again after losing the key. Using a connection that cannot be opened is an
  error. Keel never falls back to a writable identity.

## Rotation

- **The Tencent key.** Rotate every 90 days, and at once on suspected
  exposure. CAM lets a user hold two keys, so create the new key, paste it
  with "Rotate keys" in the Connections screen, press "Test connection",
  then disable and delete the old key in CAM. Keel uses the new key on its
  next credential fetch; sessions already assumed from the old key expire
  within the hour.
- **`KEEL_SECRETS_KEY`.** Generate a new key, set it as `KEEL_SECRETS_KEY`
  and move the old one to `KEEL_SECRETS_KEY_PREVIOUS`, then restart. At
  start Keel reseals every connection under the new key and records a
  `keel.cloud_connection.resealed` Activity. Then remove
  `KEEL_SECRETS_KEY_PREVIOUS`. The steps are in
  [connections.md](../runbooks/connections.md).

Nothing in Keel enforces either schedule.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| The key leaks from Keel's database. | It is sealed. The database alone does not open it. |
| `KEEL_SECRETS_KEY` and a database copy leak together. | The key reads only what its CAM user may read. Give that user read-only CAM policies; Keel does not need more, since it never writes with the key. Rotate both. |
| Keel's own code writes with the key. | The `guard` transport and `WriteSTS` refuse it, tested per write path. |
| The key belongs to a different account from the one named. | "Test connection" calls `sts:GetCallerIdentity` and fails when the account is not the payer. |
| A deployment with a stored key silently loses its write jobs. | Keel logs at start which write jobs it did not start and why. A write that still reaches the client layer fails with `ErrReadOnly`, which names this ADR. |

## Considered options

- **Allow stored keys to write.** Vending and landing-zone remediation would
  work without keyless identity. A pasted key with write rights is the
  credential ADR-0007 exists to avoid, held by a web application. Rejected.
- **Keep the key in an environment variable.** Keel already reads
  `TENCENTCLOUD_SECRET_ID` in dev. An operator would have to redeploy to add
  or rotate it, and the portal could not test it. Rejected for
  administrators; dev keeps it.
- **A KMS envelope per row.** Sealing under a cloud KMS would keep the key
  encryption key out of Keel's environment. It needs a KMS identity, the
  very thing a deployment without keyless identity lacks. Revisit when the
  connection guards more than reads.

## Consequences

- Keel holds one more long-lived secret, `KEEL_SECRETS_KEY`, and one stored
  cloud key. Its blast radius is what the CAM user may read.
- Writes still need keyless identity. A deployment that relies on a stored
  key runs discovery, cost and read jobs, and does not start its write
  jobs.
- Which write jobs start is decided at start. A connection added while
  Keel runs makes the base identity read-only at once, and the write jobs
  already running fail with `ErrReadOnly` until the next restart stops them.
- The connection's regions, payer and member role fill unset read
  settings at start. Changing them takes effect on the next restart; a key
  rotation takes effect the next time each client is built. The clients
  built once at start (TCR, Identity Center) are write clients, which a
  stored key does not start.
