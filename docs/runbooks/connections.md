# Runbook: Tencent cloud connections (#251, ADR-0022)

A cloud connection is a Tencent CAM key pair a platform admin stores in
Keel. Keel seals it under `KEEL_SECRETS_KEY` and uses it as its base Tencent
identity, read-only. Writes (vending, landing-zone remediation, CI identity,
boundaries, leaked-key disable, Identity Center grants, TCR, budget mirrors,
waste cleanup, archive writes) still need keyless identity. With a stored
key Keel does not start those jobs, and logs at start which ones it left
off (`Tencent write jobs not started`).

## 1. Set `KEEL_SECRETS_KEY`

Generate a 32-byte key and store it in the platform secret store with Keel's
other secrets. Never commit it.

```bash
openssl rand -base64 32
```

Without it, the Connections screen lists nothing it can store and Keel
refuses to start once a connection exists.

## 2. Create the CAM user and key

1. In the payer account, create a CAM sub-user `keel-reader` with
   programmatic access only.
2. Attach read-only policies: `ReadOnlyAccess`, or the narrower
   `QcloudOrganizationReadOnlyAccess`, `QcloudFinanceBillReadOnlyAccess`,
   `QcloudAuditReadOnlyAccess` and `QcloudCamReadOnlyAccess`, plus
   `sts:AssumeRole` on the member and client roles Keel assumes. Keel never
   writes with this key, so it needs no write permission.
3. Create an access key for the user.

## 3. Add the connection

As a platform admin of the home Tenant, open **Connections**, choose **Add
Tencent connection**, and enter the name, payer UIN, default region,
organisation region, member role and the key. Press **Test connection**: it
calls `sts:GetCallerIdentity` and passes when the key belongs to the payer.

The organisation region, default region, payer UIN and member role fill
`KEEL_TENCENT_ORG_REGION`, `KEEL_TENCENT_REGION`, `KEEL_TENCENT_PAYER_UIN`
and `KEEL_TENCENT_MEMBER_ROLE` when those are unset. These are the settings
reads use: discovery, bills, Cloud Monitor, and break-glass and standing
access audits, which read member accounts through the member role. The
connection never fills `KEEL_TENCENT_VENDING_ROLE`. Restart Keel after
adding the connection or changing them.

## 4. Rotate the Tencent key (every 90 days)

1. Create a second access key for `keel-reader` in CAM.
2. In **Connections**, choose **Rotate keys**, paste the new pair, and press
   **Test connection**.
3. Disable, then delete, the old key in CAM.

## 5. Rotate `KEEL_SECRETS_KEY`

1. Generate a new key.
2. Set `KEEL_SECRETS_KEY_PREVIOUS` to the current key and
   `KEEL_SECRETS_KEY` to the new one, and restart Keel. At start Keel
   reseals every connection under the new key and records a
   `keel.cloud_connection.resealed` Activity per connection.
3. Remove `KEEL_SECRETS_KEY_PREVIOUS` and restart again.

If `KEEL_SECRETS_KEY` is lost, the stored keys cannot be opened. Set a new
`KEEL_SECRETS_KEY` and restart: Keel starts with an alert, and Tencent calls
fail until a platform admin deletes the connection and adds it again. **Test
connection** says so too.
