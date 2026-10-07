# Runbook: workload secrets (M5, #137)

How a running Service gets credentials, in order of preference. None of
these puts a long-lived key in Git, CI or an image (ADR-0007).

## 1. No secret at all: TKE pod identity

The Service's Kubernetes ServiceAccount is trusted by a CAM role in the
Environment's account (OIDC, like keyless CI). The pod exchanges its projected
token for temporary credentials (`sts:AssumeRoleWithWebIdentity`).

- Keel creates the role through role requests (#132) with the account's
  Permission Boundary (#131).
- **To verify on a sandbox cluster first** (research/02 T9/T10, issue below):
  TKE 1.36 and pod identity availability in ap-bangkok, and the exact
  `oidc:sub` format per ServiceAccount, before roles are pinned to it.

## 2. A secret the provider must hold: SSM + the TKE secrets add-on

Database passwords and third-party API keys live in Tencent SSM in the
Environment's account, rotated by SSM where supported. Pods read them through
the TKE secrets add-on (an External Secrets Operator variant: the upstream
operator has no Tencent provider, research/02 T5). Pin the add-on version.

- SSM access is part of the `keel_permission_boundary` services list; grant
  `ssm:GetSecretValue` on the specific secret only.
- Fallback when the add-on is unavailable: an init container using the pod
  identity from §1 to read SSM directly.

## 3. Secrets in the config repository: SOPS + age

Values that must sit next to manifests are encrypted with SOPS for the
Environment's age recipient. Service Templates write `.sops.yaml`:

```yaml
creation_rules:
  - path_regex: envs/prod/.*\.enc\.yaml$
    age: <prod recipient>
  - path_regex: envs/(dev|staging)/.*\.enc\.yaml$
    age: <non-prod recipient>
```

- Private age keys live in SSM (one per Environment class), read by Argo CD's
  repo server through its pod identity. SOPS has no Tencent KMS backend
  (research/02 T6).
- Recipients come from `KEEL_SOPS_AGE_PROD` / `KEEL_SOPS_AGE_NONPROD`.

### Rotating an age key

1. Generate a new key (`age-keygen`), store the private half in SSM under a
   new version; keep the old version readable.
2. Change the recipient in Keel's configuration; new Service repositories get
   it from the template; existing ones: run `sops updatekeys` on every
   `*.enc.yaml` and merge the PR (Argo CD can decrypt with both versions).
3. When every repository is re-encrypted, disable the old SSM version.
4. Record the rotation as an Activity (`keel.secrets.age_rotated`) via the
   Decision Record or the change PR.
