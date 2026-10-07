# Deploy assets

| Path | What |
|---|---|
| `github/workflows/keel-build.yml` | Keel's reusable build workflow. Copy into the organisation's `keel-workflows` repo; set `KEEL_TRUSTED_BUILDER` to `https://github.com/<org>/keel-workflows/.github/workflows/keel-build.yml@` and `KEEL_REUSABLE_WORKFLOW` to its pinned path for Service Templates. |
| `github/workflows/caller-example.yml` | What Service Templates write into each repository. |
| `arc/values.yaml` | Actions Runner Controller scale set `keel-ephemeral`: one job per pod, no Docker socket, non-root. |
| `arc/egress-proxy.yaml` | Default-deny egress for runner pods except through an allowlisting proxy. |

Build job vs publish job: only `publish` may request an OIDC token, and it
never runs project code. The build job has no registry or cloud access.
Keel's CI lints these workflows with actionlint and zizmor.
