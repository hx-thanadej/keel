---
status: proposed
date: 2026-10-06
---

# Rightsizing: ingest native recommenders, run our own engine where they are weak

Every resource Keel can see gets a Rightsizing verdict. Native recommenders are
ingested where strong: AWS Cost Optimization Hub + Compute Optimizer, GCP
Recommender, Azure Advisor. Keel's **own engine** covers where they are missing
or weak: Tencent and Alibaba VMs and managed databases (their advisors have no
instance-size recommendation API), all Kubernetes workloads (requests/limits,
KRR/VPA-style on Prometheus, ≥14 days of history) and nodes (Karpenter/cluster-
autoscaler advice). Idle and orphaned resources are found by Cloud Custodian
policies (mark → notify owner → delete after N days, non-prod first).

All sources produce one **Rightsizing Recommendation** record: current vs
recommended size, utilisation evidence (p95/p99/max, lookback, sample count),
method, monthly savings re-priced at **our effective rates** (not retail, so
providers are comparable), confidence, risk and reversibility, and conflicts
with mutually exclusive recommendations. Each becomes a Finding for the owning
Team.

## Consequences

- Defaults (tunable per Environment): CPU p95, memory max, +15% headroom,
  lookback 14 days for K8s and 32 days for VMs; prod requires higher confidence.
- Kubernetes in-place pod resize (GA in 1.35) lets accepted workload
  recommendations be applied without restarts on clusters that support it.
- Recommendations are applied as PRs to IaC/GitOps config, never by mutating
  live resources, so they stay reviewable, recorded and reversible.
