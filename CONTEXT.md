# Keel — DevSecOps Platform

Keel (working name) is the internal platform that gives every team a paved road
from code to production: repositories, pipelines, deployments, cloud access,
security controls and cost visibility, all governed by one set of policies and
recorded in one activity log.

## Language

### Ownership

**Tenant**:
A client organisation (or the home organisation itself) whose Projects the
platform manages. The hard isolation boundary for data, access and cost: nothing
of one Tenant is visible to another.
_Avoid_: customer, client, org, account, workspace

**Tenant Member**:
A person who belongs to a Tenant rather than to the operating company, signs in
through that Tenant's identity provider, and sees only that Tenant's data,
mostly read-only.
_Avoid_: client user, external user, guest

**Team**:
The unit that owns things on the platform and is accountable for them. Every
Service, Repository and Cloud Account has exactly one owning Team.
_Avoid_: squad, group, owner (as a noun for a person)

**Service**:
A deployable unit of software with its own lifecycle, owned by one Team. The
Catalog's central entity.
_Avoid_: app, application, microservice, component, project

**Project**:
A client engagement or product that groups related Services and spans
Environments (e.g. `tat-crm`). Belongs to exactly one Tenant, is delivered by
one Team, and is the primary unit for Budgets and cost reporting.
_Avoid_: system, product, programme, workspace

**Catalog**:
The authoritative inventory of Teams, Projects, Services, Repositories,
Environments, Cloud Accounts and how they relate.
_Avoid_: CMDB, registry, inventory

**Scorecard**:
A Service's measured standing against a set of Controls (e.g. "has SBOM",
"deploys via GitOps", "no critical Findings older than 7 days").
_Avoid_: health check, maturity score

### Delivery

**Golden Path**:
The supported, opinionated way to do a common task (create a Service, ship to
prod, request access). Optional to use, but the only path the platform team
guarantees.
_Avoid_: paved road (as a separate term), blueprint, standard

**Template**:
A versioned, executable scaffold that implements part of a Golden Path (a repo
skeleton, a pipeline, an infra module).
_Avoid_: starter, boilerplate, archetype

**Pipeline**:
The defined sequence of stages that turns a commit into a verified Artifact.
A single execution of it is a **Run**.
_Avoid_: workflow, job, build (for the whole thing)

**Artifact**:
An immutable, content-addressed build output (container image, package,
bundle). Identified by digest, never by mutable tag.
_Avoid_: build, binary, image (when the general concept is meant)

**Attestation**:
A signed statement about an Artifact (who built it, from what, what scanned it).
**Provenance** is the Attestation describing how an Artifact was built; an
**SBOM** is the Attestation listing what it contains.
_Avoid_: metadata, certificate

**Environment**:
A named target within one Project that its Services are deployed into (dev,
staging, prod), with its own Guardrails. Each Environment has its own dedicated
Cloud Account per cloud provider (e.g. `tat-crm-prod`).
_Avoid_: stage, tier, cluster

**Release**:
A specific set of Artifact digests plus configuration, approved to move through
Environments.
_Avoid_: version, build, tag

**Promotion**:
Moving a Release from one Environment to the next, gated by Policy.
_Avoid_: deploy (for the act of advancing), push

**Deployment**:
The act, and resulting state, of a Release running in one Environment.
_Avoid_: rollout, install

### Governance

**Control**:
A requirement the organisation must meet, usually traceable to a framework
(SSDF, SLSA, ISO 27001, PDPA). Satisfied by one or more Policies.
_Avoid_: requirement, rule, standard

**Policy**:
A machine-evaluable rule that checks or enforces a Control at a specific
**Enforcement Point** (PR, Pipeline, admission, cloud API, runtime).
_Avoid_: rule, check, guardrail (when the rule itself is meant)

**Guardrail**:
A preventive Policy that makes a bad state impossible rather than reporting it
afterwards (e.g. a cloud-account policy that denies public buckets).
_Avoid_: blocker, gate

**Finding**:
A detected violation or weakness tied to a Service, an Artifact or a cloud
resource, with severity and owner.
_Avoid_: issue, alert, vulnerability (when the general concept is meant)

**Exception**:
A time-boxed, approved, recorded permission for a Finding or Policy violation to
stand. Always has an expiry and an approver.
_Avoid_: waiver, suppression, ignore, allowlist entry

**Data Region**:
The set of cloud regions a Tenant's data and logs may be stored in under
PDPA. Defaults to the Thailand set; a Platform Admin changes it.
_Avoid_: residency zone, home region

**Retention Schedule**:
How long Keel keeps each class of data it stores. The deletion run is a dry
run until a Platform Admin enables deletion for the Tenant, and deletes
nothing under a legal hold or while a breach is open.
_Avoid_: purge policy, TTL

**Breach Clock**:
The 72 hours from becoming aware of a personal data breach to notifying the
PDPC: declared, warning at 48 hours, deadline at 72, ended when the
notification is recorded (notified) or the breach is closed with a reason.
_Avoid_: incident timer

### Access

**Cloud Account**:
A billing- and blast-radius-isolated account in a cloud organisation (a Tencent
Cloud member account, an AWS account). Belongs to exactly one Environment, or to
the platform itself (shared tooling, logging, billing ingestion).
Either **platform-owned** (vended and governed by Keel) or **client-owned**
(in the Tenant's own organisation, where Keel holds only a read-only role).
_Avoid_: subscription, project, tenant

**Landing Zone**:
The baseline every Cloud Account is created with: network, logging, Guardrails,
identity wiring and budget.
_Avoid_: account baseline, foundation

**Permission Boundary**:
The maximum permissions any identity in a scope can ever hold, regardless of
what is granted inside it. Teams self-serve within it; only the platform can
change it.
_Avoid_: guardrail (for the IAM ceiling specifically), max policy

**Access Grant**:
A time-boxed elevation of a human's permissions, requested with a reason and
approved by policy or a person. Expires automatically.
_Avoid_: JIT, elevation, temporary role (as nouns)

**Standing Access**:
Permission a human holds without an active Access Grant. The platform aims to
keep this at read-only or none for production.
_Avoid_: permanent access, default access

**Break-glass**:
The audited emergency path to production access that bypasses normal approval,
used only when the platform itself is unavailable.
_Avoid_: emergency access, root access, god mode

**Workload Identity**:
A credential-less identity a Pipeline or running Service uses to call cloud
APIs, proven by an OIDC token or similar rather than a stored key.
_Avoid_: service account (ambiguous across clouds), machine user, access key

**Secret**:
A credential the platform stores, rotates and injects but no human reads in
normal operation.
_Avoid_: password, key, token (when the general concept is meant)

### Cost

**Cost Allocation**:
Attributing every unit of cloud spend to a Team and Service via account
structure, tags or Kubernetes labels.
_Avoid_: cost split, showback (showback is a use of allocation)

**Unit Cost**:
Spend divided by a business driver (cost per active user, per transaction, per
CI run).
_Avoid_: efficiency, cost ratio

**Budget**:
An expected spend for a Project, or for one Project in one Environment, over a
**Budget Period** (year, broken down into months and days), with alert
thresholds. Compared daily against Actual and Forecast spend.
_Avoid_: quota, limit (quotas are hard caps; budgets are not)

**Actual Spend**:
Amortised, net cost after discounts and credits, as reported by the provider's
billing data. Not final until the provider closes the billing period.
_Avoid_: bill, invoice amount, usage

**Forecast**:
Projected spend to the end of a Budget Period, derived from Actual Spend so far.
_Avoid_: estimate, projection

**Cost Anomaly**:
Spend that departs from its expected baseline beyond a threshold, raised as a
Finding to the owning Team.
_Avoid_: spike, overspend

**Rightsizing Recommendation**:
A proposed change to a resource's size, type or existence (downsize, change
family, delete idle) backed by observed utilisation, with estimated monthly
savings, risk and confidence. Raised as a Finding to the owning Team.
_Avoid_: optimisation tip, suggestion, advisor result

**Waste**:
Spend on resources that are idle, orphaned (no owner or no attachment) or
provisioned well above observed need.
_Avoid_: unused, overprovisioning (overprovisioning is one kind of Waste)

### Record

**Activity**:
One immutable entry in the Activity Log describing who did what to which
entity, when, through which path, why, and with what outcome. Humans,
Pipelines and the platform itself all produce Activities.
_Avoid_: audit event, log line, history

**Activity Log**:
The single append-only, tamper-evident record of every Activity across the
platform.
_Avoid_: audit log, audit trail, changelog

**Decision Record**:
A short, numbered, immutable note of a hard-to-reverse decision, its context
and why it was made. Superseded, never edited.
_Avoid_: design doc, RFC (an RFC proposes; a Decision Record records)
