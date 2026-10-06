# 03 — Platform engineering, repo management, GitOps, FinOps, metrics, decision records

Research date: 2026-10-06. Scope: primary sources only (foundation specs, official docs, original authors). Claims not traced to a primary source are marked **UNVERIFIED**. Versions are as observed on the date above.

## TL;DR

- **Platform = product, not a ticket queue.** CNCF's Platforms White Paper (v1.0, Apr 2023) lists 13 capability domains and 7 attributes, with "secure by default" and "reduced cognitive load" among them. DORA 2025 found 90% of orgs have a platform, and that platform *quality* is one of 7 capabilities that amplify AI's benefit.
- **Backstage's catalog model is the de facto vocabulary** for ownership metadata: Component / API / Resource / System / Domain / Group / User, with `owner` required on Components. Backstage is still CNCF **Incubating**, not Graduated.
- **GitOps has a 4-principle spec** (OpenGitOps v1.0.0). Argo CD (v3.5.x) and Flux (v2.9.x) are both CNCF Graduated. Environment promotion is still the immature part: Argo's Source Hydrator is beta and GitOps Promoter is experimental.
- **DORA now uses five delivery metrics** (rework rate was added in 2024), split into throughput and instability. In 2025 the elite/high/medium/low clusters were replaced by **seven team profiles**. DORA research shows CABs don't lower change-fail rate. Peer review recorded in the platform satisfies segregation of duties.
- **FinOps Framework 2026** (Mar 2026) has 4 domains and 22 capabilities. It added **Executive Strategy Alignment**, and **Scopes** were redefined as business constructs (product, cost center, environment) that sit on top of **Technology Categories**. Scopes were first introduced in Framework 2025.
- **FOCUS 1.4** was ratified 2026-06-04. **Tencent Cloud** publishes FOCUS **1.0** exports to COS, with documented gaps: EffectiveCost, ServiceCategory, SkuId and others are empty. **Alibaba Cloud** has FOCUS 1.0 in invitational preview and says it is not for reconciliation.
- **ADRs**: Nygard (2011) defined the format and MADR 4.0.0 (Sep 2024) is the current structured template. The lifecycle is proposed → accepted → deprecated/superseded, and ADRs are immutable and append-only.
- **"Shift down" beats "shift left" at scale.** Google (Kern, ACM Queue 2024) and Netflix (Wall-E, 2021) show that building security into the platform reduces whole defect classes to near zero. It also turns security review into a yes/no question: "do you use the paved road?"

---

## 1. Platform engineering

**CNCF Platforms White Paper** (TAG App Delivery, Platforms WG; v1.0, April 2023). https://tag-app-delivery.cncf.io/whitepapers/platforms/
- Definition: a platform is "an integrated collection of capabilities defined and presented according to the needs of the platform's users". It is a cross-cutting layer that gives a consistent experience across applications. https://tag-app-delivery.cncf.io/whitepapers/platforms/
- **13 capability domains**: Web portals; APIs & CLIs; Golden-path templates & docs; Build automation; Delivery automation; Development environments; Observability (including **cost tracking**); Infrastructure services; Data services; Messaging & events; Identity & secrets; Security services (code analysis, runtime analysis, policy enforcement); Artifact storage. https://tag-app-delivery.cncf.io/whitepapers/platforms/
- **7 attributes**: Platform as a product; User experience (consistent across GUI, API and CLI); Documentation & onboarding; Self-service; Reduced cognitive load; Optional & composable; **Secure by default**. https://tag-app-delivery.cncf.io/whitepapers/platforms/
- **Measuring success**:
  - User satisfaction and productivity: active users, retention, NPS, SPACE.
  - Organizational efficiency: request-to-fulfilment latency, time to deploy a new service, time to first contribution.
  - Delivery: the DORA keys.
  - https://tag-app-delivery.cncf.io/whitepapers/platforms/
- Platform teams do research and planning, marketing and advocacy, and build the interfaces (portal, API, docs, templates, CLI). They often **do not operate the underlying services** themselves. Instead they make externally provided services consistent. https://tag-app-delivery.cncf.io/whitepapers/platforms/

**CNCF Platform Engineering Maturity Model** (v1, Oct/Nov 2023). https://tag-app-delivery.cncf.io/whitepapers/platform-eng-maturity-model/ · announcement: https://tag-app-delivery.cncf.io/blog/announcing-the-platform-engineering-maturity-model/
- **Levels**: Provisional → Operational → Scalable → Optimizing.
- **Five aspects**, each with a question:
  - Investment: how are staff and funds allocated?
  - Adoption: why and how do users discover the platform?
  - Interfaces: how do users consume it?
  - Operations: how is it planned and maintained?
  - Measurement: how is feedback gathered?
  - https://tag-app-delivery.cncf.io/whitepapers/platform-eng-maturity-model/
- The levels most relevant to product design:
  - Interfaces go from "custom processes, manual intervention" to self-service at *Scalable*, then to "transparent integration into existing workflows" at *Optimizing*.
  - Adoption goes from mandates (*Operational*) to "self-directed, based on demonstrated value" (*Scalable*).
  - Investment moves from a cost-center team to being "funded as internal product based on measurable value".
  - https://tag-app-delivery.cncf.io/whitepapers/platform-eng-maturity-model/
- Status: the `cncf/tag-app-delivery` repo was **archived 2025-09-09** during the CNCF TOC's 2025 TAG restructure, which created five TAGs: Developer Experience, Infrastructure, Operational Resilience, Security & Compliance, and Workloads Foundation. Both documents remain v1. https://github.com/cncf/tag-app-delivery/ · https://www.cncf.io/blog/2025/05/07/10-years-in-cloud-native-toc-restructures-technical-groups/
  - Which new TAG now owns platform-engineering work is **UNVERIFIED**. Developer Experience is likely, but this is an inference.

**Golden paths / paved roads**
- Spotify's definition (Gary Niemen, 2020-08-17): the Golden Path is "the opinionated and supported path to build something".
  - Each discipline gets its own Golden Path tutorial, delivered via TechDocs in Backstage.
  - It is **optional**: you can leave it, but you lose support.
  - It solved "rumour-driven development" and fragmentation.
  - https://engineering.atspotify.com/2020/08/how-we-use-golden-paths-to-solve-fragmentation-in-our-software-ecosystem

**Team Topologies** (Skelton & Pais). https://teamtopologies.com/key-concepts
- Four team types: stream-aligned, platform, enabling, complicated-subsystem.
- Three interaction modes: collaboration, X-as-a-Service, facilitation.
- **Thinnest Viable Platform**: just enough platform. "A good platform should make stream-aligned teams move faster, not generate more dependencies to manage."
- **Cognitive load** is finite. Overloaded teams "make poor decisions and move slowly".

**DORA on platform engineering**. https://dora.dev/capabilities/platform-engineering/
- 2025: 90% of orgs use an internal developer platform and 76% have dedicated platform teams.
- The platform attribute most correlated with a positive user experience is "clear feedback on the outcome of my tasks".
- Recommended approach:
  - Product-management mindset.
  - Shift cognitive load into the platform.
  - Start with a minimum viable platform on the most common workflow.
  - Design for extensibility.
- Anti-patterns: "build it and they will come", ivory tower, **ticket-ops**, big bang, one-size-fits-all.
- Measure with a balanced scorecard: DORA delivery metrics + CSAT/NPS + adoption/retention + task success.
- 2024 report: platforms raise individual and team productivity but can cause an initial dip in throughput and stability. https://cloud.google.com/blog/products/devops-sre/announcing-the-2024-dora-report
  - The exact effect sizes (+8% individual productivity, +10% team, −8% throughput, −14% change stability) are **UNVERIFIED**: they are not in the pages fetched.

## 2. Internal developer portals

**Backstage**
- **CNCF Incubating**: accepted 2020-09-08, Incubating since 2022-03-15. No graduation found as of Oct 2026. https://www.cncf.io/projects/backstage/
- Releases are monthly. Latest is **v1.55.3 (2026-09-29)** and v1.56.0-next.1 is in pre-release. The new frontend system is still being rolled through core plugins. https://github.com/backstage/backstage/releases

**Catalog entity model**. https://backstage.io/docs/features/software-catalog/system-model · https://backstage.io/docs/features/software-catalog/descriptor-format
- Core entities:
  - **Component** (a deployable piece of software).
  - **API** ("first class citizen"; visibility public, restricted or private; formats OpenAPI, AsyncAPI, GraphQL, gRPC).
  - **Resource** (runtime infrastructure such as a DB, bucket or topic).
- Organizational entities: **Group** and **User**.
- Ecosystem entities:
  - **System**: components and resources that expose public APIs.
  - **Domain**: a bounded context grouping systems. `spec.subdomainOf` allows nested domains.
- Also: **Template** (scaffolder) and **Location** (a pointer to more catalog data).
- Envelope: `apiVersion`, `kind`, `metadata` (name, namespace, title, description, labels, annotations, tags, links), `spec`.
- Component spec:
  - Required: `type`, `lifecycle` (experimental/production/deprecated), **`owner`**.
  - Optional: `system`, `subcomponentOf`, `providesApis`, `consumesApis`, `dependsOn`, `dependencyOf`.

**Software Templates (scaffolder)**. https://backstage.io/docs/features/software-templates/
- A template is a series of parameterized steps (fetch skeleton → publish to GitHub/GitLab → register in catalog).
- Supports **dry-run testing**.
- The `backstage.io/time-saved` annotation (an ISO-8601 duration) lets you report ROI. https://backstage.io/docs/features/software-catalog/descriptor-format

**TechDocs**. https://backstage.io/docs/features/techdocs/
- Docs-like-code: Markdown lives beside the code and is built with MkDocs.
- The recommended setup is to build in CI and publish to object storage (S3, GCS, Azure, Swift).

**Scorecards**
- The open-source route is **Tech Insights**: fact retrievers + checks → boolean scorecards.
- Built-in retrievers cover entity metadata, ownership and TechDocs presence.
- It now lives in `backstage/community-plugins`. https://www.npmjs.com/package/@backstage-community/plugin-tech-insights-backend
- Spotify's commercial **Soundcheck** can consume Tech Insights facts. https://backstage.spotify.com/docs/plugins/soundcheck/core-concepts/fact-collectors/3p-integrations/techinsights

**Alternatives** (noted only, not benchmarked): Port (https://www.port.io) and Cortex (https://www.cortex.io) are SaaS IDPs with their own catalog and scorecard models.

## 3. Repo management at scale

**Monorepo: primary evidence.** Potvin & Levenberg, "Why Google Stores Billions of Lines of Code in a Single Repository", *CACM* 59(7), 2016. https://research.google/pubs/why-google-stores-billions-of-lines-of-code-in-a-single-repository/ · full text: https://cacm.acm.org/magazines/2016/7/204032-why-google-stores-billions-of-lines-of-code-in-a-single-repository/fulltext
- Scale (Jan 2015):
  - ~1B files, ~2B LOC in 9M source files, 86 TB.
  - ~35M commits; 25k+ developers.
  - ~16k human + 24k automated changes per day.
  - 95% of Google developers use the monorepo.
- Claimed advantages:
  - Unified versioning (one source of truth) and extensive code sharing.
  - Simplified dependency management, which avoids the **diamond dependency** problem.
  - **Atomic changes** and large-scale refactoring.
  - Cross-team collaboration and flexible team boundaries and ownership.
  - Code visibility.
- Costs:
  - Large **tooling investment** (Piper, CitC, Rosie, Critique).
  - Codebase complexity (unnecessary dependencies, discovery).
  - Code-health effort.
- Ownership: every change needs review **plus approval from an owner** of that directory (OWNERS files).
- Trunk-based: development happens at head, release branches are snapshots with cherry-picks, and long-lived branches are "exceedingly rare".
- The authors' own caveat: "not for everyone". It suits open, collaborative cultures and "would not work well" where much of the code is private between groups.
- **Implication**: monorepo vs polyrepo is mostly a tooling and culture decision. Without Google-grade build, code-search and ownership tooling, a polyrepo with strong catalog and ownership metadata is the lower-risk default.

**Ownership metadata in Git**
- GitHub CODEOWNERS:
  - Lives in `.github/`, the root or `docs/` (searched in that order).
  - gitignore-style patterns; the **last match wins**.
  - Owners need write access; the file must be under 3 MB.
  - With "Require review from Code Owners", **any one** owner's approval is enough.
  - Protect the CODEOWNERS file itself.
  - https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners
- Catalog `owner` (Backstage) and CODEOWNERS are complementary: one is the service-level owner, the other is the path-level reviewer.

**Dependency updates**
- **Renovate** (AGPL-3.0; latest 44.x, Oct 2026). https://docs.renovatebot.com/ · https://github.com/renovatebot/renovate/releases
  - Platforms: GitHub, GitLab, Bitbucket, Azure DevOps, Gitea/Forgejo, CodeCommit.
  - Features: shareable presets, monorepo discovery, scheduling, grouping, automerge, Dependency Dashboard, `packageRules`, OSV vulnerability alerts. https://docs.renovatebot.com/configuration-options/
  - **`minimumReleaseAge`** is a dependency cooldown for supply-chain safety. Example: 14 days "allows plenty of time … to catch malicious intent". https://docs.renovatebot.com/key-concepts/minimum-release-age/
- **Dependabot**:
  - Treats **security updates** differently from **version updates**: security PRs don't count toward the default limit of 5 open PRs.
  - `groups` and **`multi-ecosystem-groups`**.
  - **`cooldown`**: 3 days by default for version updates, with per-semver-level overrides.
  - Schedules from daily through yearly, or cron.
  - https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference

**Trunk-based development**
- Definition: work in a single trunk and "resist any pressure to create other long-lived development branches".
- Short-lived feature branches are fine for review and CI.
- Supporting practices: feature flags, branch by abstraction, and either short-lived release branches or release from trunk.
- https://trunkbaseddevelopment.com/
- DORA's practices:
  - **≤3 active branches**.
  - Merge to trunk **at least daily**.
  - **No code freezes or integration phases**.
  - Measure branch count, freeze time, merge frequency and review time.
  - https://dora.dev/capabilities/trunk-based-development/
- DORA documentation-quality data: trunk-based development's performance lift goes from 36% to **1525%** when documentation is above average. https://dora.dev/capabilities/documentation-quality/

## 4. GitOps

**OpenGitOps Principles v1.0.0** (released 2021-10-08). https://opengitops.dev/ · https://github.com/open-gitops/documents/releases
1. **Declarative**: desired state is expressed declaratively.
2. **Versioned and Immutable**: stored with immutability, versioning and full history.
3. **Pulled Automatically**: agents pull desired state from the source.
4. **Continuously Reconciled**: agents observe actual state and apply desired state.

**Engines** (both CNCF Graduated)
- **Argo**: Incubating 2020-03-26, Graduated 2022-12-06. Argo CD latest **v3.5.3 (2026-09-14)**. https://www.cncf.io/projects/argo/
- **Flux**: Graduated 2022-11-30. flux2 latest **v2.9.6 (2026-10-01)**. https://www.cncf.io/projects/flux/
- Flux controllers: source (Git, OCI, Helm, Bucket), kustomize, helm, notification, image-reflector/automation. https://fluxcd.io/flux/components/
- Argo CD best practice: **separate the config repo from the app source repo**. https://argo-cd.readthedocs.io/en/stable/user-guide/best_practices/
  - Reasons: cleaner audit trail, different push rights for prod, no CI loops.
  - **Pin** remote bases and charts to a tag or SHA.

**Progressive delivery**
- **Argo Rollouts** (v1.10.0, 2026-08-27):
  - Blue-green and canary strategies.
  - AnalysisTemplates over Prometheus, Datadog and similar.
  - Weighted traffic via ingress or mesh.
  - Automated promote or rollback.
  - https://argoproj.github.io/argo-rollouts/
- **Flagger** (v1.45.0, 2026-09-01; part of the Flux family):
  - Canary, A/B, blue/green and mirroring.
  - Metric analysis and automated rollback.
  - https://docs.flagger.app/

**Environment promotion** (still the least standardized area)
- **Argo CD Source Hydrator**:
  - **Beta since v3.5.0**; disabled by default.
  - Renders Helm/Kustomize output into a separate "hydrated" branch, so the exact manifests are reviewable.
  - Can write to a `hydrateTo` staging branch, but "will not create a PR or otherwise facilitate moving those changes".
  - https://argo-cd.readthedocs.io/en/stable/user-guide/source-hydrator/
- **GitOps Promoter** (argoproj-labs; **experimental**): promotes via PRs between environment branches, gated by commit statuses. https://github.com/argoproj-labs/gitops-promoter
- **Kargo** (by Akuity): a promotion orchestrator layered on Argo CD (Warehouse → Freight → Stage). https://docs.kargo.io/
  - License and maturity: **UNVERIFIED**.
- Pattern takeaway:
  - Promote **immutable artifacts** (image digest + rendered manifests) through env branches or directories via PRs.
  - Gate on automated checks recorded as commit statuses.
  - Avoid "rebuild per environment".

## 5. Engineering metrics: DORA and SPACE

**Current DORA delivery metrics** (page updated 2026-01-05). https://dora.dev/guides/dora-metrics/
- **Throughput**:
  - Change lead time (commit → production).
  - Deployment frequency.
  - **Failed deployment recovery time**.
- **Instability**:
  - Change fail rate (deployments that need immediate intervention).
  - **Deployment rework rate** (unplanned deployments caused by a production incident).
- History (article dated 2026-01-02). https://dora.dev/insights/dora-metrics-history/
  - 2014–15: four keys.
  - 2018: availability added (SDO performance).
  - 2021: availability broadened to reliability.
  - **2023**: MTTR redefined as *failed deployment recovery time*.
  - **2024**: rework rate added; metrics regrouped into throughput vs instability.

**2024 Accelerate State of DevOps** (2024-10-23). https://cloud.google.com/blog/products/devops-sre/announcing-the-2024-dora-report
- A 25% increase in AI adoption was associated with:
  - +7.5% documentation quality, +3.4% code quality, +3.1% review speed.
  - But **−1.5% throughput and −7.2% stability**.
- 39% of respondents have little or no trust in AI code.
- Unstable priorities raise burnout. https://dora.dev/research/2024/dora-report/

**2025 "State of AI-assisted Software Development"** (2025-09-24; ~5,000 respondents). https://cloud.google.com/blog/products/ai-machine-learning/announcing-the-2025-dora-report · https://dora.dev/research/2025/dora-report/
- 90% use AI at work; 30% have little or no trust in AI output.
- AI is now **positively** related to throughput but **still negatively related to stability**.
- AI is "an amplifier" of existing strengths and weaknesses.
- Value Stream Management is a "force multiplier". https://research.google/pubs/dora-2025-state-of-ai-assisted-software-development-report/
- **Seven team profiles** replace the elite/high/medium/low clusters: Foundational challenges, Legacy bottleneck, Constrained by process, High impact/low cadence, Stable and methodical, Pragmatic performers, Harmonious high-achievers.
  - The profiles come from a cluster analysis over 8 factors: throughput, instability, team performance, product performance, individual effectiveness, valuable work, friction, burnout.
  - The share percentages (10/11/17/7/15/20/20%) come from secondary write-ups and are **UNVERIFIED** against the report PDF.

**DORA AI Capabilities Model** (2025). https://cloud.google.com/blog/products/ai-machine-learning/introducing-doras-inaugural-ai-capabilities-model · https://dora.dev/ai/capabilities-model/
1. Clear and communicated AI stance.
2. Healthy data ecosystems.
3. AI-accessible internal data.
4. Strong version control practices.
5. Working in small batches.
6. User-centric focus.
7. **Quality internal platforms**.

**DORA capability catalog**. https://dora.dev/capabilities/
- Core capabilities include:
  - CI, CD, deployment automation, test automation and test data management.
  - Trunk-based development, version control and small batches.
  - Loosely coupled teams, monitoring & observability, **pervasive security**, **streamlining change approval**.
  - Documentation quality, flexible infrastructure, database change management, code maintainability.
  - Generative culture, well-being, job satisfaction.
- AI-tagged capabilities are listed separately, alongside VSM and visibility of work in the value stream, WIP limits, and others.

**SPACE** (Forsgren, Storey, Maddila, Zimmermann, Houck, Butler; *ACM Queue* 19(1), 2021). https://www.microsoft.com/en-us/research/publication/the-space-of-developer-productivity-theres-more-to-it-than-you-think/
- Five dimensions: **S**atisfaction & well-being, **P**erformance, **A**ctivity, **C**ommunication & collaboration, **E**fficiency & flow.
- Productivity is multidimensional, so don't use activity counts alone.
- The specific guidance to use "at least three dimensions" and mix perceptual with system data is **UNVERIFIED**: the paper text was not retrievable (403).

## 6. FinOps

**FinOps Framework.** https://www.finops.org/framework/
- **2026 update** (2026-03-19). https://www.finops.org/insights/2026-finops-framework/
  - New definition: FinOps "maximizes the business value of technology, enables timely data-driven decision making, and creates financial accountability through collaboration between engineering, finance, and business teams".
  - New capability: **Executive Strategy Alignment**.
  - Renames:
    - Workload Optimization → **Usage Optimization**.
    - Policy & Governance → **Governance, Policy & Risk**.
    - FinOps Tools & Services → **Automation, Tools & Services**.
    - Benchmarking → **KPIs & Benchmarking**.
    - Architecting for Cloud → **Architecting & Workload Placement**.
    - Cloud Sustainability → **Sustainability**.
  - New **Technology Categories**: Public Cloud, SaaS, Data Center, Data Cloud Platforms, AI.
- **2025 update** (2025-03-20). https://www.finops.org/insights/2025-finops-framework/
  - Introduced **Scopes** as a core element, initially Public Cloud, SaaS and Data Center.
  - Added "and technology" to the definition.
  - Changed four principles, the first change since 2019.
  - Dropped "cloud" from the domain names.
- **Scopes (2026 definition)**: "a defined segment of spending across technology categories, aligned to business constructs — such as products, cost centers, or environment".
  - Keep them "few, simple, and purposeful".
  - https://www.finops.org/framework/scopes/
- **Principles** (6): https://www.finops.org/framework/principles/
  1. Teams need to collaborate.
  2. Business value drives technology decisions.
  3. Everyone takes ownership for their technology usage.
  4. FinOps data should be accessible, timely, and accurate.
  5. FinOps should be enabled centrally.
  6. Take advantage of the variable cost model of the cloud.
- **Phases**: Inform → Optimize → Operate. The phases repeat as a loop that teams go through quickly and often. https://www.finops.org/framework/phases/
- **Domains → capabilities**: https://www.finops.org/framework/
  - *Understand Usage & Cost*: Data Ingestion, Allocation, Reporting & Analytics, Anomaly Management.
  - *Quantify Business Value*: Planning & Estimating, Forecasting, Budgeting, KPIs & Benchmarking, Unit Economics.
  - *Optimize Usage & Cost*: Architecting & Workload Placement, Usage Optimization, Rate Optimization, Licensing & SaaS, Sustainability.
  - *Manage the FinOps Practice*: Executive Strategy Alignment, FinOps Practice Operations, Governance Policy & Risk, FinOps Education & Enablement, Invoicing & Chargeback, FinOps Assessment, Automation Tools & Services, Intersecting Disciplines.
- **Personas**: https://www.finops.org/framework/personas/
  - Core: FinOps Practitioner, Engineering, Finance, Product, Procurement, Leadership.
  - Allied: ITAM, ITFM, ITSM/ITIL, Sustainability, Security.
- **Maturity (Crawl / Walk / Run)**. https://www.finops.org/framework/maturity-model/
  - Sample targets:
    - Allocation: ~70% / 85% / 90%+.
    - Commitment coverage: 60% / 75% / 80%+.
    - Forecast variance: 20% / <10% / <5%.
  - Explicit guidance: don't chase "Run" everywhere; business value decides.

**Key capabilities for a platform**
- **Allocation**: https://www.finops.org/framework/capabilities/allocation/
  - Three parts: allocation strategy, **tagging & metadata strategy** (naming, account hierarchy, tag standards), and **shared-cost strategy** (fixed, proportional or proxy split, or "informed ignore").
  - At *Run*: **enforced at provisioning** and near-real-time.
  - KPIs: allocation coverage, unallocated spend, metadata compliance, Allocation Accuracy Index.
- **Showback vs chargeback**: the difference is formality. Chargeback posts to official accounting budgets; showback is "always required". https://www.finops.org/framework/capabilities/invoicing-chargeback/
  - KPIs: GL recharge rate, chargeback accuracy, estimate-vs-actual variance.
- **Anomaly management**: https://www.finops.org/framework/capabilities/anomaly-management/
  - Lifecycle: detect → notify (route to the owner) → investigate → resolve.
  - At *Run*: integrated with ticketing.
  - KPIs: mean time to detect/notify, time unresolved, cost avoidance.
  - Depends on good allocation metadata and clear ownership.
- **Unit economics**: https://www.finops.org/framework/capabilities/unit-economics/
  - Resource-efficiency units: cost per GB, per vCPU, per token.
  - Business units: cost per customer, per transaction, cost to serve.
  - At *Run*: every scope has unit metrics that "influence architectural decisions".
- DORA 2019: teams meeting all essential cloud characteristics were **2.6× more likely to accurately estimate the cost to operate software** and 1.65× as likely to stay under budget. https://dora.dev/publications/pdf/state-of-devops-2019.pdf

**FOCUS specification.** https://focus.finops.org/ · https://focus.finops.org/focus-specification/ · https://github.com/FinOps-Open-Cost-and-Usage-Spec/FOCUS_Spec/releases
- Versions: v1.1 (2024-11), v1.2 (2025-05), v1.3 (2025-12), **v1.4 (ratified 2026-06-04)**. v1.5 is in progress.
- What it normalizes: billing datasets across "AI, cloud, SaaS, data center" vendors. Key concepts:
  - Four cost types: **BilledCost, EffectiveCost, ListCost, ContractedCost**.
  - Billing account and sub-account hierarchy.
  - Service category and subcategory.
  - ResourceId/Name and **Tags**.
  - Commitment discount columns.
  - Allocation columns.
- Per-version additions:
  - 1.2: SaaS/PaaS support and invoice reconciliation. https://www.finops.org/insights/focus-1-2-available/
  - 1.3: **Contract Commitment** dataset (13 columns) and shared-cost **allocation** columns.
  - 1.4: **Invoice Detail** and **Billing Period** datasets; +47 columns; Contract Commitment grown to 30 columns; commitment-eligibility tracking; data-integrity rules for corrections, delivery and completeness.
  - 1.5 (planned): AI token/model columns and a **Price Sheet** dataset.
  - https://www.finops.org/?p=29057
- **Who publishes FOCUS** (per the FOCUS site):
  - v1.3: MongoDB, Vercel, Snowflake, Databricks.
  - v1.2: AWS, Azure, GCP, IBM Cloud, Grafana Cloud, STACKIT, Redis, Nebius.
  - v1.0: Oracle, **Alibaba Cloud**, **Tencent Cloud**, Huawei Cloud, OVHcloud, Cloudflare, CoreWeave.
  - https://focus.finops.org/
- **Tencent Cloud (verified from its own docs)**: https://intl.cloud.tencent.com/document/product/555/67495
  - FOCUS **1.0** bills via **Bill Storage to COS**.
  - The doc says it "may not fully align" with the spec.
  - **CapacityReservationStatus, EffectiveCost, ResourceType, ServiceCategory, SkuId, SkuPriceId are empty**.
  - Doc last updated 2026-03-12.
- **Alibaba Cloud (verified from its own docs)**: https://help.aliyun.com/en/user-center/exporting-alibaba-cloud-focus1-0-preview
  - FOCUS 1.0 in **invitational preview** via Bill Subscription → OSS.
  - Delivered daily, with the monthly final by the 4th.
  - "For analysis only and cannot be used for reconciliation."
- **Tencent cost allocation tags**: https://www.tencentcloud.com/document/product/555/32276
  - Max **15** cost-allocation tag keys (out of 1,000 tag keys).
  - Tags take effect the **next day**.
  - Not retroactive, except via a "traceback" feature covering up to 12 months.

**OpenCost** (CNCF **Incubating** since 2024-10-25; latest v1.121.3, 2026-09-16). https://www.cncf.io/projects/opencost/ · https://www.opencost.io/docs/
- Its spec defines:
  - Asset costs (nodes, PVs, LBs) vs workload allocation.
  - Workload cost = **max(request, usage)**.
  - **Idle** = cluster asset cost − workload cost.
  - Shared costs (system workloads, idle, overhead) split uniformly, proportionally or by a custom metric.
  - Aggregation by container, pod, controller, label, annotation, namespace or cluster.
  - https://www.opencost.io/docs/specification

**Shift-left cost**: **Infracost** (CLI v0.10.46, 2026-09-25). https://www.infracost.io/docs/
- Shows a cost diff on the PR for Terraform, OpenTofu, CloudFormation and CDK.
- Adds tagging and FinOps policy checks.
- Docs list **AWS, Azure, GCP only**. Tencent and Alibaba are not mentioned, so treat them as unsupported.

## 7. Architecture Decision Records and change records

**Nygard, "Documenting Architecture Decisions"** (2011-11-15). https://www.cognitect.com/blog/2011/11/15/documenting-architecture-decisions
- Sections: Title, Context ("forces at play"), Decision ("We will …"), Status, Consequences (positive and negative).
- Status values: proposed, accepted, deprecated, superseded.
- Numbered sequentially and **never reused**. Reversed decisions stay in place, marked superseded with a link to the replacement.
- Stored in the repo (`doc/arch/adr-NNN.md`) and kept to one or two pages.

**MADR 4.0.0** (2024-09-17; current per GitHub releases). https://adr.github.io/madr/ · https://github.com/adr/madr/releases
- Sections:
  - Context & Problem Statement.
  - Decision Drivers *(optional)*.
  - Considered Options.
  - Decision Outcome.
  - Consequences *(opt)*, **Confirmation** *(opt: how compliance is checked)*, Pros/Cons of Options *(opt)*, More Information *(opt)*.
- Front matter: `status` (proposed / rejected / accepted / deprecated / superseded), `date`, **`decision-makers`, `consulted`, `informed`** (RACI-like).
- File naming `NNNN-title-with-dashes.md` in `docs/decisions/`.
- Dual-licensed MIT/CC0.

**adr.github.io** defines AD, ADR, ASR, decision log and AKM, and lists templates (Nygard, Y-statements, MADR, …) and tooling. https://adr.github.io/

**Tooling**
- **Log4brains**: static-site ADR knowledge base. https://github.com/thomvaill/log4brains
  - MADR-based, with `adr new` CLI, timeline, search, monorepo support, and metadata extracted from git.
  - Last release v1.1.0 (2024-12-17), so maintenance is slow.
- **adr-tools**: shell CLI; last push 2024-04. https://github.com/npryce/adr-tools

**Change management evidence (DORA)**
- 2019 report:
  - Formal approval by an external body (CAB or senior manager) has a negative impact on delivery performance. Respondents were "**2.6 times more likely to be low performers**".
  - There was "**no evidence**" that formal approval lowers change fail rate.
  - Heavier approval leads to larger, less frequent batches and therefore higher risk.
  - A **clearly understood** process drives high performance.
  - https://dora.dev/publications/pdf/state-of-devops-2019.pdf
- DORA's recommendations:
  - Meet **segregation of duties via peer review**, with "reviews, comments, and approvals captured in the team's development platform".
  - Automate detection and rollback.
  - Turn the CAB into an advisor and coordinator.
  - https://dora.dev/capabilities/streamlining-change-approval/
- **Implication**: the platform's activity log *is* the change record. PR approvals, pipeline evidence and deploy events, linked together, replace CAB tickets for standard changes.

## 8. Security on the paved road: "shift down"

- **Google, Christoph Kern, "Developer Ecosystems for Software Safety"** (*ACM Queue* 22, 2024). https://research.google/pubs/developer-ecosystems-for-software-safety/
  - Safety is an **emergent property of the developer ecosystem**: languages, libraries, frameworks, build, deploy, the production platform and its configuration.
  - Responsibility for security invariants belongs in that ecosystem, not on individual developers.
  - Result: "drastic reduction and in some cases near-zero residual rates of common classes of defects" across hundreds of apps and thousands of developers.
- **Google, Safe Coding / memory safety**: Android memory-safety vulnerabilities fell from **76% to 24%** over 6 years as new code moved to memory-safe languages. https://security.googleblog.com/2024/09/eliminating-memory-safety-vulnerabilities-Android.html
- **"Shift down"** (Richard Seroter, Google Cloud, 2023-06-09):
  - Instead of piling more on developers ("shift left" over-extended), push the work *down* into platforms and opinionated managed services.
  - Example: Cloud Build emitting SLSA attestations by default.
  - https://cloud.google.com/blog/products/application-development/richard-seroter-on-shifting-down-vs-shifting-left
  - Google Cloud frames IDPs the same way. https://cloud.google.com/solutions/platform-engineering
- **Netflix "The Show Must Go On: Securing Netflix Studios At Scale"** (2021-09-13; Fernandez, Gonigberg, Knecht, Thomas). https://netflixtechblog.com/the-show-must-go-on-securing-netflix-studios-at-scale-19b801c86479
  - **Wall-E** is a Zuul-based gateway with an SSO filter on every request, which **guarantees authentication** for services behind it.
  - WAF, DDoS protection, security headers and durable logging were added as filters. Checklist items moved from "app developer-owned" to "Wall-E owned".
  - The internet-facing checklist "boiled down to … 'Will you use Wall-E?'".
  - The paved road turns security questions into a **boolean**: "Are you using this paved road product?"
  - Result: from `git init` to a production-ready, authenticated, internet-facing app in **under 10 minutes**, saving days or weeks of security review per app.
- **DORA pervasive security**: https://dora.dev/capabilities/pervasive-security/
  - Build **InfoSec-pre-approved libraries and tools**.
  - Automate security tests in CI.
  - Involve security at design time.
  - High performers spend **50% less time remediating** security issues.
  - Measure adoption of pre-approved tools.
- CNCF lists "Secure by default" as a platform attribute (§1).

---

## Implications for our platform (ordered by value)

1. **Ownership-first catalog as the system of record.**
   - Every repo and deployable needs a Backstage-compatible descriptor (`kind`, `owner`, `system`, `lifecycle`, `providesApis`/`dependsOn`) plus CODEOWNERS.
   - Block repo creation, and flag existing repos, that lack an owner.
   - Allocation, anomaly routing, security findings, ADRs and the activity log all key off this same owner/system ID. Use Backstage's vocabulary even if we don't run Backstage.
2. **Unified, append-only activity log as the change record.**
   - Link each event to the actor, repo/system, and the PR/approval/pipeline run: commit, PR review and approval, pipeline run, policy decision, deploy, promotion, rollback, permission change, cost anomaly, ADR status change.
   - This satisfies segregation of duties via peer review (DORA) and replaces CAB tickets for standard changes.
   - Make the approval process **visible and explicit**: DORA 2019 says a clear process alone improves performance.
3. **Paved-road templates with security "shifted down".**
   - Scaffolder templates create: repo + CI + Renovate/Dependabot config (with cooldown/`minimumReleaseAge`) + CODEOWNERS + catalog file + `docs/decisions/` with a MADR template + TechDocs + mandatory cost-allocation tags.
   - Security controls (SSO-at-gateway, SAST/SCA, signing/SLSA provenance, secrets) live in the platform. The compliance question becomes "on the paved road? yes/no", as with Netflix Wall-E.
   - Paths stay optional but supported (Spotify).
   - Record `time-saved` per template to show ROI.
4. **DORA five-metric dashboard derived from events, not surveys.**
   - Lead time, deploy frequency, failed-deployment recovery time, change fail rate, rework rate.
   - Rework rate needs an event tag that links a deploy to a triggering incident, so design the deploy-event schema for this now.
   - Add trunk-health metrics: active branches ≤3, daily merge rate, review latency.
   - Pair with lightweight SPACE/CSAT pulse surveys. Do not rank individuals.
5. **FOCUS-native cost ingestion.**
   - Normalize every bill to the FOCUS schema, targeting 1.2+ semantics, with an adapter layer.
   - **Tencent's FOCUS 1.0 leaves EffectiveCost and ServiceCategory empty**, so the adapter must derive them, e.g. from Tencent's native bill and a service map. Store `x_`-prefixed vendor columns.
   - Alibaba's FOCUS is preview-only and not reconcilable.
   - Track the FOCUS version per source.
6. **Allocation and tag governance enforced at provisioning.**
   - Policy-as-code that requires the owner, system, env and cost-center tags on IaC PRs. This is FinOps *Run*-level allocation.
   - Design around **Tencent's 15 cost-allocation-tag limit and next-day activation**.
   - Report allocation coverage and unallocated spend as KPIs.
   - For Kubernetes, use OpenCost (max(request, usage), idle and shared-cost split) mapped to the same owner/system tags.
7. **Showback by default; chargeback optional later.**
   - Per-team and per-system showback views with unit-economics hooks (cost per tenant, per request, per token). Chargeback needs Finance/GL integration, so defer it.
   - Model FinOps **Scopes** as business constructs (product, cost center, environment) over technology categories (Public Cloud, SaaS, AI).
8. **Cost anomaly detection routed to owners.**
   - Detect → notify the owning team (from the catalog) → investigate → resolve, with a ticket.
   - Track mean time to detect, time unresolved, and cost avoided.
9. **Shift-left cost on PRs.**
   - Show a cost diff on IaC PRs. Infracost covers AWS/Azure/GCP only, so Tencent needs our own price lookup (Tencent pricing API) or a coarse estimate.
   - Start with tag and policy checks, which are cloud-agnostic, before price diffs.
10. **ADRs as first-class, linked artifacts.**
    - MADR 4.0 files in `docs/decisions/NNNN-*.md`, indexed by the platform.
    - Status lifecycle: proposed → accepted/rejected → deprecated/superseded, with immutable supersede links.
    - Use `decision-makers`/`consulted`/`informed` for notifications.
    - ADR status changes go to the activity log, and ADRs link to the systems they govern in the catalog.
    - Use MADR's "Confirmation" section to attach an automated check where possible.
11. **GitOps delivery with PR-based promotion.**
    - Separate config repo(s), pinned refs, Argo CD or Flux reconciliation.
    - Promote immutable digests through environments via PRs gated by commit statuses.
    - Treat Source Hydrator (beta) and GitOps Promoter (experimental) as patterns to follow, not yet dependencies.
    - Add progressive delivery (Argo Rollouts or Flagger) later, once metrics exist.
12. **Run the platform as a product with maturity self-assessment.**
    - Use CNCF's five aspects (investment, adoption, interfaces, operations, measurement) as a quarterly scorecard.
    - Scorecards on catalog entities, Tech-Insights style: has owner, has docs, has ADR dir, on the paved road, deps fresh.
    - Avoid DORA's anti-patterns, especially ticket-ops and big-bang launches.
    - Start with a thinnest viable platform covering the single most common workflow.
