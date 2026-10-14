// Command keel-api serves the Keel control-plane API.
//
// Environment:
//
//	KEEL_ADDR           listen address (default :8080)
//	KEEL_DATABASE_URL   Postgres URL for the application role (keel_app)
//	KEEL_MIGRATE_URL    optional Postgres URL for the owner role; if set, migrations run at start
//	KEEL_BASE_URL       Keel's external URL (OIDC callback = KEEL_BASE_URL/auth/callback)
//	KEEL_COOKIE_KEY     base64 32-byte key for the login-state cookie
//	KEEL_INSECURE_COOKIES=1  drop the Secure flag (local http only)
//	KEEL_ENV            "dev" enables KEEL_DEV_PRINCIPAL
//	KEEL_DEV_PRINCIPAL  JSON Principal every request is authenticated as (dev only)
//
// Identity-provider client secrets are read from the environment variable
// named by each provider's client_secret_ref.
//
//	KEEL_DIGEST_KEY     base64 32-byte Ed25519 seed; enables hourly Activity Log sealing
//	KEEL_ARCHIVE_BUCKET   bucket for the WORM Activity Log archive (with KEEL_DIGEST_KEY)
//	KEEL_ARCHIVE_PROVIDER aws (default; S3 Object Lock, ADR-0019) | tencent (existing COS archives)
//	KEEL_ARCHIVE_REGION   bucket region, e.g. ap-southeast-1 (aws) or ap-bangkok (tencent)
//	KEEL_ARCHIVE_ENDPOINT tencent: e.g. cos.ap-bangkok.myqcloud.com; aws: optional, default s3.<region>.amazonaws.com
//	KEEL_ARCHIVE_RETENTION_DAYS  aws: COMPLIANCE retention per object, default 2555 (7 years), minimum 365
//	                    credentials are keyless: aws web identity or instance role; tencent STS
//	KEEL_TENCENT_BILL_BUCKET   COS bucket where the payer's Bill Storage delivers FOCUS bills
//	KEEL_TENCENT_BILL_PREFIX   object prefix of the FOCUS bill files
//	KEEL_TENCENT_PAYER_UIN     payer account id (FOCUS BillingAccountId)
//	KEEL_TENCENT_BILL_ROLE     name of the payer CAM role Keel's base identity assumes for bill sync and invoices
//	KEEL_TENCENT_BILL_MODE     per-day (default) | cumulative (daily FOCUS files are month-to-date); confirm on first delivery
//	KEEL_TENCENT_REGION        region for billing API and COS (default ap-bangkok)
//	                           client payers (ADR-0018) are data, not env: client_payers rows on client-owned Cloud Accounts
//	KEEL_AWS_BILL_BUCKET      S3 bucket of the AWS Data Exports FOCUS 1.2 export (CSV)
//	KEEL_AWS_BILL_PREFIX      export prefix
//	KEEL_AWS_PAYER_ACCOUNT    management account id (FOCUS BillingAccountId)
//	KEEL_AWS_REGION           bucket region; credentials: AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE
//	                          client management accounts (ADR-0018) are data: client_payers rows, read through each client's role
//	KEEL_TENCENT_BUDGETS=1    mirror opted-in Budgets to Tencent Cloud budgets (payer credentials)
//	KEEL_AWS_BUDGET_ACCOUNT   mirror opted-in Budgets to AWS Budgets in this management account
//	KEEL_AWS_BUDGET_EMAIL     optional subscriber so AWS budgets also carry the thresholds
//	KEEL_PROMETHEUS     cluster=url[@tenant/project/env][,…]: per-container utilisation for rightsizing
//	KEEL_TENCENT_MEMBER_ROLE  role Keel assumes in member accounts to read Cloud Monitor (CVM utilisation)
//	KEEL_AWS_COH=1      import AWS Cost Optimization Hub recommendations (management account, web identity)
//	KEEL_WASTE_CLEANUP=1      allow deleting waste in opted-in non-prod Environments after the grace period
//	KEEL_WASTE_GRACE_DAYS     days a waste recommendation must stay open first (default 7)
//	KEEL_OPENCOST       cluster=url[,cluster=url]: per-namespace daily cost for k8s allocation rules
//	KEEL_GITHUB_OWNER   user/org whose repos' catalog-info.yaml are synced every 10 min; enables Keel's GitHub
//	                    integrations: catalog sync, decision index, governance, alert sync (Dependabot, secret and
//	                    code scanning, every 6h), Service Templates, and rightsizing, admission-policy and promotion PRs
//	KEEL_GITHUB_ORG=1   KEEL_GITHUB_OWNER is an organisation
//	KEEL_GITHUB_WEBHOOK_SECRET  signs the organisation webhook at POST /v1/webhooks/github: secret-scanning
//	                    alerts, and governance events when KEEL_GITHUB_OWNER is an organisation
//	KEEL_GITHUB_WEBHOOK_HOOK_ID  id of that webhook; every 15 min Keel asks GitHub to redeliver the failed deliveries
//	                    of the last 24h
//	KEEL_GITHUB_APP_ID, KEEL_GITHUB_APP_INSTALLATION_ID, KEEL_GITHUB_APP_PRIVATE_KEY (PEM)  the GitHub App and its
//	                    installation on KEEL_GITHUB_OWNER, required by every GitHub integration (ADR-0020). Each
//	                    caller mints its own one-hour installation token with only its permissions (#231)
//	KEEL_PDPA_REGIONS   default data region set for Tenants with no PDPA settings (default ap-bangkok,ap-southeast-7)
//	KEEL_DB_REGION      region of Keel's Postgres; unset, each PDPA residency run reports the database as not checked; see docs/runbooks/deploy-regions.md
//	KEEL_GCP_BILL_BUCKET_REGION    region of KEEL_GCP_BILL_BUCKET; required with it (PDPA residency)
//	KEEL_AZURE_BILL_EXPORT_REGION  region of the KEEL_AZURE_BILL_STORAGE_ACCOUNT holding the bill export; required with KEEL_AZURE_BILL_CONTAINER
//	KEEL_TENCENT_ORG_REGION  enables Tencent organisation discovery (e.g. ap-bangkok);
//	                    credentials: TKE pod identity or CVM role (env keys only with KEEL_ENV=dev)
//
// Subcommands:
//
//	keel-api digest-pubkey                 print the public key for KEEL_DIGEST_KEY
//	keel-api verify-log -tenant ID -pubkey BASE64[,BASE64...]
//	keel-api verify-archive -tenant ID -pubkey BASE64[,BASE64...]   (needs KEEL_ARCHIVE_*)
//
//	keel-api bootstrap -slug harmonyx -name HarmonyX -issuer URL -client-id ID \
//	    -client-secret-ref ENV_NAME -admin-group keel-admins [-email-domain harmonyx.co]
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	awscreds "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/riverqueue/river"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/access"
	"github.com/hx-thanadej/keel/internal/admission"
	"github.com/hx-thanadej/keel/internal/anomaly"
	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/apply"
	"github.com/hx-thanadej/keel/internal/archive"
	"github.com/hx-thanadej/keel/internal/attest"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/boundary"
	"github.com/hx-thanadej/keel/internal/breakglass"
	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/catalogsync"
	"github.com/hx-thanadej/keel/internal/ciidentity"
	"github.com/hx-thanadej/keel/internal/clientreads"
	"github.com/hx-thanadej/keel/internal/cloud/alibaba"
	awsadapter "github.com/hx-thanadej/keel/internal/cloud/aws"
	"github.com/hx-thanadej/keel/internal/cloud/azure"
	"github.com/hx-thanadej/keel/internal/cloud/gcp"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/controls"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/decisions"
	"github.com/hx-thanadej/keel/internal/discovery"
	"github.com/hx-thanadej/keel/internal/dora"
	"github.com/hx-thanadej/keel/internal/evidence"
	"github.com/hx-thanadej/keel/internal/exceptions"
	"github.com/hx-thanadej/keel/internal/findings"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/fx"
	"github.com/hx-thanadej/keel/internal/ghalerts"
	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/githubgov"
	"github.com/hx-thanadej/keel/internal/integrity"
	"github.com/hx-thanadej/keel/internal/landingzone"
	"github.com/hx-thanadej/keel/internal/leaks"
	"github.com/hx-thanadej/keel/internal/maturity"
	"github.com/hx-thanadej/keel/internal/oidcauth"
	"github.com/hx-thanadej/keel/internal/pdpa"
	"github.com/hx-thanadej/keel/internal/pipelineauth"
	"github.com/hx-thanadej/keel/internal/promotion"
	"github.com/hx-thanadej/keel/internal/registry"
	"github.com/hx-thanadej/keel/internal/reports"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/sbom"
	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/scorecard"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/templates"
	"github.com/hx-thanadej/keel/internal/utilisation"
	"github.com/hx-thanadej/keel/internal/vending"
	"github.com/hx-thanadej/keel/internal/vex"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		cmds := map[string]func([]string) error{"bootstrap": bootstrap, "digest-pubkey": digestPubkey, "verify-log": verifyLog, "verify-archive": verifyArchive, "verify-evidence": verifyEvidence}
		if cmd, ok := cmds[os.Args[1]]; ok {
			if err := cmd(os.Args[2:]); err != nil {
				slog.Error(os.Args[1], "err", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		slog.Error("keel-api", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := envOr("KEEL_ADDR", ":8080")
	deps, cleanup, err := buildDeps(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.NewRouter(api.Info{Version: version}, deps),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("keel-api listening", "addr", addr, "version", version, "catalog", deps.Catalog != nil)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func buildDeps(ctx context.Context) (api.Deps, func(), error) {
	noop := func() {}
	dbURL := os.Getenv("KEEL_DATABASE_URL")
	if dbURL == "" {
		slog.Warn("KEEL_DATABASE_URL not set; serving /healthz only")
		return api.Deps{}, noop, nil
	}
	if u := os.Getenv("KEEL_MIGRATE_URL"); u != "" {
		if err := store.Migrate(ctx, u); err != nil {
			return api.Deps{}, noop, err
		}
	}
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return api.Deps{}, noop, err
	}
	az, err := authz.New()
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	st := store.New(pool)
	githubHTTP := &http.Client{Timeout: 30 * time.Second}
	app, err := githubApp(githubHTTP)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	var gh *githubTokens
	if app != nil {
		gh = newGitHubTokens(*app, os.Getenv("KEEL_GITHUB_ORG") == "1", os.Getenv("KEEL_GITHUB_REMEDIATE") == "1", os.Getenv("KEEL_REUSABLE_WORKFLOW") != "")
	}
	deps := api.Deps{Catalog: catalog.New(st, az), Discovery: map[string]discovery.Source{},
		Cost:    &api.CostDeps{Authz: az, Queries: cost.Queries{Store: st}, Ingester: &cost.Ingester{Store: st}, Rules: cost.Rules{Store: st}},
		Budgets: &api.BudgetDeps{Authz: az, Budgets: budget.Service{Store: st}}}
	deps.Budgets.Catalog = deps.Catalog
	deps.Authz = az
	deps.Rightsize = &api.RightsizeDeps{Authz: az, Service: rightsize.Service{Store: st}}
	if gh != nil {
		deps.Rightsize.Applier = &apply.Applier{Recs: rightsize.Service{Store: st}, Git: apply.GitHub{Client: gh.rightsizing.Client(githubHTTP)}}
	}
	promoSvc := promotion.Service{Store: st, PathTemplate: os.Getenv("KEEL_PROMOTION_PATH"), AppTemplate: os.Getenv("KEEL_ARGOCD_APP"),
		RequireVSA: os.Getenv("KEEL_REQUIRE_VSA") != "0"}
	att, err := attestService(st)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	deps.Attest = &api.AttestDeps{Authz: az, Service: att}
	reg, err := controls.Load()
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	deps.Controls = &api.ControlDeps{Authz: az, Service: controls.Service{Store: st, Registry: reg}}
	evKey, err := digestKey()
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	pdpaStores, err := pdpa.PlatformStores(os.Getenv)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	pdpaSvc := pdpa.Service{Store: st, Regions: strings.FieldsFunc(os.Getenv("KEEL_PDPA_REGIONS"), func(r rune) bool { return r == ',' }), Stores: pdpaStores}
	deps.PDPA = &api.PDPADeps{Authz: az, Service: pdpaSvc}
	deps.Evidence = &api.EvidenceDeps{Authz: az, Exporter: evidence.Exporter{Store: st, Controls: controls.Service{Store: st, Registry: reg}, PDPA: pdpaSvc, Key: evKey}}
	go every(ctx, 15*time.Minute, "PDPA breach clock", func(ctx context.Context) error {
		n, err := pdpaSvc.RunClock(ctx)
		if err == nil && n > 0 {
			slog.Warn("PDPA breach clock advanced", "breaches", n)
		}
		return err
	})
	go daily(ctx, "PDPA residency", func(ctx context.Context) error {
		_, err := pdpaSvc.RunResidency(ctx)
		return err
	})
	go daily(ctx, "PDPA retention", func(ctx context.Context) error {
		_, err := pdpaSvc.RunRetention(ctx)
		return err
	})
	if os.Getenv("KEEL_KEV") != "0" {
		cra := evidence.CRA{Store: st, KEV: evidence.CISAKEV{URL: os.Getenv("KEEL_KEV_URL")}}
		go every(ctx, 6*time.Hour, "CRA clock", func(ctx context.Context) error {
			n, err := cra.Run(ctx)
			if err == nil && n > 0 {
				slog.Warn("CRA reporting clock started", "vulnerabilities", n)
			}
			return err
		})
	}
	deps.VEX = &api.VEXDeps{Authz: az, Service: vex.Service{Store: st}, Author: os.Getenv("KEEL_BASE_URL")}
	deps.SBOM = &api.SBOMDeps{Authz: az, Service: sbom.Service{Store: st}, Releases: att}
	if os.Getenv("KEEL_OSV") != "0" {
		m := sbom.Matcher{Store: st, OSV: sbom.OSVClient{BaseURL: os.Getenv("KEEL_OSV_URL")}, Tenants: func(ctx context.Context) ([]string, error) {
			rows, err := st.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
			if err != nil {
				return nil, err
			}
			return pgx.CollectRows(rows, pgx.RowTo[string])
		}}
		go daily(ctx, "osv re-match", func(ctx context.Context) error {
			res, err := m.Run(ctx)
			if err == nil {
				slog.Info("osv re-match", "components", res.Components, "raised", res.Raised, "resolved", res.Resolved)
			}
			return err
		})
	}
	adm := admission.Service{Store: st, Registry: os.Getenv("KEEL_TCR_DOMAIN"), BuilderSubject: os.Getenv("KEEL_TRUSTED_BUILDER") + "*", RekorURL: os.Getenv("KEEL_REKOR_URL")}
	if gh != nil {
		adm.Git = apply.GitHub{Client: gh.admission.Client(githubHTTP)}
	}
	deps.Admission = &api.AdmissionDeps{Authz: az, Service: adm}
	if adm.Git != nil && adm.Registry != "" && os.Getenv("KEEL_TRUSTED_BUILDER") != "" {
		go every(ctx, time.Hour, "admission policies", func(ctx context.Context) error {
			res, err := adm.Reconcile(ctx)
			if err == nil && res.PRs > 0 {
				slog.Info("admission policies proposed", "prs", res.PRs)
			}
			return err
		})
	}
	if gh != nil {
		promoSvc.Git = apply.GitHub{Client: gh.promotion.Client(githubHTTP)}
	}
	if u := os.Getenv("KEEL_ARGOCD_URL"); u != "" {
		promoSvc.Argo = promotion.ArgoCD{BaseURL: u, Token: os.Getenv("KEEL_ARGOCD_TOKEN")}
	}
	promo, err := promotion.New(promoSvc)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	deps.Promotion = &api.PromotionDeps{Authz: az, Service: promo}
	deps.DORA = &api.DORADeps{Authz: az, Service: dora.Service{Store: st}}
	deps.Scorecards = &api.ScorecardDeps{Authz: az, Service: scorecard.Service{Store: st}}
	// Monthly Tenant reports (#152), generated by an hourly River job.
	rep := reports.Service{Store: st, Budgets: budget.Service{Store: st}, DORA: dora.Service{Store: st},
		Savings: rightsize.Tracker{Service: rightsize.Service{Store: st}}}
	deps.Reports = &api.ReportDeps{Authz: az, Service: rep}
	// Quarterly maturity self-assessment (#154) and its reminder.
	mat := maturity.Service{Store: st, DORA: dora.Service{Store: st}}
	deps.Maturity = &api.MaturityDeps{Authz: az, Service: mat}
	go daily(ctx, "maturity reminder", func(ctx context.Context) error {
		n, err := mat.Remind(ctx)
		if n > 0 {
			slog.Info("maturity reminders", "opened", n)
		}
		return err
	})
	go daily(ctx, "scorecard snapshot", func(ctx context.Context) error {
		n, err := scorecard.Service{Store: st}.Snapshot(ctx)
		if err == nil {
			slog.Info("scorecards", "services", n)
		}
		return err
	})
	go every(ctx, 2*time.Minute, "promotion sync", func(ctx context.Context) error {
		res, err := promo.Sync(ctx)
		if err == nil && res != (promotion.SyncResult{}) {
			slog.Info("promotion sync", "merged", res.Merged, "closed", res.Closed, "deployed", res.Deployed)
		}
		return err
	})
	go daily(ctx, "finding SLA", func(ctx context.Context) error {
		res, err := findings.SLA{Store: st}.Run(ctx)
		if err == nil {
			slog.Info("finding SLA", "dated", res.Dated, "overdue", res.Overdue, "unowned", res.Unowned)
		}
		return err
	})
	evaluator := budget.Evaluator{Service: budget.Service{Store: st}}
	go fxLoop(ctx, st)
	if err := startUtilisation(ctx, st, deps.Rightsize.Applier); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	if err := startOpenCost(ctx, st); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	go evaluateLoop(ctx, evaluator)
	if err := startMirrors(ctx, st); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	if region := os.Getenv("KEEL_TENCENT_ORG_REGION"); region != "" {
		deps.Discovery["tencent"] = tencent.OrgSource{Region: region, Creds: tencent.Credentials()}
	}
	if gh != nil {
		gov := githubgov.Reconciler{Store: st, Policy: githubPolicy(), Remediate: os.Getenv("KEEL_GITHUB_REMEDIATE") == "1",
			API: githubgov.GitHub{Client: ghapi.Client{HTTP: gh.governance.Client(githubHTTP)}, Login: app.Owner, Org: os.Getenv("KEEL_GITHUB_ORG") == "1"}}
		go every(ctx, time.Hour, "github governance", func(ctx context.Context) error {
			rep, err := gov.Run(ctx)
			if err == nil {
				slog.Info("github governance", "plan", rep.Plan, "mode", rep.Mode, "repos", rep.Repos, "drift", len(rep.Items))
			}
			return err
		})
	}
	if gh != nil {
		alerts := ghalerts.Syncer{Store: st, Source: ghalerts.GitHub{Client: ghapi.Client{HTTP: gh.alerts.Client(githubHTTP)}}}
		go every(ctx, 6*time.Hour, "github alert sync", func(ctx context.Context) error {
			res, err := alerts.Run(ctx)
			if err != nil {
				return err
			}
			limited := 0
			for _, s := range res.Statuses {
				for _, status := range []string{s.CodeScanning, s.Dependabot, s.SecretScanning} {
					if status != ghalerts.StatusOK && status != ghalerts.StatusKeel {
						limited++
					}
				}
			}
			slog.Info("github alerts", "services", res.Services, "raised", res.Raised, "resolved", res.Resolved, "unavailable_alert_types", limited)
			return nil
		})
	}
	if gh != nil {
		ix := decisions.Indexer{Store: st, Source: decisions.GitHub{Client: ghapi.Client{HTTP: gh.decisions.Client(githubHTTP)}}}
		go every(ctx, 6*time.Hour, "decision index", func(ctx context.Context) error {
			res, err := ix.Run(ctx)
			if err == nil && res.Changed > 0 {
				slog.Info("decision records", "services", res.Services, "records", res.Records, "changed", res.Changed)
			}
			return err
		})
	}
	if gh != nil {
		syncer := &catalogsync.Syncer{Store: st, Source: &catalogsync.GitHub{Owner: app.Owner, Org: os.Getenv("KEEL_GITHUB_ORG") == "1", Client: gh.catalog.Client(githubHTTP)}}
		go syncer.Every(ctx, 10*time.Minute)
	}
	if err := startBillSync(ctx, st, evaluator); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	go clientBillSyncLoop(ctx, evaluator, clientBillSyncs(ctx, st, ""), clientReads(ctx, st))
	if err := startAWSBillSync(ctx, st, evaluator); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	if err := startMultiCloudBillSync(ctx, st, evaluator); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	if err := startSealer(ctx, st); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	vendors := vendors(ctx, st)
	creator, err := templateCreator(st, gh, githubHTTP)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	defs := flowDefs(vendors)
	if creator != nil {
		defs = append(defs, creator.Def())
	}
	var dir access.Directory
	if zone, region := os.Getenv("KEEL_CIC_ZONE_ID"), os.Getenv("KEEL_TENCENT_ORG_REGION"); zone != "" && region != "" {
		dir = tencent.IdentityCenter{API: tencent.NewOrgAPI(region, tencent.Credentials()), ZoneID: zone}
	}
	acc, err := access.New(st, dir)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	deps.Access = &api.AccessDeps{Authz: az, Service: acc}
	bg := breakglass.Service{Store: st}
	deps.BreakGlass = &api.BreakGlassDeps{Authz: az, Service: bg, Home: func(r *http.Request) (string, error) {
		var h *string
		if err := st.AppPool().QueryRow(r.Context(), `SELECT home_tenant_id()::text`).Scan(&h); err != nil || h == nil {
			return "", errors.Join(errors.New("no home tenant"), err)
		}
		return *h, nil
	}}
	if region := os.Getenv("KEEL_TENCENT_ORG_REGION"); region != "" {
		accessRole := envOr("KEEL_TENCENT_VENDING_ROLE", "OrganizationAccessControlRole")
		bg.Audit = func(account string) (breakglass.Audit, error) {
			// The organisation admin account is read with Keel's own role; members through the access role.
			var creds common.Provider = keelRole(st, tencent.Credentials(), account, accessRole, region)
			if account == os.Getenv("KEEL_TENCENT_ORG_ADMIN_UIN") {
				creds = tencent.Credentials()
			}
			return tencent.NewCloudAudit(region, creds)
		}
		deps.BreakGlass.Service = bg
		go every(ctx, time.Hour, "break-glass watch", func(ctx context.Context) error {
			res, err := bg.Watch(ctx, 2*time.Hour)
			if err == nil && (res.Uses > 0 || res.DrillsOverdue > 0) {
				slog.Warn("break-glass", "uses", res.Uses, "drills_overdue", res.DrillsOverdue)
			}
			return err
		})
		standing := access.Standing{Store: st, Directory: dir, BreakGlass: bg.Names, Users: func(account string) (access.Users, error) {
			return tencent.NewCAMUsers(keelRole(st, tencent.Credentials(), account, accessRole, region))
		}}
		go daily(ctx, "standing access", func(ctx context.Context) error {
			res, err := standing.Run(ctx)
			if err == nil {
				slog.Info("standing production access", "accounts", res.Accounts, "standing", res.Standing, "excused", res.Excused)
			}
			return err
		})
	}
	lk := &leaks.Service{Store: st, WebhookSecret: []byte(os.Getenv("KEEL_GITHUB_WEBHOOK_SECRET")), Keys: map[string]leaks.Keys{}}
	if gh != nil {
		lk.Alerts = leaks.GitHubAlerts{Client: ghapi.Client{HTTP: gh.leaks.Client(githubHTTP)}}
	}
	if region := os.Getenv("KEEL_TENCENT_ORG_REGION"); region != "" {
		accessRole := envOr("KEEL_TENCENT_VENDING_ROLE", "OrganizationAccessControlRole")
		lk.Keys["tencent"] = tencent.AccessKeys{API: func(account string) (tencent.KeyAPI, error) {
			return tencent.NewKeyAPI(keelRole(st, tencent.Credentials(), account, accessRole, region))
		}}
	}
	if len(lk.WebhookSecret) > 0 {
		deps.Webhooks = &api.WebhookDeps{Leaks: lk}
		if owner := os.Getenv("KEEL_GITHUB_OWNER"); owner != "" && os.Getenv("KEEL_GITHUB_ORG") == "1" {
			deps.Webhooks.Governance = &githubgov.Receiver{Store: st, Owner: owner, Policy: githubPolicy()}
			if err := startWebhookCatchup(ctx, st, owner, gh.catchup, githubHTTP); err != nil {
				pool.Close()
				return api.Deps{}, noop, err
			}
		}
	}
	excs := exceptions.New(st)
	engine, stopJobs, err := startFlows(ctx, st, defs, excs, acc, lk, rep)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	deps.Flows = &api.FlowDeps{Authz: az, Engine: engine}
	deps.Exception = &api.ExceptionDeps{Authz: az, Service: excs}
	deps.Scans = &api.ScanDeps{Authz: az, Service: scans.Service{Store: st}}
	deps.Registry = &api.RegistryDeps{Authz: az, Store: st, Domain: os.Getenv("KEEL_TCR_DOMAIN")}
	if id := os.Getenv("KEEL_TCR_REGISTRY_ID"); id != "" {
		if tcrAPI, err := tencent.NewTCR(envOr("KEEL_TENCENT_REGION", "ap-bangkok"), tencent.Credentials()); err != nil {
			slog.Error("tcr client", "err", err)
		} else {
			deps.Registry.Broker = tencent.Registry{API: tcrAPI, RegistryID: id}
		}
	}
	if creator != nil {
		deps.Templates = &api.TemplateDeps{Authz: az, Engine: engine, Creator: *creator}
	}
	deps.Vending = &api.VendingDeps{Authz: az, Engine: engine, Vendors: vendors}
	cleanup := func() { stopJobs(); pool.Close() }
	if raw := os.Getenv("KEEL_DEV_PRINCIPAL"); raw != "" {
		authn, err := devAuthenticator(raw)
		if err != nil {
			cleanup()
			return api.Deps{}, noop, err
		}
		deps.Auth, deps.Sessions = pipelines(st, authn), authn
		return deps, cleanup, nil
	}
	sessions, err := signIn(st)
	if err != nil {
		cleanup()
		return api.Deps{}, noop, err
	}
	deps.Auth, deps.Sessions = pipelines(st, sessions), sessions
	return deps, cleanup, nil
}

// vendors are the account factories per provider (#88). Tencent vending
// needs organisation-admin credentials: KEEL_TENCENT_ORG_REGION.
func vendors(ctx context.Context, st *store.Store) map[string]vending.Vendor {
	out := map[string]vending.Vendor{}
	if region := os.Getenv("KEEL_TENCENT_ORG_REGION"); region != "" {
		orgAPI := tencent.NewOrgAPI(region, tencent.Credentials())
		baseline := landingzone.Tencent(landingzone.Options{AutomationRole: os.Getenv("KEEL_TENCENT_AUTOMATION_ROLE")})
		guardrails := tencent.Guardrails{API: orgAPI}
		// Fresh member accounts carry the organisation's access role, which
		// Keel assumes to configure them.
		accessRole := envOr("KEEL_TENCENT_VENDING_ROLE", "OrganizationAccessControlRole")
		ci := ciidentity.Manager{Store: st, Provider: "tencent", JWKS: ciidentity.GitHubJWKS(nil),
			IAM: func(account string) (ciidentity.IAM, error) {
				api, err := tencent.NewCAM(keelRole(st, tencent.Credentials(), account, accessRole, region))
				return tencent.CIIdentity{API: api}, err
			}}
		bounds := boundary.Manager{Store: st, Provider: "tencent", IAM: func(account string) (boundary.IAM, error) {
			return tencent.NewBoundaries(keelRole(st, tencent.Credentials(), account, accessRole, region))
		}}
		go daily(ctx, "permission boundaries", func(ctx context.Context) error {
			res, err := bounds.Check(ctx)
			if err == nil {
				slog.Info("permission boundaries", "accounts", res.Accounts, "roles_outside", res.Missing)
			}
			return err
		})
		steps := []flow.Step{landingzone.Step(st, guardrails, baseline), ci.Step(), bounds.Step()}
		if id := os.Getenv("KEEL_TCR_REGISTRY_ID"); id != "" {
			api, err := tencent.NewTCR(envOr("KEEL_TENCENT_REGION", "ap-bangkok"), tencent.Credentials())
			if err != nil {
				slog.Error("tcr client", "err", err)
			} else {
				steps = append(steps, registry.Step(st, tencent.Registry{API: api, RegistryID: id}, 30))
			}
		}
		out["tencent"] = vending.Vendor{Store: st, Org: tencent.AccountFactory{API: orgAPI}, Baseline: steps}
		go daily(ctx, "ci identity sync", func(ctx context.Context) error {
			res, err := ci.Sync(ctx)
			if err == nil {
				slog.Info("ci identity sync", "accounts", res.Accounts, "changed", res.Changed, "failed", res.Failed)
			}
			return err
		})
		w := landingzone.Watcher{Store: st, Provider: "tencent", Org: guardrails, Baseline: baseline, Remediate: os.Getenv("KEEL_LANDING_ZONE_REMEDIATE") == "1"}
		go daily(ctx, "landing zone drift", func(ctx context.Context) error {
			res, err := w.Run(ctx)
			if err == nil {
				slog.Info("landing zone drift", "accounts", res.Accounts, "drifted", res.Drifted, "remediated", res.Remediated)
			}
			return err
		})
	}
	return out
}

// startWebhookCatchup redelivers failed organisation webhook deliveries
// every 15 minutes, looking back 24 hours (#226), with an installation
// token carrying only organisation webhooks write (ADR-0020).
func startWebhookCatchup(ctx context.Context, st *store.Store, org string, tokens *ghapi.TokenSource, httpc *http.Client) error {
	hookID := os.Getenv("KEEL_GITHUB_WEBHOOK_HOOK_ID")
	if hookID == "" {
		slog.Warn("github webhook catch-up disabled: KEEL_GITHUB_WEBHOOK_HOOK_ID is unset, so failed deliveries are not redelivered")
		return nil
	}
	hook, err := strconv.ParseInt(hookID, 10, 64)
	if err != nil {
		return fmt.Errorf("KEEL_GITHUB_WEBHOOK_HOOK_ID: %w", err)
	}
	job := githubgov.Catchup{Store: st, Org: org, HookID: hook, Window: 24 * time.Hour, Pause: time.Second, HTTP: httpc, Token: tokens.Token}
	go every(ctx, 15*time.Minute, "github webhook catch-up", func(ctx context.Context) error {
		res, err := job.Run(ctx)
		slog.Info("github webhook catch-up", "attempts", res.Attempts, "missed", res.Missed, "redelivered", res.Redelivered)
		return err
	})
	return nil
}

// githubApp reads the Keel GitHub App, through which every GitHub
// integration authenticates (ADR-0020). It returns nil when no integration
// is configured, and an error naming what is missing when one is but the
// App is not, so Keel never starts with a GitHub integration silently off.
func githubApp(httpc *http.Client) (*ghapi.App, error) {
	var set, missing []string
	for _, k := range []string{"KEEL_GITHUB_APP_ID", "KEEL_GITHUB_APP_INSTALLATION_ID", "KEEL_GITHUB_APP_PRIVATE_KEY"} {
		if os.Getenv(k) == "" {
			missing = append(missing, k)
		} else {
			set = append(set, k)
		}
	}
	var enabledBy []string
	for _, k := range []string{"KEEL_GITHUB_OWNER", "KEEL_GITHUB_WEBHOOK_SECRET", "KEEL_TEMPLATES"} {
		if os.Getenv(k) != "" {
			enabledBy = append(enabledBy, k)
		}
	}
	var legacy []string
	for _, k := range []string{"KEEL_GITHUB_ADMIN_TOKEN", "KEEL_GITHUB_WRITE_TOKEN", "KEEL_GITHUB_TOKEN"} {
		if os.Getenv(k) != "" {
			legacy = append(legacy, k)
		}
	}
	owner := os.Getenv("KEEL_GITHUB_OWNER")
	switch {
	case len(set) == 0 && len(legacy) > 0:
		return nil, fmt.Errorf("%s no longer enable GitHub integrations (#231): configure the GitHub App (KEEL_GITHUB_APP_ID, KEEL_GITHUB_APP_INSTALLATION_ID, KEEL_GITHUB_APP_PRIVATE_KEY, KEEL_GITHUB_OWNER) and remove the token", strings.Join(legacy, ", "))
	case len(set) == 0 && len(enabledBy) == 0:
		return nil, nil
	case len(missing) > 0:
		return nil, fmt.Errorf("github integration (%s) needs the GitHub App: set %s", strings.Join(append(enabledBy, set...), ", "), strings.Join(missing, ", "))
	case owner == "":
		return nil, errors.New("the GitHub App needs KEEL_GITHUB_OWNER, the account its installation must be on")
	}
	inst, err := strconv.ParseInt(os.Getenv("KEEL_GITHUB_APP_INSTALLATION_ID"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("KEEL_GITHUB_APP_INSTALLATION_ID: %w", err)
	}
	key, err := ghapi.ParseAppKey([]byte(os.Getenv("KEEL_GITHUB_APP_PRIVATE_KEY")))
	if err != nil {
		return nil, fmt.Errorf("KEEL_GITHUB_APP_PRIVATE_KEY: %w", err)
	}
	return &ghapi.App{ID: os.Getenv("KEEL_GITHUB_APP_ID"), Installation: inst, Owner: owner, Key: key, HTTP: httpc}, nil
}

// githubTokens is one installation token source per GitHub caller (#231).
// Each asks only for the permissions its endpoints need, per GitHub's
// "Permissions required for GitHub Apps"; ADR-0020 maps them to endpoints.
type githubTokens struct {
	rightsizing, admission, promotion *ghapi.TokenSource
	governance, alerts, leaks         *ghapi.TokenSource
	templates, decisions, catalog     *ghapi.TokenSource
	catchup                           *ghapi.TokenSource
}

// workflows is true when Service Templates write .github/workflows/*
// (KEEL_REUSABLE_WORKFLOW set), which GitHub gates behind Workflows: write.
func newGitHubTokens(app ghapi.App, org, remediate, workflows bool) *githubTokens {
	pullRequests := ghapi.Permissions{"contents": "write", "pull_requests": "write", "metadata": "read"}
	governance := ghapi.Permissions{"metadata": "read"}
	if org {
		// GitHub lists organisation rulesets only to administration write.
		governance["organization_administration"] = "write"
		governance["organization_custom_properties"] = "read"
		governance["organization_plan"] = "read"
	}
	if remediate {
		governance["administration"] = "write"
		if org {
			governance["organization_custom_properties"] = "admin"
		}
	}
	templates := ghapi.Permissions{"administration": "write", "contents": "write", "metadata": "read",
		"organization_custom_properties": "write", "members": "read"}
	if workflows {
		templates["workflows"] = "write"
	}
	return &githubTokens{
		rightsizing: app.Source(pullRequests),
		admission:   app.Source(pullRequests),
		promotion:   app.Source(pullRequests),
		governance:  app.Source(governance),
		alerts:      app.Source(ghapi.Permissions{"security_events": "read", "vulnerability_alerts": "read", "secret_scanning_alerts": "read"}),
		leaks:       app.Source(ghapi.Permissions{"secret_scanning_alerts": "read"}),
		templates:   app.Source(templates),
		decisions:   app.Source(ghapi.Permissions{"contents": "read"}),
		catalog:     app.Source(ghapi.Permissions{"contents": "read", "metadata": "read"}),
		catchup:     app.Source(ghapi.Permissions{"organization_hooks": "write"}),
	}
}

// daily runs fn now and then every 24h until ctx ends.
func daily(ctx context.Context, name string, fn func(context.Context) error) {
	every(ctx, 24*time.Hour, name, fn)
}

// every runs fn now and then every d until ctx ends.
func every(ctx context.Context, d time.Duration, name string, fn func(context.Context) error) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		if err := fn(ctx); err != nil {
			slog.Error(name+" failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// githubPolicy is keel-github@1 with KEEL_GITHUB_REQUIRED_CHECKS and
// KEEL_GITHUB_ALLOWED_ACTIONS.
func githubPolicy() githubgov.Policy {
	var checks []string
	for _, c := range strings.Split(os.Getenv("KEEL_GITHUB_REQUIRED_CHECKS"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			checks = append(checks, c)
		}
	}
	policy := githubgov.Default(checks)
	for _, p := range strings.Split(os.Getenv("KEEL_GITHUB_ALLOWED_ACTIONS"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			policy.Actions.AllowedPatterns = append(policy.Actions.AllowedPatterns, p)
		}
	}
	return policy
}

// templateCreator configures Service Templates (#92) from
// KEEL_TEMPLATES="name=owner/repo@sha,..." in the KEEL_GITHUB_OWNER org.
func templateCreator(st *store.Store, gh *githubTokens, httpc *http.Client) (*templates.Creator, error) {
	raw := os.Getenv("KEEL_TEMPLATES")
	if raw == "" || gh == nil {
		return nil, nil
	}
	c := &templates.Creator{Store: st, Git: templates.GitHub{Client: ghapi.Client{HTTP: gh.templates.Client(httpc)}}, Org: os.Getenv("KEEL_GITHUB_OWNER"),
		ReusableWorkflow: os.Getenv("KEEL_REUSABLE_WORKFLOW"), KeelURL: os.Getenv("KEEL_BASE_URL"), Templates: map[string]templates.Template{},
		AgeProd: os.Getenv("KEEL_SOPS_AGE_PROD"), AgeNonProd: os.Getenv("KEEL_SOPS_AGE_NONPROD")}
	for _, kv := range strings.Split(raw, ",") {
		name, rest, ok := strings.Cut(strings.TrimSpace(kv), "=")
		repo, ref, _ := strings.Cut(rest, "@")
		if !ok || name == "" || !strings.Contains(repo, "/") {
			return nil, fmt.Errorf("KEEL_TEMPLATES entry %q is not name=owner/repo@sha", kv)
		}
		c.Templates[name] = templates.Template{Name: name, Repo: repo, Ref: ref}
	}
	return c, nil
}

// flowDefs lists the durable flows Keel runs (#87).
func flowDefs(vs map[string]vending.Vendor) []flow.Def {
	var defs []flow.Def
	for _, v := range vs {
		defs = append(defs, v.Def())
	}
	return defs
}

// attestService configures the release policy (#112): the Sigstore trusted
// root (KEEL_SIGSTORE_TRUSTED_ROOT, e.g. from "gh attestation trusted-root"),
// GitHub's private instance (KEEL_SIGSTORE_GITHUB_PRIVATE=1), the trusted
// builder workflow prefix (KEEL_TRUSTED_BUILDER) and Keel's signing key.
func attestService(st *store.Store) (attest.Service, error) {
	s := attest.Service{Store: st, VerifierID: strings.TrimSuffix(os.Getenv("KEEL_BASE_URL"), "/") + "/attestations",
		Expectation: attest.Expectation{BuilderPrefix: os.Getenv("KEEL_TRUSTED_BUILDER")}}
	key, err := digestKey()
	if err != nil {
		return s, err
	}
	s.Key = key
	if path := os.Getenv("KEEL_SIGSTORE_TRUSTED_ROOT"); path != "" {
		tr, err := root.NewTrustedRootFromPath(path)
		if err != nil {
			return s, fmt.Errorf("sigstore trusted root: %w", err)
		}
		builder := os.Getenv("KEEL_TRUSTED_BUILDER")
		s.Verifier = attest.Sigstore{Trusted: tr, GitHubPrivate: os.Getenv("KEEL_SIGSTORE_GITHUB_PRIVATE") == "1", IdentityRegexp: "^" + regexp.QuoteMeta(builder)}
	}
	return s, nil
}

// pipelines lets GitHub Actions authenticate with their OIDC token
// (audience KEEL_PIPELINE_AUDIENCE, default "keel"); everything else goes
// to the human authenticator.
func pipelines(st *store.Store, next auth.Authenticator) auth.Authenticator {
	return &pipelineauth.Authenticator{Store: st, Audience: envOr("KEEL_PIPELINE_AUDIENCE", "keel"), Next: next}
}

// riverUser is anything with its own River workers (timers).
type riverUser interface {
	Register(*river.Workers)
	SetClient(*river.Client[pgx.Tx])
}

// startFlows runs River (ADR-0014) for durable flows. The returned func stops
// it, letting running steps finish for up to 30s.
func startFlows(ctx context.Context, st *store.Store, defs []flow.Def, timers ...riverUser) (*flow.Engine, func(), error) {
	engine := flow.New(st, defs...)
	workers := river.NewWorkers()
	engine.Register(workers)
	for _, t := range timers {
		t.Register(workers)
	}
	client, err := flow.NewClient(st.AppPool(), workers, flow.ClientOptions{Logger: slog.Default()})
	if err != nil {
		return nil, nil, fmt.Errorf("river: %w", err)
	}
	engine.SetClient(client)
	for _, t := range timers {
		t.SetClient(client)
	}
	if err := client.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("river: %w", err)
	}
	return engine, func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := client.Stop(c); err != nil {
			slog.Error("river stop", "err", err)
		}
	}, nil
}

func signIn(st *store.Store) (*oidcauth.Service, error) {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("KEEL_COOKIE_KEY"))
	if err != nil || len(key) != 32 {
		return nil, errors.New("KEEL_COOKIE_KEY must be base64 of 32 random bytes (openssl rand -base64 32)")
	}
	base := os.Getenv("KEEL_BASE_URL")
	if base == "" {
		return nil, errors.New("KEEL_BASE_URL is required")
	}
	return oidcauth.New(st, oidcauth.Config{
		BaseURL:       base,
		SecureCookies: os.Getenv("KEEL_INSECURE_COOKIES") != "1",
		CookieKey:     key,
		Secrets: func(ref string) (string, error) {
			v := os.Getenv(ref)
			if v == "" {
				return "", fmt.Errorf("secret %s not set", ref)
			}
			return v, nil
		},
	})
}

func bootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	var in oidcauth.BootstrapInput
	fs.StringVar(&in.HomeSlug, "slug", "", "home tenant slug")
	fs.StringVar(&in.HomeName, "name", "", "home tenant name")
	fs.StringVar(&in.Issuer, "issuer", "", "OIDC issuer URL of the home identity provider")
	fs.StringVar(&in.ClientID, "client-id", "", "OIDC client id registered for Keel")
	fs.StringVar(&in.ClientSecretRef, "client-secret-ref", "", "name of the env var holding the client secret")
	fs.StringVar(&in.AdminGroup, "admin-group", "", "IdP group whose members become platform_admin")
	fs.StringVar(&in.EmailDomain, "email-domain", "", "optional allowed email domain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	if u := os.Getenv("KEEL_MIGRATE_URL"); u != "" {
		if err := store.Migrate(ctx, u); err != nil {
			return err
		}
	}
	pool, err := pgxpool.New(ctx, os.Getenv("KEEL_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	id, err := oidcauth.Bootstrap(ctx, store.New(pool), in)
	if err != nil {
		return err
	}
	fmt.Println("home tenant:", id)
	return nil
}

func devAuthenticator(raw string) (auth.Static, error) {
	if os.Getenv("KEEL_ENV") != "dev" {
		return auth.Static{}, errors.New("KEEL_DEV_PRINCIPAL is only allowed with KEEL_ENV=dev")
	}
	slog.Warn("DEV AUTHENTICATION: every request is the static KEEL_DEV_PRINCIPAL")
	return auth.ParseStatic(raw)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func digestKey() (ed25519.PrivateKey, error) {
	raw := os.Getenv("KEEL_DIGEST_KEY")
	if raw == "" {
		return nil, nil
	}
	seed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("KEEL_DIGEST_KEY must be base64 of a 32-byte Ed25519 seed (openssl rand -base64 32)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// startSealer seals every Tenant's Activity Log hourly. Postgres advisory
// locks make concurrent replicas safe.
func startSealer(ctx context.Context, st *store.Store) error {
	key, err := digestKey()
	if err != nil {
		return err
	}
	if key == nil {
		slog.Warn("KEEL_DIGEST_KEY not set; Activity Log is not being sealed")
		return nil
	}
	sealer := &integrity.Sealer{Store: st, Signer: integrity.NewEd25519(key)}
	objs, _, err := archiveStore(ctx)
	if err != nil {
		return err
	}
	var exporter *archive.Exporter
	if objs != nil {
		exporter = &archive.Exporter{Store: st, Objects: objs}
	} else {
		slog.Warn("KEEL_ARCHIVE_BUCKET not set; sealed digests are not shipped to the WORM archive")
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			if err := sealer.SealAll(ctx); err != nil {
				slog.Error("ALERT activity log sealing failed", "err", err)
			}
			if exporter != nil {
				if n, err := exporter.ExportAll(ctx); err != nil {
					slog.Error("ALERT activity log archive export failed", "err", err, "exported", n)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return nil
}

// verifyEvidence checks an exported bundle offline:
// keel-api verify-evidence <bundle.json> <base64 public key>.
func verifyEvidence(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: keel-api verify-evidence <bundle.json> <base64 ed25519 public key>")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, evidence.MaxBundleBytes+1))
	if err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("public key must be base64 of 32 bytes")
	}
	b, err := evidence.Verify(pub, raw)
	if err != nil {
		return err
	}
	fmt.Printf("OK: %s for tenant %s, frameworks [%s], %s → %s, %d sections\n", b.Manifest.Format, b.Manifest.Tenant, strings.Join(b.Manifest.Frameworks, " "), b.Manifest.From.Format("2006-01-02"), b.Manifest.To.Format("2006-01-02"), len(b.Sections))
	return nil
}

func digestPubkey([]string) error {
	key, err := digestKey()
	if err != nil || key == nil {
		return errors.New("set KEEL_DIGEST_KEY")
	}
	pub := key.Public().(ed25519.PublicKey)
	fmt.Printf("key_id=%s pubkey=%s\n", integrity.KeyID(pub), base64.StdEncoding.EncodeToString(pub))
	return nil
}

func verifyLog(args []string) error {
	fs := flag.NewFlagSet("verify-log", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant id")
	pubs := fs.String("pubkey", "", "comma-separated base64 Ed25519 public keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := parseKeys(*pubs)
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("KEEL_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	r, err := integrity.Verify(ctx, store.New(pool), *tenant, keys)
	if err != nil {
		return err
	}
	return printReport(r)
}

// archiveStore connects to the WORM archive bucket, or returns nil when
// KEEL_ARCHIVE_BUCKET is unset. An aws bucket must have Object Lock and
// versioning enabled; Keel refuses to archive into it otherwise (ADR-0019).
func archiveStore(ctx context.Context) (*archive.S3, string, error) {
	sel, err := archive.Select(os.Getenv)
	if err != nil {
		return nil, "", err
	}
	if sel.Bucket == "" {
		return nil, "", nil
	}
	if sel.Provider == "tencent" {
		creds := archive.Refreshing(tencent.STS{Creds: tencent.Credentials()}, 10*time.Minute)
		s3, err := archive.NewS3(archive.S3Config{Endpoint: sel.Endpoint, Region: sel.Region, Bucket: sel.Bucket, Creds: creds})
		return s3, sel.Provider, err
	}
	s3, err := archive.NewS3(archive.S3Config{Endpoint: sel.Endpoint, Region: sel.Region, Bucket: sel.Bucket, Creds: awscreds.NewIAM(""), RetentionDays: sel.RetentionDays})
	if err != nil {
		return nil, "", err
	}
	if err := s3.RequireObjectLock(ctx); err != nil {
		return nil, "", fmt.Errorf("refusing to archive: %w", err)
	}
	return s3, sel.Provider, nil
}

func verifyArchive(args []string) error {
	fs := flag.NewFlagSet("verify-archive", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant id")
	pubs := fs.String("pubkey", "", "comma-separated base64 Ed25519 public keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := parseKeys(*pubs)
	if err != nil {
		return err
	}
	ctx := context.Background()
	objs, provider, err := archiveStore(ctx)
	if err != nil {
		return err
	}
	if objs == nil {
		return errors.New("set KEEL_ARCHIVE_BUCKET and KEEL_ARCHIVE_REGION (see docs/runbooks/log-archive.md)")
	}
	r, err := archive.Verify(ctx, objs, *tenant, keys)
	if err != nil {
		return err
	}
	if provider == "aws" {
		rs, err := objs.Retentions(ctx, archive.Prefix(*tenant))
		if err != nil {
			return err
		}
		lines, problems := archive.RetentionReport(rs)
		for _, l := range lines {
			fmt.Println(l)
		}
		r.Problems = append(r.Problems, problems...)
	}
	return printReport(r)
}

func parseKeys(csv string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	for _, p := range strings.Split(csv, ",") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bad public key %q", p)
		}
		keys[integrity.KeyID(b)] = b
	}
	return keys, nil
}

func printReport(r integrity.Report) error {
	fmt.Printf("digests=%d covered=%d unsealed=%d\n", r.Digests, r.Covered, r.Unsealed)
	for _, p := range r.Problems {
		fmt.Println("PROBLEM:", p)
	}
	if !r.OK() {
		return errors.New("activity log failed verification")
	}
	fmt.Println("OK")
	return nil
}

// startBillSync loads the Tencent payer's FOCUS bills hourly and reconciles
// them against the billing API (#31–#33).
func startBillSync(ctx context.Context, st *store.Store, ev budget.Evaluator) error {
	bucket := os.Getenv("KEEL_TENCENT_BILL_BUCKET")
	if bucket == "" {
		return nil
	}
	payer := os.Getenv("KEEL_TENCENT_PAYER_UIN")
	if payer == "" {
		return errors.New("KEEL_TENCENT_PAYER_UIN is required with KEEL_TENCENT_BILL_BUCKET")
	}
	region := envOr("KEEL_TENCENT_REGION", "ap-bangkok")
	creds := billCredentials(st, tencent.Credentials(), payer, os.Getenv("KEEL_TENCENT_BILL_ROLE"), region)
	objs, err := archive.NewS3(archive.S3Config{Endpoint: "cos." + region + ".myqcloud.com", Region: region, Bucket: bucket,
		Creds: archive.Refreshing(tencent.STS{Creds: creds}, 10*time.Minute)})
	if err != nil {
		return err
	}
	mode := cost.PerDayFiles
	switch os.Getenv("KEEL_TENCENT_BILL_MODE") {
	case "", "per-day":
	case "cumulative":
		mode = cost.CumulativeFiles
	default:
		return errors.New("KEEL_TENCENT_BILL_MODE must be per-day or cumulative")
	}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: st}, Objects: billObjects{objs}, Provider: "tencent", BillingAccountID: payer,
		Prefix: os.Getenv("KEEL_TENCENT_BILL_PREFIX"), Mode: mode, Invoices: tencent.Invoices{Region: region, Creds: creds}}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			// A blocked period (overlapping per-day files) still leaves the
			// other periods' loads to reconcile and evaluate. Run errors on a
			// block only when it is new or its files changed; its Finding
			// stays open until the period loads.
			rep, err := bs.Run(ctx)
			if err != nil {
				slog.Error("ALERT tencent bill sync failed", "err", err)
			}
			slog.Info("tencent bill sync", "new_files", rep.NewFiles, "loads", len(rep.Loads), "skipped", len(rep.Skipped), "not_focus", rep.NotFOCUS, "blocked", rep.Blocked)
			for _, l := range rep.Loads {
				if l.Reconcile == "mismatch" {
					slog.Error("ALERT tencent bill does not reconcile with invoice", "period", l.Period.Format("2006-01"), "load", l.LoadID)
				}
			}
			if len(rep.Loads) > 0 {
				evaluate(ctx, ev)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return nil
}

// billCredentials is the identity that reads the payer's bills and invoices.
// With a payer billing role it assumes that role from Keel's base identity,
// so payer billing access never becomes Keel's identity for other calls.
func billCredentials(st *store.Store, base common.Provider, payer, role, region string) common.Provider {
	if role == "" {
		slog.Warn("KEEL_TENCENT_BILL_ROLE is unset; tencent bill sync reads bills with Keel's base identity")
		return base
	}
	return keelRole(st, base, payer, role, region)
}

// keelRole is Keel's own role in a Tencent account. It is never assumed in a
// client-owned Cloud Account, which Keel reads only through the client's
// read-only role (ADR-0018, #240).
func keelRole(st *store.Store, base common.Provider, account, role, region string) *tencent.MemberRole {
	return &tencent.MemberRole{Base: base, Account: account, Role: role, Region: region, Guard: func(account string) error {
		return catalog.RequireKeelReachable(context.Background(), st, "tencent", account)
	}}
}

// clientBillSyncs reads client payers' bills on each provider, each through
// its client's read-only role and into its own Tenant (ADR-0018): Tencent
// payers (#182) and AWS management accounts (#183). Client payers are data:
// client_payers rows on client-owned Cloud Accounts. A broken AWS identity
// (unloadable config, access keys instead of a keyless source, or one STS
// rejects) fails the AWS sync's Ready check once per run with payers, as
// Keel's fault, and never stops the Tencent sync.
func clientBillSyncs(ctx context.Context, st *store.Store, tencentSTS string) []*cost.ClientBillSync {
	own := func(env string) []string {
		if v := os.Getenv(env); v != "" {
			return []string{v}
		}
		return nil
	}
	in := &cost.Ingester{Store: st}
	aws := &cost.ClientBillSync{Ingester: in, Provider: "aws", OwnPayers: own("KEEL_AWS_PAYER_ACCOUNT")}
	if base, err := awsadapter.Keyless(ctx); err != nil {
		aws.Ready = func(context.Context) error { return fmt.Errorf("loading Keel's AWS identity: %w", err) }
	} else {
		aws = awsClientBillSync(in, base, "", "")
	}
	return []*cost.ClientBillSync{
		tencentClientBillSync(in, tencent.Credentials(), tencentSTS),
		aws,
	}
}

// awsClientBillSync reads AWS client payers as their read-only roles,
// assumed from Keel's keyless identity. Ready has STS accept that identity
// first, so Keel's own rejected credentials are never blamed on a client's
// role. stsEndpoint and s3Endpoint override the AWS endpoints in tests.
func awsClientBillSync(in *cost.Ingester, base awsadapter.Identity, stsEndpoint, s3Endpoint string) *cost.ClientBillSync {
	var own []string
	if v := os.Getenv("KEEL_AWS_PAYER_ACCOUNT"); v != "" {
		own = []string{v}
	}
	return &cost.ClientBillSync{Ingester: in, Provider: "aws", OwnPayers: own, Connect: awsClientPayerConnect(base, stsEndpoint, s3Endpoint),
		Ready: func(ctx context.Context) error {
			if _, err := base.Retrieve(ctx); err != nil {
				return fmt.Errorf("loading Keel's AWS identity: %w", err)
			}
			if err := awsadapter.CallerIdentity(ctx, base, stsEndpoint); err != nil {
				return fmt.Errorf("%w Keel's AWS identity: %w", cost.ErrIdentityRejected, err)
			}
			return nil
		}}
}

// tencentClientBillSync reads Tencent client payers as their read-only roles,
// assumed from Keel's base identity. Ready loads that identity and has STS
// accept it first, so Keel's own missing or rejected credentials are never
// blamed on a client's role. The SDK calls cannot be cancelled, so Ready
// returns when ctx ends and leaves the call to the SDK's own timeout.
// stsEndpoint overrides the STS host in tests.
func tencentClientBillSync(in *cost.Ingester, base common.Provider, stsEndpoint string) *cost.ClientBillSync {
	var own []string
	if v := os.Getenv("KEEL_TENCENT_PAYER_UIN"); v != "" {
		own = []string{v}
	}
	return &cost.ClientBillSync{Ingester: in, Provider: "tencent", OwnPayers: own, Connect: clientPayerConnect(base, stsEndpoint),
		Ready: func(ctx context.Context) error {
			done := make(chan error, 1)
			go func() {
				cred, err := base.GetCredential()
				if err != nil {
					done <- fmt.Errorf("loading Keel's Tencent identity: %w", err)
					return
				}
				if err := tencent.CallerIdentity(cred, envOr("KEEL_TENCENT_REGION", "ap-bangkok"), stsEndpoint); err != nil {
					done <- fmt.Errorf("%w Keel's Tencent identity: %w", cost.ErrIdentityRejected, err)
					return
				}
				done <- nil
			}()
			select {
			case err := <-done:
				return err
			case <-ctx.Done():
				return fmt.Errorf("checking Keel's Tencent identity: %w", ctx.Err())
			}
		}}
}

// clientBillSyncLoop runs every client payer sync hourly.
func clientBillSyncLoop(ctx context.Context, ev budget.Evaluator, syncs []*cost.ClientBillSync, reads map[string]*clientreads.Sync) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if syncClients(ctx, syncs, reads) {
			evaluate(ctx, ev)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// syncClients runs each provider's client bill sync, then its client reads
// for the payers that sync visited. A sync stopped by Keel's own identity
// visits no payer, so no client role is tried for reads either. It reports
// whether any bill loaded.
func syncClients(ctx context.Context, syncs []*cost.ClientBillSync, reads map[string]*clientreads.Sync) bool {
	loaded := false
	for _, cs := range syncs {
		runs, err := cs.Run(ctx)
		if err != nil {
			slog.Error("ALERT client bill sync failed", "provider", cs.Provider, "err", err)
		}
		var payers []cost.ClientPayer
		for _, r := range runs {
			slog.Info("client bill sync", "provider", cs.Provider, "tenant", r.Payer.TenantID, "payer", r.Payer.PayerID, "no_delivery", r.NoDelivery,
				"new_files", r.Report.NewFiles, "loads", len(r.Report.Loads), "not_focus", r.Report.NotFOCUS, "blocked", r.Report.Blocked)
			loaded = loaded || len(r.Report.Loads) > 0
			payers = append(payers, r.Payer)
		}
		cr := reads[cs.Provider]
		if cr == nil || len(payers) == 0 {
			continue
		}
		reports, err := cr.Run(ctx, payers)
		if err != nil {
			slog.Error("ALERT client reads failed", "provider", cs.Provider, "err", err)
		}
		for _, r := range reports {
			slog.Info("client reads", "provider", cs.Provider, "tenant", r.Payer.TenantID, "payer", r.Payer.PayerID, "budgets", r.Budgets,
				"budgets_over", r.BudgetsOver, "findings", r.Findings, "recommendations", r.Recommendations, "dropped", r.Dropped)
		}
	}
	return loaded
}

// clientReads reads client payers' Budgets, security Findings and
// Rightsizing Recommendations through their read-only roles, per provider:
// Tencent payers (#182) and AWS management accounts (#183). Without a
// keyless AWS identity there is nothing to read AWS with; the AWS bill sync
// already reports that.
func clientReads(ctx context.Context, st *store.Store) map[string]*clientreads.Sync {
	reads := map[string]*clientreads.Sync{"tencent": tencentClientReads(st, tencent.Credentials(), "", "")}
	if base, err := awsadapter.Keyless(ctx); err == nil {
		reads["aws"] = awsClientReads(st, base, "", "")
	}
	return reads
}

// tencentClientReads reads each Tencent client payer as its read-only
// role, assumed from Keel's base identity with the payer's ExternalId and a
// session limited to tencent.ReadActions: Budgets, Smart Advisor risks, and
// Cloud Monitor and CVM types for rightsizing the payer's own instances.
// Only the CVM catalogue, Tencent's public price list, is read as Keel. It
// assumes the role up front, so a role that refuses Keel fails before any
// read. stsEndpoint and endpoint override the Tencent hosts in tests.
func tencentClientReads(st *store.Store, base common.Provider, stsEndpoint, endpoint string) *clientreads.Sync {
	return &clientreads.Sync{Store: st, Provider: "tencent", Connect: func(p cost.ClientPayer) (clientreads.Reader, error) {
		role, err := tencent.ReadsRole(base, p.RoleARN, p.PayerID, p.RoleExternalID, p.Region)
		if err != nil {
			return nil, &cost.RoleError{Err: err}
		}
		role.Endpoint = stsEndpoint
		if _, err := role.GetCredential(); err != nil {
			return nil, &cost.RoleError{Err: err}
		}
		r, err := tencent.NewClientReads(role, p.PayerID, p.Region, endpoint)
		if err != nil {
			return nil, err
		}
		catalog, err := tencent.NewCVM(p.Region, base, endpoint)
		if err != nil {
			return nil, err
		}
		return tencentReader{r, clientreads.CVMRightsizing{Store: st, Tenant: p.TenantID, Payer: p.PayerID, Region: p.Region,
			Monitor: r.Monitor(), Inventory: r.Inventory(), Catalog: tencent.Catalog{API: catalog}}}, nil
	}}
}

// tencentReader is a Tencent payer's clientreads.Reader: Budgets and
// Smart Advisor findings from the payer, Recommendations from Keel's VM
// engine over what the payer's Cloud Monitor reports.
type tencentReader struct {
	*tencent.ClientReads
	cvm clientreads.CVMRightsizing
}

func (r tencentReader) Recommendations(ctx context.Context) ([]rightsize.Recommendation, error) {
	return r.cvm.Recommendations(ctx)
}

// awsClientReads reads each AWS client management account as its
// read-only role, assumed from Keel's keyless identity with the payer's
// ExternalId and a session limited to awsadapter.ReadActions. It assumes the
// role up front, so a role that refuses Keel fails before any read.
// stsEndpoint and endpoint override the AWS endpoints in tests.
func awsClientReads(st *store.Store, base awsadapter.Identity, stsEndpoint, endpoint string) *clientreads.Sync {
	return &clientreads.Sync{Store: st, Provider: "aws", Connect: func(p cost.ClientPayer) (clientreads.Reader, error) {
		role, err := awsadapter.ReadsRole(base, p.RoleARN, p.PayerID, p.RoleExternalID, stsEndpoint)
		if err != nil {
			return nil, &cost.RoleError{Err: err}
		}
		if _, _, _, err := role.Get(); err != nil {
			return nil, &cost.RoleError{Err: err}
		}
		return awsadapter.NewClientReads(role, p.PayerID, p.Region, endpoint), nil
	}}
}

// clientPayerConnect gives read-only access to a client payer's bills and
// invoice totals, as that client's read-only role assumed from Keel's base
// identity. It assumes the role up front, so a role that refuses Keel fails
// here and not mid-sync. stsEndpoint overrides the STS host in tests.
func clientPayerConnect(base common.Provider, stsEndpoint string) func(cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
	return func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
		role, err := tencent.ReadOnlyRole(base, p.RoleARN, p.PayerID, p.RoleExternalID, p.Region)
		if err != nil {
			return nil, nil, &cost.RoleError{Err: err}
		}
		role.Endpoint = stsEndpoint
		if _, err := role.GetCredential(); err != nil {
			return nil, nil, &cost.RoleError{Err: err}
		}
		objs, err := archive.NewS3(archive.S3Config{Endpoint: "cos." + p.Region + ".myqcloud.com", Region: p.Region, Bucket: p.Bucket,
			Creds: archive.Refreshing(tencent.STS{Creds: role}, 10*time.Minute)})
		if err != nil {
			return nil, nil, err
		}
		return billObjects{objs}, tencent.Invoices{Region: p.Region, Creds: role}, nil
	}
}

// awsClientPayerConnect gives read-only access to a client management
// account's Data Exports, as that client's read-only role assumed from
// Keel's keyless identity with the payer's ExternalId. It assumes the role
// up front, so a role that refuses Keel fails here and not mid-sync. AWS
// has no invoice source, as for Keel's own AWS payer. stsEndpoint and
// s3Endpoint (scheme://host) override the AWS endpoints in tests.
func awsClientPayerConnect(base awsadapter.Identity, stsEndpoint, s3Endpoint string) func(cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
	return func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
		role, err := awsadapter.ReadOnlyRole(base, p.RoleARN, p.PayerID, p.RoleExternalID,
			awsadapter.Export{Bucket: p.Bucket, Prefix: p.Prefix, Region: p.Region, KMSKeyARN: p.KMSKeyARN}, stsEndpoint)
		if err != nil {
			return nil, nil, &cost.RoleError{Err: err}
		}
		if _, _, _, err := role.Get(); err != nil {
			return nil, nil, &cost.RoleError{Err: err}
		}
		endpoint, insecure := "s3."+p.Region+".amazonaws.com", false
		if scheme, host, ok := strings.Cut(s3Endpoint, "://"); ok {
			endpoint, insecure = host, scheme == "http"
		}
		objs, err := archive.NewS3(archive.S3Config{Endpoint: endpoint, Insecure: insecure, Region: p.Region, Bucket: p.Bucket,
			Creds: archive.Refreshing(role, 10*time.Minute)})
		if err != nil {
			return nil, nil, err
		}
		return billObjects{objs}, nil, nil
	}
}

// fxLoop keeps ECB reference rates current: a full 3-year backfill when the
// stored history is shorter, then the daily feed every 6h.
func fxLoop(ctx context.Context, st *store.Store) {
	db := fx.DB{Store: st}
	since := time.Now().UTC().AddDate(-3, 0, 0)
	url := fx.ECBDailyURL
	if earliest, err := db.Earliest(ctx); err != nil || earliest.IsZero() || earliest.After(since.AddDate(0, 0, 7)) {
		url = fx.ECBHistoryURL
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		if rates, err := fx.FetchECB(ctx, nil, url); err != nil {
			slog.Error("fx fetch failed", "err", err)
		} else if n, err := db.SaveRates(ctx, fx.Filter(rates, since)); err != nil {
			slog.Error("fx save failed", "err", err)
		} else {
			slog.Info("fx rates", "new", n)
			url = fx.ECBDailyURL
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func evaluateLoop(ctx context.Context, ev budget.Evaluator) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		evaluate(ctx, ev)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func evaluate(ctx context.Context, ev budget.Evaluator) {
	if res, err := (&anomaly.Runner{Store: ev.Service.Store}).Run(ctx); err != nil {
		slog.Error("cost anomaly scan failed", "err", err)
	} else if res.Raised+res.Resolved > 0 {
		slog.Warn("cost anomalies", "raised", res.Raised, "updated", res.Updated, "resolved", res.Resolved)
	}
	alerts, err := ev.EvaluateAll(ctx)
	if err != nil {
		slog.Error("budget evaluation failed", "err", err)
		return
	}
	for _, a := range alerts {
		slog.Warn("budget threshold crossed", "tenant", a.TenantID, "budget", a.Name, "basis", a.Basis, "pct", a.Pct, "value", a.Value, "currency", a.Currency)
	}
}

// billObjects adapts an S3 bucket to cost.Objects with ETag versioning.
type billObjects struct{ *archive.S3 }

func (b billObjects) ListWithETag(ctx context.Context, prefix string) ([]cost.ObjectInfo, error) {
	vs, err := b.S3.ListWithETag(ctx, prefix)
	out := make([]cost.ObjectInfo, len(vs))
	for i, v := range vs {
		out[i] = cost.ObjectInfo{Key: v.Key, ETag: v.ETag}
	}
	return out, err
}

// startAWSBillSync loads AWS Data Exports FOCUS 1.2 (CSV) from the management
// account's S3 bucket hourly (#44). Credentials are keyless: web identity
// (AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE) or the instance role.
func startAWSBillSync(ctx context.Context, st *store.Store, ev budget.Evaluator) error {
	bucket := os.Getenv("KEEL_AWS_BILL_BUCKET")
	if bucket == "" {
		return nil
	}
	account := os.Getenv("KEEL_AWS_PAYER_ACCOUNT")
	if account == "" {
		return errors.New("KEEL_AWS_PAYER_ACCOUNT is required with KEEL_AWS_BILL_BUCKET")
	}
	region := envOr("KEEL_AWS_REGION", "us-east-1")
	objs, err := archive.NewS3(archive.S3Config{Endpoint: "s3." + region + ".amazonaws.com", Region: region, Bucket: bucket, Creds: awscreds.NewIAM("")})
	if err != nil {
		return err
	}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: st}, Objects: billObjects{objs}, Provider: "aws", BillingAccountID: account,
		Prefix: os.Getenv("KEEL_AWS_BILL_PREFIX"), Mode: cost.LatestExportFolder}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			rep, err := bs.Run(ctx)
			if err != nil {
				slog.Error("ALERT aws bill sync failed", "err", err)
			} else {
				slog.Info("aws bill sync", "new_files", rep.NewFiles, "loads", len(rep.Loads))
				if len(rep.Loads) > 0 {
					evaluate(ctx, ev)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return nil
}

// startOpenCost pulls per-namespace daily cost from each shared cluster's
// OpenCost every 6h (last 3 days, so late data settles) for k8s rules (#35).
func startOpenCost(ctx context.Context, st *store.Store) error {
	raw := os.Getenv("KEEL_OPENCOST")
	if raw == "" {
		return nil
	}
	clusters := map[string]string{}
	for _, kv := range strings.Split(raw, ",") {
		name, url, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || name == "" || url == "" {
			return fmt.Errorf("KEEL_OPENCOST entry %q is not cluster=url", kv)
		}
		clusters[name] = strings.TrimSuffix(url, "/")
	}
	rules := cost.Rules{Store: st}
	go func() {
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			var home *string
			if err := st.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err == nil && home != nil {
				now := time.Now().UTC()
				to := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
				for name, url := range clusters {
					days, err := cost.FetchOpenCost(ctx, nil, url, to.AddDate(0, 0, -3), to)
					if err != nil {
						slog.Error("opencost fetch failed", "cluster", name, "err", err)
						continue
					}
					for day, costs := range days {
						if _, err := rules.SaveNamespaceCosts(ctx, *home, name, day, costs); err != nil {
							slog.Error("opencost save failed", "cluster", name, "err", err)
						}
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return nil
}

// startMirrors keeps native provider budgets in step with opted-in Budgets
// hourly (#39). Provider budgets alert even if Keel is down.
func startMirrors(ctx context.Context, st *store.Store) error {
	natives := map[string]budget.Native{}
	if os.Getenv("KEEL_TENCENT_BUDGETS") == "1" {
		natives["tencent"] = tencent.Budgets{Region: envOr("KEEL_TENCENT_REGION", "ap-bangkok"), Creds: tencent.Credentials()}
	}
	if acct := os.Getenv("KEEL_AWS_BUDGET_ACCOUNT"); acct != "" {
		b, err := awsadapter.New(ctx, acct, os.Getenv("KEEL_AWS_BUDGET_EMAIL"))
		if err != nil {
			return err
		}
		natives["aws"] = b
	}
	if len(natives) == 0 {
		return nil
	}
	m := budget.Mirror{Service: budget.Service{Store: st}, Natives: natives, BillingCurrency: map[string]string{"tencent": "USD", "aws": "USD"}}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			rep, err := m.SyncAll(ctx)
			if err != nil {
				slog.Error("budget mirror sync failed", "err", err)
			}
			for _, d := range rep.Drift {
				slog.Warn("native budget drift corrected", "detail", d)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return nil
}

// startUtilisation collects rightsizing evidence (#68): a 14-day backfill at
// start, then every 6h the last two days (late samples settle).
func startUtilisation(ctx context.Context, st *store.Store, prs *apply.Applier) error {
	job := utilisation.Job{Store: utilisation.Store{Store: st}}
	if raw := os.Getenv("KEEL_PROMETHEUS"); raw != "" {
		for _, kv := range strings.Split(raw, ",") {
			name, rest, ok := strings.Cut(strings.TrimSpace(kv), "=")
			if !ok || name == "" || rest == "" {
				return fmt.Errorf("KEEL_PROMETHEUS entry %q is not cluster=url[@tenant/project/env]", kv)
			}
			url, scope, _ := strings.Cut(rest, "@")
			job.Clusters = append(job.Clusters, utilisation.Cluster{Prometheus: utilisation.Prometheus{Cluster: name, URL: url}, DefaultScope: scope})
		}
	}
	if role := os.Getenv("KEEL_TENCENT_MEMBER_ROLE"); role != "" {
		job.CVM = tencentCVMUtilisation(st, tencent.Credentials(), role, envOr("KEEL_TENCENT_REGION", "ap-bangkok"), "")
	}
	if len(job.Clusters) == 0 && job.CVM == nil && os.Getenv("KEEL_AWS_COH") != "1" {
		return nil // nothing to collect and no recommender to import from
	}
	go func() {
		today := time.Now().UTC()
		for d := 14; d >= 1; d-- {
			if err := job.Run(ctx, today.AddDate(0, 0, -d)); err != nil {
				slog.Error("utilisation backfill", "day", today.AddDate(0, 0, -d).Format("2006-01-02"), "err", err)
			}
		}
		rightsizeAll(ctx, st, prs)
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			now := time.Now().UTC()
			for _, d := range []int{2, 1} {
				if err := job.Run(ctx, now.AddDate(0, 0, -d)); err != nil {
					slog.Error("utilisation collection", "err", err)
				}
			}
			rightsizeAll(ctx, st, prs)
		}
	}()
	return nil
}

// rightsizeAll runs Keel's rightsizing engines over fresh utilisation, and
// syncs rightsizing pull requests when prs is set.
func rightsizeAll(ctx context.Context, st *store.Store, prs *apply.Applier) {
	if prs != nil {
		if res, err := prs.Sync(ctx); err != nil {
			slog.Error("rightsizing PR sync", "err", err)
		} else if res.Applied+res.Reopened > 0 {
			slog.Info("rightsizing PRs", "applied", res.Applied, "reopened", res.Reopened)
		}
	}
	k8s := rightsize.K8sEngine{Service: rightsize.Service{Store: st}, Utilisation: utilisation.Store{Store: st}}
	if res, err := k8s.Run(ctx); err != nil {
		slog.Error("k8s rightsizing failed", "err", err)
	} else {
		slog.Info("k8s rightsizing", "raised", res.Raised, "kept", res.Kept, "skipped", res.Skipped)
	}
	if os.Getenv("KEEL_AWS_COH") == "1" {
		if c, err := awsadapter.NewCOH(ctx); err != nil {
			slog.Error("aws cost optimization hub", "err", err)
		} else if recs, err := c.List(ctx); err != nil {
			slog.Error("aws cost optimization hub", "err", err)
		} else if res, err := (rightsize.Service{Store: st}).Import(ctx, recs); err != nil {
			slog.Error("aws recommendations import", "err", err)
		} else {
			slog.Info("aws recommendations", "raised", res.Raised, "kept", res.Kept, "unowned", res.Unowned)
		}
	}
	if res, err := (rightsize.OffHoursEngine{Service: rightsize.Service{Store: st}}).Run(ctx); err != nil {
		slog.Error("off-hours scheduling failed", "err", err)
	} else {
		slog.Info("off-hours scheduling", "raised", res.Raised, "kept", res.Kept, "skipped", res.Skipped)
	}
	if res, err := (rightsize.K8sOffHoursEngine{Service: rightsize.Service{Store: st}}).Run(ctx); err != nil {
		slog.Error("k8s off-hours scheduling failed", "err", err)
	} else {
		slog.Info("k8s off-hours scheduling", "raised", res.Raised, "kept", res.Kept, "skipped", res.Skipped)
	}
	// Realised savings and regressions; advice from engines below is seen on the next run.
	if res, err := (rightsize.Tracker{Service: rightsize.Service{Store: st}}).Run(ctx); err != nil {
		slog.Error("savings tracker failed", "err", err)
	} else {
		slog.Info("savings tracker", "updated", res.Updated, "waiting", res.Waiting, "regressions", res.Regressions)
	}
	role := os.Getenv("KEEL_TENCENT_MEMBER_ROLE")
	if role == "" {
		return
	}
	region := envOr("KEEL_TENCENT_REGION", "ap-bangkok")
	base := tencent.Credentials()
	catAPI, err := tencent.NewCVM(region, base, "")
	if err != nil {
		slog.Error("cvm catalogue", "err", err)
		return
	}
	vm := rightsize.VMEngine{Service: rightsize.Service{Store: st}, Catalog: tencent.Catalog{API: catAPI}, Region: region,
		Inventory: func(account string) rightsize.Inventory {
			api, err := tencent.NewCVM(region, keelRole(st, base, account, role, region), "")
			if err != nil {
				return failingInventory{err}
			}
			return tencent.Inventory{API: api}
		}}
	if res, err := vm.Run(ctx); err != nil {
		slog.Error("cvm rightsizing failed", "err", err)
	} else {
		slog.Info("cvm rightsizing", "raised", res.Raised, "kept", res.Kept, "skipped", res.Skipped)
	}
	grace, _ := strconv.Atoi(envOr("KEEL_WASTE_GRACE_DAYS", "7"))
	waste := rightsize.WasteEngine{Service: rightsize.Service{Store: st}, GraceDays: max(grace, 1), CleanupEnabled: os.Getenv("KEEL_WASTE_CLEANUP") == "1",
		Scanner: tencentWasteScanner(st, base, role, region, "")}
	if res, err := waste.Run(ctx); err != nil {
		slog.Error("waste scan failed", "err", err)
	} else {
		slog.Info("waste", "raised", res.Raised, "kept", res.Kept, "deleted", res.Deleted, "errors", res.Errors)
	}
}

// tencentCVMUtilisation reads each member account's Cloud Monitor through
// Keel's member role there, one role per account so its session is reused.
// stsEndpoint overrides the STS host, for tests.
func tencentCVMUtilisation(st *store.Store, base common.Provider, role, region, stsEndpoint string) func(string) (*utilisation.TencentCVM, error) {
	roles := map[string]*tencent.MemberRole{}
	return func(account string) (*utilisation.TencentCVM, error) {
		r, ok := roles[account]
		if !ok {
			r = keelRole(st, base, account, role, region)
			r.Endpoint = stsEndpoint
			roles[account] = r
		}
		api, err := utilisation.NewMonitorClient(region, r)
		if err != nil {
			return nil, err
		}
		return &utilisation.TencentCVM{API: api}, nil
	}
}

// tencentWasteScanner scans and cleans each member account through Keel's
// member role there. stsEndpoint overrides the STS host, for tests.
func tencentWasteScanner(st *store.Store, base common.Provider, role, region, stsEndpoint string) func(string) (rightsize.WasteScanner, rightsize.Cleaner, error) {
	return func(account string) (rightsize.WasteScanner, rightsize.Cleaner, error) {
		r := keelRole(st, base, account, role, region)
		r.Endpoint = stsEndpoint
		w, err := tencent.NewWaste(region, r)
		return w, w, err
	}
}

type failingInventory struct{ err error }

func (f failingInventory) InstanceTypes(context.Context, string, []string) (map[string]string, error) {
	return nil, f.err
}

// startMultiCloudBillSync loads FOCUS exports from Azure (Blob, workload
// identity), Google Cloud (Cloud Storage, workload identity federation) and
// Alibaba Cloud (OSS, RRSA) hourly when their bucket is configured (#153).
// All three are keyless (ADR-0007).
func startMultiCloudBillSync(ctx context.Context, st *store.Store, ev budget.Evaluator) error {
	type source struct {
		provider, account string
		objects           cost.Objects
		mode              cost.FileMode
		prefix            string
	}
	var sources []source
	if c := os.Getenv("KEEL_AZURE_BILL_CONTAINER"); c != "" {
		acct, billing := os.Getenv("KEEL_AZURE_BILL_STORAGE_ACCOUNT"), os.Getenv("KEEL_AZURE_BILLING_ACCOUNT")
		if acct == "" || billing == "" {
			return errors.New("KEEL_AZURE_BILL_STORAGE_ACCOUNT and KEEL_AZURE_BILLING_ACCOUNT are required with KEEL_AZURE_BILL_CONTAINER")
		}
		auth, err := azure.FromEnv(azure.StorageScope)
		if err != nil {
			return err
		}
		sources = append(sources, source{"azure", billing, azure.Blob{Account: acct, Container: c, Auth: auth}, cost.LatestExportFolder, os.Getenv("KEEL_AZURE_BILL_PREFIX")})
	}
	if b := os.Getenv("KEEL_GCP_BILL_BUCKET"); b != "" {
		billing := os.Getenv("KEEL_GCP_BILLING_ACCOUNT")
		if billing == "" {
			return errors.New("KEEL_GCP_BILLING_ACCOUNT is required with KEEL_GCP_BILL_BUCKET")
		}
		ts, err := gcp.Keyless(ctx, gcp.ReadOnlyScope)
		if err != nil {
			return err
		}
		sources = append(sources, source{"gcp", billing, gcp.GCS{Bucket: b, Tokens: ts}, cost.LatestExportFolder, os.Getenv("KEEL_GCP_BILL_PREFIX")})
	}
	if b := os.Getenv("KEEL_ALIBABA_BILL_BUCKET"); b != "" {
		payer := os.Getenv("KEEL_ALIBABA_PAYER_ACCOUNT")
		if payer == "" {
			return errors.New("KEEL_ALIBABA_PAYER_ACCOUNT is required with KEEL_ALIBABA_BILL_BUCKET")
		}
		creds, err := alibaba.RRSAFromEnv()
		if err != nil {
			return err
		}
		// Each delivery is month-to-date in a timestamped folder.
		sources = append(sources, source{"alibaba", payer, alibaba.OSS{Bucket: b, Region: envOr("KEEL_ALIBABA_REGION", "ap-southeast-1"), Creds: creds}, cost.LatestExportFolder, os.Getenv("KEEL_ALIBABA_BILL_PREFIX")})
	}
	for _, src := range sources {
		bs := &cost.BillSync{Ingester: &cost.Ingester{Store: st}, Objects: src.objects, Provider: src.provider, BillingAccountID: src.account, Prefix: src.prefix, Mode: src.mode}
		go every(ctx, time.Hour, src.provider+" bill sync", func(ctx context.Context) error {
			rep, err := bs.Run(ctx)
			if err != nil {
				slog.Error("ALERT "+src.provider+" bill sync failed", "err", err)
				return nil
			}
			slog.Info(src.provider+" bill sync", "new_files", rep.NewFiles, "loads", len(rep.Loads))
			if len(rep.Loads) > 0 {
				evaluate(ctx, ev)
			}
			return nil
		})
	}
	return nil
}
