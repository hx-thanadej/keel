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
//	KEEL_ARCHIVE_BUCKET   S3-compatible bucket for the WORM Activity Log archive (with KEEL_DIGEST_KEY)
//	KEEL_ARCHIVE_ENDPOINT e.g. cos.ap-bangkok.myqcloud.com
//	KEEL_ARCHIVE_REGION   e.g. ap-bangkok; credentials are Tencent STS (keyless)
//	KEEL_TENCENT_BILL_BUCKET   COS bucket where the payer's Bill Storage delivers FOCUS bills
//	KEEL_TENCENT_BILL_PREFIX   object prefix of the FOCUS bill files
//	KEEL_TENCENT_PAYER_UIN     payer account id (FOCUS BillingAccountId)
//	KEEL_TENCENT_BILL_MODE     per-day (default) | cumulative; confirm on first delivery
//	KEEL_TENCENT_REGION        region for billing API and COS (default ap-bangkok)
//	KEEL_AWS_BILL_BUCKET      S3 bucket of the AWS Data Exports FOCUS 1.2 export (CSV)
//	KEEL_AWS_BILL_PREFIX      export prefix
//	KEEL_AWS_PAYER_ACCOUNT    management account id (FOCUS BillingAccountId)
//	KEEL_AWS_REGION           bucket region; credentials: AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE
//	KEEL_TENCENT_BUDGETS=1    mirror opted-in Budgets to Tencent Cloud budgets (payer credentials)
//	KEEL_AWS_BUDGET_ACCOUNT   mirror opted-in Budgets to AWS Budgets in this management account
//	KEEL_AWS_BUDGET_EMAIL     optional subscriber so AWS budgets also carry the thresholds
//	KEEL_PROMETHEUS     cluster=url[@tenant/project/env][,…]: per-container utilisation for rightsizing
//	KEEL_TENCENT_MEMBER_ROLE  role Keel assumes in member accounts to read Cloud Monitor (CVM utilisation)
//	KEEL_AWS_COH=1      import AWS Cost Optimization Hub recommendations (management account, web identity)
//	KEEL_WASTE_CLEANUP=1      allow deleting waste in opted-in non-prod Environments after the grace period
//	KEEL_WASTE_GRACE_DAYS     days a waste recommendation must stay open first (default 7)
//	KEEL_GITHUB_WRITE_TOKEN   lets Keel open rightsizing pull requests (contents:write, pull_requests:write)
//	KEEL_OPENCOST       cluster=url[,cluster=url]: per-namespace daily cost for k8s allocation rules
//	KEEL_GITHUB_OWNER   user/org whose repos' catalog-info.yaml are synced every 10 min
//	KEEL_GITHUB_ORG=1   KEEL_GITHUB_OWNER is an organisation
//	KEEL_GITHUB_TOKEN   read-only token (contents + metadata)
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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	awscreds "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/riverqueue/river"

	"github.com/hx-thanadej/keel/internal/anomaly"
	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/apply"
	"github.com/hx-thanadej/keel/internal/archive"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/catalogsync"
	"github.com/hx-thanadej/keel/internal/ciidentity"
	awsadapter "github.com/hx-thanadej/keel/internal/cloud/aws"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/discovery"
	"github.com/hx-thanadej/keel/internal/findings"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/fx"
	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/githubgov"
	"github.com/hx-thanadej/keel/internal/integrity"
	"github.com/hx-thanadej/keel/internal/landingzone"
	"github.com/hx-thanadej/keel/internal/oidcauth"
	"github.com/hx-thanadej/keel/internal/promotion"
	"github.com/hx-thanadej/keel/internal/registry"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/templates"
	"github.com/hx-thanadej/keel/internal/utilisation"
	"github.com/hx-thanadej/keel/internal/vending"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		cmds := map[string]func([]string) error{"bootstrap": bootstrap, "digest-pubkey": digestPubkey, "verify-log": verifyLog, "verify-archive": verifyArchive}
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
	deps := api.Deps{Catalog: catalog.New(st, az), Discovery: map[string]discovery.Source{},
		Cost:    &api.CostDeps{Authz: az, Queries: cost.Queries{Store: st}, Ingester: &cost.Ingester{Store: st}, Rules: cost.Rules{Store: st}},
		Budgets: &api.BudgetDeps{Authz: az, Budgets: budget.Service{Store: st}}}
	deps.Budgets.Catalog = deps.Catalog
	deps.Authz = az
	deps.Rightsize = &api.RightsizeDeps{Authz: az, Service: rightsize.Service{Store: st}}
	if tok := os.Getenv("KEEL_GITHUB_WRITE_TOKEN"); tok != "" {
		deps.Rightsize.Applier = &apply.Applier{Recs: rightsize.Service{Store: st}, Git: apply.GitHub{Token: tok}}
	}
	promoSvc := promotion.Service{Store: st, PathTemplate: os.Getenv("KEEL_PROMOTION_PATH"), AppTemplate: os.Getenv("KEEL_ARGOCD_APP")}
	if tok := os.Getenv("KEEL_GITHUB_WRITE_TOKEN"); tok != "" {
		promoSvc.Git = apply.GitHub{Token: tok}
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
	if err := startUtilisation(ctx, st); err != nil {
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
	if tok := os.Getenv("KEEL_GITHUB_ADMIN_TOKEN"); tok != "" && os.Getenv("KEEL_GITHUB_OWNER") != "" {
		var checks []string
		for _, c := range strings.Split(os.Getenv("KEEL_GITHUB_REQUIRED_CHECKS"), ",") {
			if c = strings.TrimSpace(c); c != "" {
				checks = append(checks, c)
			}
		}
		gov := githubgov.Reconciler{Store: st, Policy: githubgov.Default(checks), Remediate: os.Getenv("KEEL_GITHUB_REMEDIATE") == "1",
			API: githubgov.GitHub{Client: ghapi.Client{Token: tok}, Login: os.Getenv("KEEL_GITHUB_OWNER"), Org: os.Getenv("KEEL_GITHUB_ORG") == "1"}}
		go every(ctx, time.Hour, "github governance", func(ctx context.Context) error {
			rep, err := gov.Run(ctx)
			if err == nil {
				slog.Info("github governance", "plan", rep.Plan, "mode", rep.Mode, "repos", rep.Repos, "drift", len(rep.Items))
			}
			return err
		})
	}
	if owner := os.Getenv("KEEL_GITHUB_OWNER"); owner != "" {
		syncer := &catalogsync.Syncer{Store: st, Source: &catalogsync.GitHub{Owner: owner, Org: os.Getenv("KEEL_GITHUB_ORG") == "1", Token: os.Getenv("KEEL_GITHUB_TOKEN")}}
		go syncer.Every(ctx, 10*time.Minute)
	}
	if err := startBillSync(ctx, st, evaluator); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	if err := startAWSBillSync(ctx, st, evaluator); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	if err := startSealer(ctx, st); err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	vendors := vendors(ctx, st)
	creator, err := templateCreator(st)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	defs := flowDefs(vendors)
	if creator != nil {
		defs = append(defs, creator.Def())
	}
	engine, stopJobs, err := startFlows(ctx, st, defs)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	deps.Flows = &api.FlowDeps{Authz: az, Engine: engine}
	deps.Registry = &api.RegistryDeps{Authz: az, Store: st}
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
		deps.Auth, deps.Sessions = authn, authn
		return deps, cleanup, nil
	}
	sessions, err := signIn(st)
	if err != nil {
		cleanup()
		return api.Deps{}, noop, err
	}
	deps.Auth, deps.Sessions = sessions, sessions
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
				api, err := tencent.NewCAM(&tencent.MemberRole{Base: tencent.Credentials(), Account: account, Role: accessRole, Region: region})
				return tencent.CIIdentity{API: api}, err
			}}
		steps := []flow.Step{landingzone.Step(st, guardrails, baseline), ci.Step()}
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

// templateCreator configures Service Templates (#92) from
// KEEL_TEMPLATES="name=owner/repo@sha,..." in the KEEL_GITHUB_OWNER org.
func templateCreator(st *store.Store) (*templates.Creator, error) {
	raw, tok := os.Getenv("KEEL_TEMPLATES"), os.Getenv("KEEL_GITHUB_ADMIN_TOKEN")
	if raw == "" || tok == "" {
		return nil, nil
	}
	c := &templates.Creator{Store: st, Git: templates.GitHub{Client: ghapi.Client{Token: tok}}, Org: os.Getenv("KEEL_GITHUB_OWNER"),
		ReusableWorkflow: os.Getenv("KEEL_REUSABLE_WORKFLOW"), Templates: map[string]templates.Template{}}
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

// startFlows runs River (ADR-0014) for durable flows. The returned func stops
// it, letting running steps finish for up to 30s.
func startFlows(ctx context.Context, st *store.Store, defs []flow.Def) (*flow.Engine, func(), error) {
	engine := flow.New(st, defs...)
	workers := river.NewWorkers()
	engine.Register(workers)
	client, err := flow.NewClient(st.AppPool(), workers, flow.ClientOptions{Logger: slog.Default()})
	if err != nil {
		return nil, nil, fmt.Errorf("river: %w", err)
	}
	engine.SetClient(client)
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
	objs, err := archiveStore()
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

func archiveStore() (archive.ObjectStore, error) {
	bucket := os.Getenv("KEEL_ARCHIVE_BUCKET")
	if bucket == "" {
		return nil, nil
	}
	creds := archive.Refreshing(tencent.STS{Creds: tencent.Credentials()}, 10*time.Minute)
	return archive.NewS3(archive.S3Config{Endpoint: os.Getenv("KEEL_ARCHIVE_ENDPOINT"), Region: os.Getenv("KEEL_ARCHIVE_REGION"), Bucket: bucket, Creds: creds})
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
	objs, err := archiveStore()
	if err != nil || objs == nil {
		return errors.New("set KEEL_ARCHIVE_BUCKET, KEEL_ARCHIVE_ENDPOINT, KEEL_ARCHIVE_REGION")
	}
	r, err := archive.Verify(context.Background(), objs, *tenant, keys)
	if err != nil {
		return err
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
	creds := tencent.Credentials()
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
			rep, err := bs.Run(ctx)
			if err != nil {
				slog.Error("ALERT tencent bill sync failed", "err", err)
			} else {
				slog.Info("tencent bill sync", "new_files", rep.NewFiles, "loads", len(rep.Loads), "skipped", len(rep.Skipped))
				for _, l := range rep.Loads {
					if l.Reconcile == "mismatch" {
						slog.Error("ALERT tencent bill does not reconcile with invoice", "period", l.Period.Format("2006-01"), "load", l.LoadID)
					}
				}
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
func startUtilisation(ctx context.Context, st *store.Store) error {
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
		region := envOr("KEEL_TENCENT_REGION", "ap-bangkok")
		base := tencent.Credentials()
		roles := map[string]*tencent.MemberRole{}
		job.CVM = func(account string) (*utilisation.TencentCVM, error) {
			r, ok := roles[account]
			if !ok {
				r = &tencent.MemberRole{Base: base, Account: account, Role: role, Region: region}
				roles[account] = r
			}
			api, err := utilisation.NewMonitorClient(region, r)
			if err != nil {
				return nil, err
			}
			return &utilisation.TencentCVM{API: api}, nil
		}
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
		rightsizeAll(ctx, st)
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
			rightsizeAll(ctx, st)
		}
	}()
	return nil
}

// rightsizeAll runs Keel's rightsizing engines over fresh utilisation.
func rightsizeAll(ctx context.Context, st *store.Store) {
	if tok := os.Getenv("KEEL_GITHUB_WRITE_TOKEN"); tok != "" {
		a := apply.Applier{Recs: rightsize.Service{Store: st}, Git: apply.GitHub{Token: tok}}
		if res, err := a.Sync(ctx); err != nil {
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
	catAPI, err := tencent.NewCVM(region, base)
	if err != nil {
		slog.Error("cvm catalogue", "err", err)
		return
	}
	vm := rightsize.VMEngine{Service: rightsize.Service{Store: st}, Catalog: tencent.Catalog{API: catAPI}, Region: region,
		Inventory: func(account string) rightsize.Inventory {
			api, err := tencent.NewCVM(region, &tencent.MemberRole{Base: base, Account: account, Role: role, Region: region})
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
		Scanner: func(account string) (rightsize.WasteScanner, rightsize.Cleaner, error) {
			w, err := tencent.NewWaste(region, &tencent.MemberRole{Base: base, Account: account, Role: role, Region: region})
			return w, w, err
		}}
	if res, err := waste.Run(ctx); err != nil {
		slog.Error("waste scan failed", "err", err)
	} else {
		slog.Info("waste", "raised", res.Raised, "kept", res.Kept, "deleted", res.Deleted, "errors", res.Errors)
	}
}

type failingInventory struct{ err error }

func (f failingInventory) InstanceTypes(context.Context, string, []string) (map[string]string, error) {
	return nil, f.err
}
