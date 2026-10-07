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
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	awscreds "github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/hx-thanadej/keel/internal/anomaly"
	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/archive"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/catalogsync"
	awsadapter "github.com/hx-thanadej/keel/internal/cloud/aws"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/discovery"
	"github.com/hx-thanadej/keel/internal/fx"
	"github.com/hx-thanadej/keel/internal/integrity"
	"github.com/hx-thanadej/keel/internal/oidcauth"
	"github.com/hx-thanadej/keel/internal/store"
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
	evaluator := budget.Evaluator{Service: budget.Service{Store: st}}
	go fxLoop(ctx, st)
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
	if raw := os.Getenv("KEEL_DEV_PRINCIPAL"); raw != "" {
		authn, err := devAuthenticator(raw)
		if err != nil {
			pool.Close()
			return api.Deps{}, noop, err
		}
		deps.Auth, deps.Sessions = authn, authn
		return deps, pool.Close, nil
	}
	sessions, err := signIn(st)
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	deps.Auth, deps.Sessions = sessions, sessions
	return deps, pool.Close, nil
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
