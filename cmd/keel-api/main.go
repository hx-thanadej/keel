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

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/catalogsync"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/discovery"
	"github.com/hx-thanadej/keel/internal/integrity"
	"github.com/hx-thanadej/keel/internal/oidcauth"
	"github.com/hx-thanadej/keel/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		cmds := map[string]func([]string) error{"bootstrap": bootstrap, "digest-pubkey": digestPubkey, "verify-log": verifyLog}
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
	deps := api.Deps{Catalog: catalog.New(st, az), Discovery: map[string]discovery.Source{}}
	if region := os.Getenv("KEEL_TENCENT_ORG_REGION"); region != "" {
		deps.Discovery["tencent"] = tencent.OrgSource{Region: region, Creds: tencent.Credentials()}
	}
	if owner := os.Getenv("KEEL_GITHUB_OWNER"); owner != "" {
		syncer := &catalogsync.Syncer{Store: st, Source: &catalogsync.GitHub{Owner: owner, Org: os.Getenv("KEEL_GITHUB_ORG") == "1", Token: os.Getenv("KEEL_GITHUB_TOKEN")}}
		go syncer.Every(ctx, 10*time.Minute)
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
		deps.Auth = authn
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

func devAuthenticator(raw string) (auth.Authenticator, error) {
	if os.Getenv("KEEL_ENV") != "dev" {
		return nil, errors.New("KEEL_DEV_PRINCIPAL is only allowed with KEEL_ENV=dev")
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
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			if err := sealer.SealAll(ctx); err != nil {
				slog.Error("ALERT activity log sealing failed", "err", err)
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
	keys := map[string]ed25519.PublicKey{}
	for _, p := range strings.Split(*pubs, ",") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("bad public key %q", p)
		}
		keys[integrity.KeyID(b)] = b
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
