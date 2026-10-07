// Command keel-api serves the Keel control-plane API.
//
// Environment:
//
//	KEEL_ADDR           listen address (default :8080)
//	KEEL_DATABASE_URL   Postgres URL for the application role (keel_app)
//	KEEL_MIGRATE_URL    optional Postgres URL for the owner role; if set, migrations run at start
//	KEEL_ENV            "dev" enables KEEL_DEV_PRINCIPAL
//	KEEL_DEV_PRINCIPAL  JSON Principal every request is authenticated as (dev only)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
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
	authn, err := authenticator()
	if err != nil {
		pool.Close()
		return api.Deps{}, noop, err
	}
	return api.Deps{Auth: authn, Catalog: catalog.New(store.New(pool), az)}, pool.Close, nil
}

func authenticator() (auth.Authenticator, error) {
	raw := os.Getenv("KEEL_DEV_PRINCIPAL")
	if raw == "" {
		return nil, errors.New("no authenticator configured (OIDC arrives in #21; for local dev set KEEL_ENV=dev and KEEL_DEV_PRINCIPAL)")
	}
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
