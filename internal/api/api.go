// Package api is Keel's HTTP surface.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// Info is build metadata exposed on /healthz.
type Info struct {
	Version string
}

// Deps are the services the API serves. Nil services are not mounted.
type Deps struct {
	Auth     auth.Authenticator
	Sessions Mounter // sign-in routes under /auth
	Catalog  *catalog.Service
}

// Mounter registers its own routes.
type Mounter interface{ Mount(*http.ServeMux) }

// NewRouter returns the Keel API handler.
func NewRouter(info Info, deps Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": info.Version})
	})
	if deps.Sessions != nil {
		deps.Sessions.Mount(mux)
	}
	if deps.Catalog != nil && deps.Auth != nil {
		mountCatalog(mux, deps.Catalog, deps.Auth)
	}
	// Session cookies make cross-site writes possible; reject them (CSRF).
	return http.NewCrossOriginProtection().Handler(mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
