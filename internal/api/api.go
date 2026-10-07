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
	Auth    auth.Authenticator
	Catalog *catalog.Service
}

// NewRouter returns the Keel API handler.
func NewRouter(info Info, deps Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": info.Version})
	})
	if deps.Catalog != nil && deps.Auth != nil {
		mountCatalog(mux, deps.Catalog, deps.Auth)
	}
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
