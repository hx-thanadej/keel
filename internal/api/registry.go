package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/registry"
	"github.com/hx-thanadej/keel/internal/store"
)

// RegistryDeps serves the registry egress report (#94).
type RegistryDeps struct {
	Authz catalog.Authorizer
	Store *store.Store
}

func mountRegistry(mux Mux, a auth.Authenticator, d RegistryDeps) {
	mux.Handle("GET /v1/tenants/{tenant}/projects/{project}/registry", authed(a, []string{"tenant", "project"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "cost.read", Resource: authz.Resource{Type: "cost", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		out, err := registry.Report(r.Context(), d.Store, tenant, r.PathValue("project"), 14, time.Now())
		if errors.Is(err, registry.ErrNotFound) {
			return catalog.ErrNotFound
		}
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
