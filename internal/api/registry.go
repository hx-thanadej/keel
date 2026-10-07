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

// RegistryDeps serves the registry egress report (#94) and short-lived
// push tokens for pipelines (#104).
type RegistryDeps struct {
	Authz  catalog.Authorizer
	Store  *store.Store
	Broker registry.Broker // nil: tokens not configured
	Domain string          // e.g. acme.tencentcloudcr.com
}

func mountRegistry(mux Mux, a auth.Authenticator, d RegistryDeps) {
	mux.Handle("POST /v1/tenants/{tenant}/services/{service}/registry-token", authed(a, []string{"tenant", "service"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant, service := r.PathValue("tenant"), r.PathValue("service")
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "registry.push", Resource: authz.Resource{Type: "service", ID: service, TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		if d.Broker == nil {
			return errors.Join(catalog.ErrInvalid, errors.New("registry tokens are not configured (KEEL_TCR_REGISTRY_ID)"))
		}
		c, err := registry.IssueToken(r.Context(), d.Store, d.Broker, d.Domain, tenant, service, actor(p))
		switch {
		case errors.Is(err, registry.ErrNotFound):
			return catalog.ErrNotFound
		case errors.Is(err, registry.ErrNoNamespace):
			return errors.Join(catalog.ErrConflict, err)
		case err != nil:
			return err
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, c)
		return nil
	}))
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
