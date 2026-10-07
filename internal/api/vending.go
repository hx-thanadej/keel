package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/vending"
)

// VendingDeps serves account vending (#88).
type VendingDeps struct {
	Authz   catalog.Authorizer
	Engine  *flow.Engine
	Vendors map[string]vending.Vendor // by provider
}

func mountVending(mux Mux, a auth.Authenticator, d VendingDeps) {
	mux.Handle("POST /v1/tenants/{tenant}/projects/{project}/environments/{env}/vend", authed(a, []string{"tenant", "project", "env"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "environment.vend", Resource: authz.Resource{Type: "environment", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		var in struct{ Provider string }
		if err := decode(r, &in); err != nil {
			return err
		}
		v, ok := d.Vendors[in.Provider]
		if !ok {
			return errors.Join(catalog.ErrInvalid, errors.New("vending is not configured for provider "+in.Provider))
		}
		f, created, err := v.Request(r.Context(), d.Engine, tenant, r.PathValue("project"), r.PathValue("env"), actor(p))
		switch {
		case errors.Is(err, vending.ErrNotFound):
			return catalog.ErrNotFound
		case errors.Is(err, vending.ErrAlreadyVended):
			return errors.Join(catalog.ErrConflict, err)
		case err != nil:
			return err
		}
		status := http.StatusAccepted
		if !created {
			status = http.StatusOK
		}
		writeJSON(w, status, f)
		return nil
	}))
}
