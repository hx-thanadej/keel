package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/controls"
)

// ControlDeps serves the Controls registry (#116), optionally narrowed to
// one framework with ?framework= (#188, #189).
type ControlDeps struct {
	Authz   catalog.Authorizer
	Service controls.Service
}

func mountControls(mux Mux, a auth.Authenticator, d ControlDeps) {
	mux.Handle("GET /v1/tenants/{tenant}/controls", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "finding.read", Resource: authz.Resource{Type: "control", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		out, err := d.Service.Report(r.Context(), tenant)
		if err != nil {
			return err
		}
		if f := r.URL.Query().Get("framework"); f != "" {
			var ok bool
			if out, ok = out.Only(f); !ok {
				return errors.Join(catalog.ErrInvalid, fmt.Errorf("unknown framework %q", f))
			}
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
