package api

import (
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/scorecard"
)

// ScorecardDeps serves Scorecards (#149).
type ScorecardDeps struct {
	Authz   catalog.Authorizer
	Service scorecard.Service
}

func mountScorecards(mux Mux, a auth.Authenticator, d ScorecardDeps) {
	mux.Handle("GET /v1/tenants/{tenant}/scorecards", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "service.read", Resource: authz.Resource{Type: "service", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		out, err := d.Service.Compute(r.Context(), tenant)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
