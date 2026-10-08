package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/maturity"
)

// MaturityDeps serves the platform maturity self-assessment (#154).
type MaturityDeps struct {
	Authz   catalog.Authorizer
	Service maturity.Service
}

func mountMaturity(mux Mux, a auth.Authenticator, d MaturityDeps) {
	allow := func(r *http.Request, p auth.Principal, action, tenant string) error {
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "maturity", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		return nil
	}
	mapErr := func(err error) error {
		if errors.Is(err, maturity.ErrInvalid) {
			return errors.Join(catalog.ErrInvalid, err)
		}
		return err
	}
	// The questionnaire, this quarter's measured indicators and the trend.
	mux.Handle("GET /v1/tenants/{tenant}/maturity", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "maturity.read", tenant); err != nil {
			return err
		}
		q, err := maturity.Load()
		if err != nil {
			return err
		}
		quarter := d.Service.CurrentQuarter()
		ind, err := d.Service.Measure(r.Context(), tenant, quarter)
		if err != nil {
			return err
		}
		trend, err := d.Service.List(r.Context(), tenant)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"questionnaire": q, "quarter": quarter, "indicators": ind, "assessments": trend})
		return nil
	}))
	mux.Handle("PUT /v1/tenants/{tenant}/maturity/{quarter}", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "maturity.submit", tenant); err != nil {
			return err
		}
		var body struct {
			Answers map[string]maturity.Answer `json:"answers"`
		}
		if err := decode(r, &body); err != nil {
			return err
		}
		out, err := d.Service.Submit(r.Context(), tenant, r.PathValue("quarter"), body.Answers, actor(p))
		if err != nil {
			return mapErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
