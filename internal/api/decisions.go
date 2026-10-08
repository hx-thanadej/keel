package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/decisions"
)

func mountDecisions(mux Mux, a auth.Authenticator, c *catalog.Service, az catalog.Authorizer) {
	mux.Handle("GET /v1/tenants/{tenant}/decisions", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		dec, err := az.Decide(r.Context(), authz.Request{Principal: p, Action: "service.read", Resource: authz.Resource{Type: "service", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		q := r.URL.Query()
		svc := q.Get("service")
		if svc != "" && !catalog.ValidID(svc) {
			return errors.Join(catalog.ErrInvalid, errors.New("service must be a uuid"))
		}
		out, err := decisions.Search(r.Context(), c.Store(), tenant, q.Get("q"), svc)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
}
