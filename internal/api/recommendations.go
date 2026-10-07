package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/rightsize"
)

// RightsizeDeps serves Rightsizing Recommendations.
type RightsizeDeps struct {
	Authz   catalog.Authorizer
	Service rightsize.Service
}

func (d RightsizeDeps) allow(r *http.Request, p auth.Principal, action, tenant string) error {
	dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "recommendation", TenantID: tenant}})
	if err != nil {
		return err
	}
	if !dec.Allow {
		return catalog.ErrForbidden
	}
	return nil
}

func rightsizeErr(err error) error {
	switch {
	case errors.Is(err, rightsize.ErrNotFound):
		return catalog.ErrNotFound
	case errors.Is(err, rightsize.ErrState):
		return errors.Join(catalog.ErrConflict, err)
	case errors.Is(err, rightsize.ErrInvalid):
		return errors.Join(catalog.ErrInvalid, err)
	}
	return err
}

func mountRightsize(mux Mux, a auth.Authenticator, d RightsizeDeps) {
	mux.Handle("GET /v1/tenants/{tenant}/recommendations", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "recommendation.read", tenant); err != nil {
			return err
		}
		q := r.URL.Query()
		state := q.Get("state")
		if state != "" && state != "open" && state != "accepted" && state != "applied" && state != "dismissed" && state != "superseded" {
			return errors.Join(catalog.ErrInvalid, errors.New("unknown state"))
		}
		if pr := q.Get("project"); pr != "" && !catalog.ValidID(pr) {
			return errors.Join(catalog.ErrInvalid, errors.New("project must be a uuid"))
		}
		out, err := d.Service.List(r.Context(), tenant, rightsize.Filter{State: state, ProjectID: q.Get("project")})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/recommendations/{recommendation}/accept", authed(a, []string{"tenant", "recommendation"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "recommendation.decide", tenant); err != nil {
			return err
		}
		out, err := d.Service.Accept(r.Context(), tenant, r.PathValue("recommendation"), actor(p))
		if err != nil {
			return rightsizeErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/recommendations/{recommendation}/dismiss", authed(a, []string{"tenant", "recommendation"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "recommendation.decide", tenant); err != nil {
			return err
		}
		var in struct{ Reason string }
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Service.Dismiss(r.Context(), tenant, r.PathValue("recommendation"), in.Reason, actor(p))
		if err != nil {
			return rightsizeErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
