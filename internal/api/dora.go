package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/dora"
)

// DORADeps serves DORA metrics (#148).
type DORADeps struct {
	Authz   catalog.Authorizer
	Service dora.Service
}

func mountDORA(mux Mux, a auth.Authenticator, d DORADeps) {
	allow := func(r *http.Request, p auth.Principal, action, tenant string) error {
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "promotion", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		return nil
	}
	mux.Handle("GET /v1/tenants/{tenant}/dora", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "promotion.read", tenant); err != nil {
			return err
		}
		q := r.URL.Query()
		to := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 1)
		from := to.AddDate(0, 0, -30)
		var err error
		if v := q.Get("from"); v != "" {
			if from, err = time.Parse("2006-01-02", v); err != nil {
				return errors.Join(catalog.ErrInvalid, errors.New("from is YYYY-MM-DD"))
			}
		}
		if v := q.Get("to"); v != "" {
			if to, err = time.Parse("2006-01-02", v); err != nil {
				return errors.Join(catalog.ErrInvalid, errors.New("to is YYYY-MM-DD"))
			}
		}
		if !from.Before(to) || to.Sub(from) > 366*24*time.Hour {
			return errors.Join(catalog.ErrInvalid, errors.New("from must be before to, at most a year apart"))
		}
		out, err := d.Service.Compute(r.Context(), tenant, from, to)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/promotions/{promotion}/failed", authed(a, []string{"tenant", "promotion"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "promotion.request", tenant); err != nil {
			return err
		}
		var in struct{ Reason string }
		if err := decode(r, &in); err != nil {
			return err
		}
		if in.Reason == "" {
			return errors.Join(catalog.ErrInvalid, errors.New("reason is required"))
		}
		err := d.Service.MarkFailed(r.Context(), tenant, r.PathValue("promotion"), in.Reason, time.Now(), actor(p))
		if errors.Is(err, dora.ErrNotFound) {
			return errors.Join(catalog.ErrConflict, errors.New("not a deployed, unfailed deployment"))
		}
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "marked failed"})
		return nil
	}))
}
