package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/breakglass"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// BreakGlassDeps serves the break-glass registry (#135). It is platform
// data in the home Tenant.
type BreakGlassDeps struct {
	Authz   catalog.Authorizer
	Service breakglass.Service
	Home    func(r *http.Request) (string, error)
}

func mountBreakGlass(mux Mux, a auth.Authenticator, d BreakGlassDeps) {
	allow := func(r *http.Request, p auth.Principal) error {
		home, err := d.Home(r)
		if err != nil {
			return err
		}
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "breakglass.manage", Resource: authz.Resource{Type: "breakglass", TenantID: home}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		return nil
	}
	errs := func(err error) error {
		switch {
		case errors.Is(err, breakglass.ErrInvalid):
			return errors.Join(catalog.ErrInvalid, err)
		case errors.Is(err, breakglass.ErrNotFound):
			return catalog.ErrNotFound
		}
		return err
	}
	mux.Handle("GET /v1/breakglass", authed(a, nil, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p); err != nil {
			return err
		}
		out, err := d.Service.List(r.Context())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/breakglass", authed(a, nil, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p); err != nil {
			return err
		}
		var in breakglass.Identity
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Service.Register(r.Context(), in, actor(p))
		if err != nil {
			return errs(err)
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("POST /v1/breakglass/{identity}/drill", authed(a, []string{"identity"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p); err != nil {
			return err
		}
		var in struct{ Notes string }
		if err := decode(r, &in); err != nil {
			return err
		}
		if err := d.Service.Drill(r.Context(), r.PathValue("identity"), in.Notes, actor(p)); err != nil {
			return errs(err)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
		return nil
	}))
	mux.Handle("POST /v1/breakglass/uses/{use}/postmortem", authed(a, []string{"use"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p); err != nil {
			return err
		}
		var in struct{ URL string }
		if err := decode(r, &in); err != nil {
			return err
		}
		if err := d.Service.PostMortem(r.Context(), r.PathValue("use"), in.URL, actor(p)); err != nil {
			return errs(err)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
		return nil
	}))
}
