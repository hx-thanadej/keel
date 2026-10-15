package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/connections"
)

// ConnectionDeps serves cloud connections (#251, ADR-0022). They are
// platform data in the home Tenant. Responses never carry key material.
type ConnectionDeps struct {
	Authz   catalog.Authorizer
	Service connections.Service
	Home    func(r *http.Request) (string, error)
}

func mountConnections(mux Mux, a auth.Authenticator, d ConnectionDeps) {
	allow := func(r *http.Request, p auth.Principal, action string) error {
		home, err := d.Home(r)
		if err != nil {
			return err
		}
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "cloud_connection", TenantID: home}})
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
		case errors.Is(err, connections.ErrInvalid):
			return errors.Join(catalog.ErrInvalid, err)
		case errors.Is(err, connections.ErrNotFound):
			return catalog.ErrNotFound
		case errors.Is(err, connections.ErrConflict), errors.Is(err, connections.ErrNoSecretsKey):
			return conflict{err}
		case errors.Is(err, connections.ErrUnopenable):
			return conflict{connections.ErrUnopenable}
		}
		return err
	}
	mux.Handle("GET /v1/cloud-connections", authed(a, nil, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "cloud_connection.read"); err != nil {
			return err
		}
		out, err := d.Service.List(r.Context())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/cloud-connections", authed(a, nil, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "cloud_connection.manage"); err != nil {
			return err
		}
		var in connections.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Service.Create(r.Context(), in, actor(p))
		if err != nil {
			return errs(err)
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("PATCH /v1/cloud-connections/{connection}", authed(a, []string{"connection"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "cloud_connection.manage"); err != nil {
			return err
		}
		var in connections.Change
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Service.Update(r.Context(), r.PathValue("connection"), in, actor(p))
		if err != nil {
			return errs(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("DELETE /v1/cloud-connections/{connection}", authed(a, []string{"connection"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "cloud_connection.manage"); err != nil {
			return err
		}
		if err := d.Service.Delete(r.Context(), r.PathValue("connection"), actor(p)); err != nil {
			return errs(err)
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.Handle("POST /v1/cloud-connections/{connection}/test", authed(a, []string{"connection"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "cloud_connection.manage"); err != nil {
			return err
		}
		out, err := d.Service.Test(r.Context(), r.PathValue("connection"), actor(p))
		if err != nil {
			return errs(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}

// conflict is a 409 whose message is err's alone.
type conflict struct{ error }

func (c conflict) Is(target error) bool { return target == catalog.ErrConflict }
func (c conflict) Unwrap() error        { return c.error }
