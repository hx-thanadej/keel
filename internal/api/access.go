package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/access"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// AccessDeps serves roles and Access Grants (M5).
type AccessDeps struct {
	Authz   catalog.Authorizer
	Service *access.Service
}

func accessErr(err error) error {
	switch {
	case errors.Is(err, access.ErrNotFound):
		return catalog.ErrNotFound
	case errors.Is(err, access.ErrState):
		return errors.Join(catalog.ErrConflict, err)
	case errors.Is(err, access.ErrInvalid):
		return errors.Join(catalog.ErrInvalid, err)
	}
	return err
}

func (d AccessDeps) allow(r *http.Request, p auth.Principal, action, tenant string) error {
	dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "access", TenantID: tenant}})
	if err != nil {
		return err
	}
	if !dec.Allow {
		return catalog.ErrForbidden
	}
	return nil
}

func mountAccess(mux Mux, a auth.Authenticator, d AccessDeps) {
	mux.Handle("GET /v1/tenants/{tenant}/access/templates", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := d.allow(r, p, "access.read", r.PathValue("tenant")); err != nil {
			return err
		}
		out := []access.Template{}
		for _, name := range []string{"read-only", "data-reader", "deployer", "operator"} {
			out = append(out, access.Templates[name])
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/access/roles", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "access.read", tenant); err != nil {
			return err
		}
		out, err := d.Service.Roles(r.Context(), tenant)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/access/roles", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "access.request_role", tenant); err != nil {
			return err
		}
		var in struct {
			EnvironmentID string `json:"environment_id"`
			TeamID        string `json:"team_id"`
			Template      string `json:"template"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		if !catalog.ValidID(in.EnvironmentID) || !catalog.ValidID(in.TeamID) {
			return errors.Join(catalog.ErrInvalid, errors.New("environment_id and team_id must be uuids"))
		}
		out, err := d.Service.RequestRole(r.Context(), tenant, in.EnvironmentID, in.TeamID, in.Template, actor(p))
		if err != nil {
			return accessErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/access/roles/{role}/decide", authed(a, []string{"tenant", "role"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "access.approve_role", tenant); err != nil {
			return err
		}
		var in struct{ Approve bool }
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Service.DecideRole(r.Context(), tenant, r.PathValue("role"), in.Approve, actor(p))
		if err != nil {
			return accessErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
