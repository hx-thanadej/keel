package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/pdpa"
)

// PDPADeps serves a Tenant's PDPA settings and breach clock (#190).
type PDPADeps struct {
	Authz   catalog.Authorizer
	Service pdpa.Service
}

func pdpaErr(err error) error {
	switch {
	case errors.Is(err, pdpa.ErrNotFound):
		return catalog.ErrNotFound
	case errors.Is(err, pdpa.ErrState):
		return errors.Join(catalog.ErrConflict, err)
	case errors.Is(err, pdpa.ErrInvalid):
		return errors.Join(catalog.ErrInvalid, err)
	}
	return err
}

func mountPDPA(mux Mux, a auth.Authenticator, d PDPADeps) {
	allow := func(r *http.Request, p auth.Principal, action string) error {
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "pdpa", TenantID: r.PathValue("tenant")}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		return nil
	}
	mux.Handle("GET /v1/tenants/{tenant}/pdpa", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "pdpa.read"); err != nil {
			return err
		}
		out, err := d.Service.Overview(r.Context(), r.PathValue("tenant"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("PUT /v1/tenants/{tenant}/pdpa/settings", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "pdpa.configure"); err != nil {
			return err
		}
		var in struct {
			DataRegions     []string `json:"data_regions"`
			DeletionEnabled bool     `json:"deletion_enabled"`
			LegalHold       string   `json:"legal_hold"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Service.Configure(r.Context(), r.PathValue("tenant"), pdpa.Settings{DataRegions: in.DataRegions, DeletionEnabled: in.DeletionEnabled, LegalHold: in.LegalHold}, actor(p))
		if err != nil {
			return pdpaErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/pdpa/breaches", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "pdpa.breach"); err != nil {
			return err
		}
		var in pdpa.Declaration
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Service.Declare(r.Context(), r.PathValue("tenant"), in, actor(p))
		if err != nil {
			return pdpaErr(err)
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/pdpa/breaches/{breach}/notify", authed(a, []string{"tenant", "breach"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "pdpa.breach"); err != nil {
			return err
		}
		var in pdpa.Notification
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Service.Notify(r.Context(), r.PathValue("tenant"), r.PathValue("breach"), in, actor(p))
		if err != nil {
			return pdpaErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/pdpa/breaches/{breach}/close", authed(a, []string{"tenant", "breach"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "pdpa.breach"); err != nil {
			return err
		}
		var in struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Service.Close(r.Context(), r.PathValue("tenant"), r.PathValue("breach"), in.Reason, actor(p))
		if err != nil {
			return pdpaErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
