package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/vex"
)

// VEXDeps serves VEX statements (#111).
type VEXDeps struct {
	Authz   catalog.Authorizer
	Service vex.Service
	Author  string // OpenVEX document author, e.g. the Keel base URL
}

func mountVEX(mux Mux, a auth.Authenticator, d VEXDeps) {
	allow := func(r *http.Request, p auth.Principal, action, tenant string) error {
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "service", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		return nil
	}
	mux.Handle("POST /v1/tenants/{tenant}/vex", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "vex.record", tenant); err != nil {
			return err
		}
		var in vex.Statement
		if err := decode(r, &in); err != nil {
			return err
		}
		if !catalog.ValidID(in.ServiceID) || (in.ReleaseID != nil && !catalog.ValidID(*in.ReleaseID)) {
			return errors.Join(catalog.ErrInvalid, errors.New("service_id and release_id must be uuids"))
		}
		out, err := d.Service.Record(r.Context(), tenant, in, actor(p))
		switch {
		case errors.Is(err, vex.ErrInvalid):
			return errors.Join(catalog.ErrInvalid, err)
		case errors.Is(err, vex.ErrNotFound):
			return catalog.ErrNotFound
		case err != nil:
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/vex", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "release.read", tenant); err != nil {
			return err
		}
		svc := r.URL.Query().Get("service")
		if svc != "" && !catalog.ValidID(svc) {
			return errors.Join(catalog.ErrInvalid, errors.New("service must be a uuid"))
		}
		out, err := d.Service.List(r.Context(), tenant, svc)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/releases/{release}/vex", authed(a, []string{"tenant", "release"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "release.read", tenant); err != nil {
			return err
		}
		doc, err := d.Service.Document(r.Context(), tenant, r.PathValue("release"), d.Author)
		if errors.Is(err, vex.ErrNotFound) {
			return catalog.ErrNotFound
		}
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
		return nil
	}))
}
