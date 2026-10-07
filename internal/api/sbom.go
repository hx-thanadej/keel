package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/hx-thanadej/keel/internal/attest"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/sbom"
)

// SBOMDeps serves SBOMs and component search (#110).
type SBOMDeps struct {
	Authz   catalog.Authorizer
	Service sbom.Service
	// Releases resolves a Release's Service for pipeline authorisation.
	Releases attest.Service
}

func mountSBOM(mux Mux, a auth.Authenticator, d SBOMDeps) {
	allow := func(r *http.Request, p auth.Principal, action, tenant, id string) error {
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "service", ID: id, TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		return nil
	}
	mux.Handle("POST /v1/tenants/{tenant}/releases/{release}/sbom", authed(a, []string{"tenant", "release"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant, release := r.PathValue("tenant"), r.PathValue("release")
		if p.Kind != auth.KindPipeline {
			if err := allow(r, p, "sbom.submit", tenant, ""); err != nil {
				return err
			}
		}
		svc, err := d.Releases.ReleaseService(r.Context(), tenant, release)
		if err != nil {
			if p.Kind == auth.KindPipeline {
				return catalog.ErrForbidden
			}
			return catalog.ErrNotFound
		}
		if err := allow(r, p, "sbom.submit", tenant, svc); err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 50<<20))
		if err != nil {
			return err
		}
		out, err := d.Service.Submit(r.Context(), tenant, release, raw, actor(p))
		switch {
		case errors.Is(err, sbom.ErrInvalid):
			return errors.Join(catalog.ErrInvalid, err)
		case errors.Is(err, sbom.ErrNotFound):
			return catalog.ErrNotFound
		case err != nil:
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/components", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "release.read", tenant, ""); err != nil {
			return err
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			return errors.Join(catalog.ErrInvalid, errors.New("name is required"))
		}
		out, err := d.Service.Where(r.Context(), tenant, name)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
}
