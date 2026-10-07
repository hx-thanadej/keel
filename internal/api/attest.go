package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/hx-thanadej/keel/internal/attest"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// AttestDeps serves the release policy (#112).
type AttestDeps struct {
	Authz   catalog.Authorizer
	Service attest.Service
}

func mountAttest(mux Mux, a auth.Authenticator, d AttestDeps) {
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
	notFound := func(err error) error {
		if errors.Is(err, attest.ErrNotFound) {
			return catalog.ErrNotFound
		}
		return err
	}
	mux.Handle("POST /v1/tenants/{tenant}/releases/{release}/attestations", authed(a, []string{"tenant", "release"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant, release := r.PathValue("tenant"), r.PathValue("release")
		// Decide on the tenant first so a foreign principal learns nothing about the release.
		if err := allow(r, p, "attestation.submit", tenant, ""); err != nil && p.Kind != auth.KindPipeline {
			return err
		}
		svc, err := d.Service.ReleaseService(r.Context(), tenant, release)
		if err != nil {
			if p.Kind == auth.KindPipeline {
				return catalog.ErrForbidden
			}
			return notFound(err)
		}
		if err := allow(r, p, "attestation.submit", tenant, svc); err != nil {
			return err
		}
		bundle, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			return err
		}
		out, err := d.Service.Submit(r.Context(), tenant, release, bundle, actor(p))
		if errors.Is(err, attest.ErrInvalid) {
			return errors.Join(catalog.ErrInvalid, err)
		}
		if err != nil {
			return notFound(err)
		}
		writeJSON(w, http.StatusCreated, items(out))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/releases/{release}/attestations", authed(a, []string{"tenant", "release"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "release.read", tenant, ""); err != nil {
			return err
		}
		out, err := d.Service.List(r.Context(), tenant, r.PathValue("release"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
}
