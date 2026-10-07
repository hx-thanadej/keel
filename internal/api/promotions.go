package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/promotion"
)

// PromotionDeps serves Releases and Promotions (#93).
type PromotionDeps struct {
	Authz   catalog.Authorizer
	Service *promotion.Service
}

func (d PromotionDeps) allow(r *http.Request, p auth.Principal, action, typ, tenant string, id ...string) error {
	res := authz.Resource{Type: typ, TenantID: tenant}
	if len(id) > 0 {
		res.ID = id[0]
	}
	dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: res})
	if err != nil {
		return err
	}
	if !dec.Allow {
		return catalog.ErrForbidden
	}
	return nil
}

func promotionErr(err error) error {
	switch {
	case errors.Is(err, promotion.ErrNotFound):
		return catalog.ErrNotFound
	case errors.Is(err, promotion.ErrState):
		return errors.Join(catalog.ErrConflict, err)
	case errors.Is(err, promotion.ErrInvalid):
		return errors.Join(catalog.ErrInvalid, err)
	}
	return err
}

func mountPromotions(mux Mux, a auth.Authenticator, d PromotionDeps) {
	mux.Handle("POST /v1/tenants/{tenant}/services/{service}/releases", authed(a, []string{"tenant", "service"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "release.create", "release", tenant, r.PathValue("service")); err != nil {
			return err
		}
		var in struct {
			Version   string            `json:"version"`
			Images    []promotion.Image `json:"images"`
			CommitSHA string            `json:"commit_sha"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		if p.Pipeline != nil {
			in.CommitSHA = p.Pipeline.SHA // the token, not the caller, says which commit was built
		}
		out, err := d.Service.CreateRelease(r.Context(), tenant, r.PathValue("service"), in.Version, in.Images, in.CommitSHA, actor(p))
		if err != nil {
			return promotionErr(err)
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/releases", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "release.read", "release", tenant); err != nil {
			return err
		}
		svc := r.URL.Query().Get("service")
		if svc != "" && !catalog.ValidID(svc) {
			return errors.Join(catalog.ErrInvalid, errors.New("service must be a uuid"))
		}
		out, err := d.Service.Releases(r.Context(), tenant, svc)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/releases/{release}/promote", authed(a, []string{"tenant", "release"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "promotion.request", "promotion", tenant); err != nil {
			return err
		}
		var in struct {
			EnvironmentID string `json:"environment_id"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		if !catalog.ValidID(in.EnvironmentID) {
			return errors.Join(catalog.ErrInvalid, errors.New("environment_id must be a uuid"))
		}
		out, err := d.Service.Promote(r.Context(), tenant, r.PathValue("release"), in.EnvironmentID, actor(p))
		if err != nil {
			return promotionErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/releases/{release}/preview", authed(a, []string{"tenant", "release"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "promotion.read", "promotion", tenant); err != nil {
			return err
		}
		var in struct {
			EnvironmentID string `json:"environment_id"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		if !catalog.ValidID(in.EnvironmentID) {
			return errors.Join(catalog.ErrInvalid, errors.New("environment_id must be a uuid"))
		}
		out, err := d.Service.Preview(r.Context(), tenant, r.PathValue("release"), in.EnvironmentID)
		if err != nil {
			return promotionErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/promotions", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "promotion.read", "promotion", tenant); err != nil {
			return err
		}
		rel := r.URL.Query().Get("release")
		if rel != "" && !catalog.ValidID(rel) {
			return errors.Join(catalog.ErrInvalid, errors.New("release must be a uuid"))
		}
		out, err := d.Service.List(r.Context(), tenant, rel)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/promotions/{promotion}/approve", authed(a, []string{"tenant", "promotion"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "promotion.approve", "promotion", tenant); err != nil {
			return err
		}
		out, err := d.Service.Approve(r.Context(), tenant, r.PathValue("promotion"), actor(p))
		if err != nil {
			return promotionErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
