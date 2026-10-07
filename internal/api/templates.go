package api

import (
	"errors"
	"net/http"
	"sort"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/templates"
)

// TemplateDeps serves Service Templates (#92).
type TemplateDeps struct {
	Authz   catalog.Authorizer
	Engine  *flow.Engine
	Creator templates.Creator
}

func mountTemplates(mux Mux, a auth.Authenticator, d TemplateDeps) {
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
	mux.Handle("GET /v1/tenants/{tenant}/templates", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := allow(r, p, "service.read", r.PathValue("tenant")); err != nil {
			return err
		}
		out := make([]templates.Template, 0, len(d.Creator.Templates))
		for _, t := range d.Creator.Templates {
			out = append(out, t)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/projects/{project}/services", authed(a, []string{"tenant", "project"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "service.create", tenant); err != nil {
			return err
		}
		var in struct{ Slug, Title, Template, Tier string }
		if err := decode(r, &in); err != nil {
			return err
		}
		f, created, err := d.Creator.Request(r.Context(), d.Engine, tenant, r.PathValue("project"), in.Slug, in.Title, in.Template, in.Tier, actor(p))
		switch {
		case errors.Is(err, templates.ErrNotFound):
			return catalog.ErrNotFound
		case errors.Is(err, templates.ErrInvalid), errors.Is(err, templates.ErrUnknownTemplate):
			return errors.Join(catalog.ErrInvalid, err)
		case err != nil:
			return err
		}
		status := http.StatusAccepted
		if !created {
			status = http.StatusOK
		}
		writeJSON(w, status, f)
		return nil
	}))
}
