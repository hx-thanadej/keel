package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/flow"
)

// FlowDeps serves durable flows (#87).
type FlowDeps struct {
	Authz  catalog.Authorizer
	Engine *flow.Engine
}

func (d FlowDeps) allow(r *http.Request, p auth.Principal, action, tenant string) error {
	dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "flow", TenantID: tenant}})
	if err != nil {
		return err
	}
	if !dec.Allow {
		return catalog.ErrForbidden
	}
	return nil
}

func flowErr(err error) error {
	switch {
	case errors.Is(err, flow.ErrNotFound):
		return catalog.ErrNotFound
	case errors.Is(err, flow.ErrState):
		return errors.Join(catalog.ErrConflict, err)
	case errors.Is(err, flow.ErrUnknown):
		return errors.Join(catalog.ErrInvalid, err)
	}
	return err
}

func mountFlows(mux Mux, a auth.Authenticator, d FlowDeps) {
	mux.Handle("GET /v1/tenants/{tenant}/flows", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "flow.read", tenant); err != nil {
			return err
		}
		q := r.URL.Query()
		out, err := d.Engine.List(r.Context(), tenant, q.Get("kind"), q.Get("subject"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/flows/{flow}", authed(a, []string{"tenant", "flow"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "flow.read", tenant); err != nil {
			return err
		}
		out, err := d.Engine.Get(r.Context(), tenant, r.PathValue("flow"))
		if err != nil {
			return flowErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/flows/{flow}/retry", authed(a, []string{"tenant", "flow"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "flow.operate", tenant); err != nil {
			return err
		}
		if err := d.Engine.Retry(r.Context(), tenant, r.PathValue("flow"), actor(p)); err != nil {
			return flowErr(err)
		}
		out, err := d.Engine.Get(r.Context(), tenant, r.PathValue("flow"))
		if err != nil {
			return flowErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/flows/{flow}/cancel", authed(a, []string{"tenant", "flow"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "flow.operate", tenant); err != nil {
			return err
		}
		var in struct{ Reason string }
		if err := decode(r, &in); err != nil {
			return err
		}
		if in.Reason == "" {
			return errors.Join(catalog.ErrInvalid, errors.New("reason is required"))
		}
		if err := d.Engine.Cancel(r.Context(), tenant, r.PathValue("flow"), in.Reason, actor(p)); err != nil {
			return flowErr(err)
		}
		out, err := d.Engine.Get(r.Context(), tenant, r.PathValue("flow"))
		if err != nil {
			return flowErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
}
