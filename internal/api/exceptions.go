package api

import (
	"errors"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/exceptions"
)

// ExceptionDeps serves Exceptions (#108).
type ExceptionDeps struct {
	Authz   catalog.Authorizer
	Service *exceptions.Service
}

func exceptionErr(err error) error {
	switch {
	case errors.Is(err, exceptions.ErrNotFound):
		return catalog.ErrNotFound
	case errors.Is(err, exceptions.ErrState):
		return errors.Join(catalog.ErrConflict, err)
	case errors.Is(err, exceptions.ErrInvalid):
		return errors.Join(catalog.ErrInvalid, err)
	}
	return err
}

func mountExceptions(mux Mux, a auth.Authenticator, d ExceptionDeps) {
	allow := func(r *http.Request, p auth.Principal, action, tenant string) error {
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "exception", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		return nil
	}
	mux.Handle("GET /v1/tenants/{tenant}/exceptions", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "exception.read", tenant); err != nil {
			return err
		}
		out, err := d.Service.List(r.Context(), tenant, r.URL.Query().Get("state"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/exceptions", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "exception.request", tenant); err != nil {
			return err
		}
		var in exceptions.Request
		if err := decode(r, &in); err != nil {
			return err
		}
		for _, id := range in.FindingIDs {
			if !catalog.ValidID(id) {
				return errors.Join(catalog.ErrInvalid, errors.New("finding_ids must be uuids"))
			}
		}
		if in.ProjectID != nil && !catalog.ValidID(*in.ProjectID) {
			return errors.Join(catalog.ErrInvalid, errors.New("project_id must be a uuid"))
		}
		out, err := d.Service.Create(r.Context(), tenant, in, actor(p))
		if err != nil {
			return exceptionErr(err)
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	decide := func(action string, fn func(*exceptions.Service) func(r *http.Request, tenant, id, note string, p auth.Principal) (exceptions.Exception, error)) http.Handler {
		return authed(a, []string{"tenant", "exception"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
			tenant := r.PathValue("tenant")
			if err := allow(r, p, action, tenant); err != nil {
				return err
			}
			var in struct{ Note string }
			if err := decode(r, &in); err != nil {
				return err
			}
			out, err := fn(d.Service)(r, tenant, r.PathValue("exception"), in.Note, p)
			if err != nil {
				return exceptionErr(err)
			}
			writeJSON(w, http.StatusOK, out)
			return nil
		})
	}
	mux.Handle("POST /v1/tenants/{tenant}/exceptions/{exception}/approve", decide("exception.approve", func(s *exceptions.Service) func(*http.Request, string, string, string, auth.Principal) (exceptions.Exception, error) {
		return func(r *http.Request, t, id, note string, p auth.Principal) (exceptions.Exception, error) {
			return s.Approve(r.Context(), t, id, note, actor(p))
		}
	}))
	mux.Handle("POST /v1/tenants/{tenant}/exceptions/{exception}/reject", decide("exception.approve", func(s *exceptions.Service) func(*http.Request, string, string, string, auth.Principal) (exceptions.Exception, error) {
		return func(r *http.Request, t, id, note string, p auth.Principal) (exceptions.Exception, error) {
			return s.Reject(r.Context(), t, id, note, actor(p))
		}
	}))
	mux.Handle("POST /v1/tenants/{tenant}/exceptions/{exception}/revoke", decide("exception.approve", func(s *exceptions.Service) func(*http.Request, string, string, string, auth.Principal) (exceptions.Exception, error) {
		return func(r *http.Request, t, id, note string, p auth.Principal) (exceptions.Exception, error) {
			return s.Revoke(r.Context(), t, id, note, actor(p))
		}
	}))
}
