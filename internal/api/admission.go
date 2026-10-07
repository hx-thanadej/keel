package api

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/admission"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// AdmissionDeps serves admission rollout (#113).
type AdmissionDeps struct {
	Authz   catalog.Authorizer
	Service admission.Service
}

func mountAdmission(mux Mux, a auth.Authenticator, d AdmissionDeps) {
	mux.Handle("POST /v1/tenants/{tenant}/projects/{project}/environments/{env}/admission", authed(a, []string{"tenant", "project", "env"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "environment.set_admission", Resource: authz.Resource{Type: "environment", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		var in struct{ Mode, Why string }
		if err := decode(r, &in); err != nil {
			return err
		}
		if in.Why == "" {
			return errors.Join(catalog.ErrInvalid, errors.New("why is required"))
		}
		err = d.Service.SetMode(r.Context(), tenant, r.PathValue("env"), in.Mode, in.Why, actor(p))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return catalog.ErrNotFound
		case errors.Is(err, admission.ErrInvalid):
			return errors.Join(catalog.ErrInvalid, err)
		case err != nil:
			return err
		}
		writeJSON(w, http.StatusOK, map[string]string{"mode": in.Mode})
		return nil
	}))
}
