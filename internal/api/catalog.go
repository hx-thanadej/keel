package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/catalog"
)

type handler func(w http.ResponseWriter, r *http.Request, p auth.Principal) error

// authed authenticates, validates every {…} id path value, and maps errors.
func authed(a auth.Authenticator, ids []string, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthenticated"))
			return
		}
		for _, name := range ids {
			if !catalog.ValidID(r.PathValue(name)) {
				writeJSON(w, http.StatusBadRequest, errBody(name+" must be a uuid"))
				return
			}
		}
		if err := h(w, r.WithContext(auth.WithPrincipal(r.Context(), p)), p); err != nil {
			writeError(w, r, err)
		}
	}
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, catalog.ErrForbidden):
		writeJSON(w, http.StatusForbidden, errBody("forbidden"))
	case errors.Is(err, catalog.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody("not found"))
	case errors.Is(err, catalog.ErrConflict):
		writeJSON(w, http.StatusConflict, errBody(err.Error()))
	case errors.Is(err, catalog.ErrInvalid), errors.Is(err, errBadJSON):
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
	default:
		slog.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
	}
}

var errBadJSON = errors.New("invalid JSON body")

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.Join(errBadJSON, err)
	}
	return nil
}

type list[T any] struct {
	Items []T `json:"items"`
}

func items[T any](v []T) list[T] {
	if v == nil {
		v = []T{}
	}
	return list[T]{Items: v}
}

func mountCatalog(mux Mux, c *catalog.Service, a auth.Authenticator) {
	t := []string{"tenant"}
	tp := []string{"tenant", "project"}

	mux.Handle("POST /v1/tenants", authed(a, nil, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct{ Slug, Name, Why string }
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.CreateTenant(r.Context(), p, in.Slug, in.Name, in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		out, err := c.GetTenant(r.Context(), p, r.PathValue("tenant"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))

	mux.Handle("POST /v1/tenants/{tenant}/teams", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct{ Slug, Name, Why string }
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.CreateTeam(r.Context(), p, r.PathValue("tenant"), in.Slug, in.Name, in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/teams", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		out, err := c.ListTeams(r.Context(), p, r.PathValue("tenant"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))

	mux.Handle("POST /v1/tenants/{tenant}/projects", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct {
			TeamID          string `json:"team_id"`
			Slug, Name, Why string
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.CreateProject(r.Context(), p, r.PathValue("tenant"), in.TeamID, in.Slug, in.Name, in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/projects", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		out, err := c.ListProjects(r.Context(), p, r.PathValue("tenant"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/projects/{project}", authed(a, tp, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		out, err := c.GetProject(r.Context(), p, r.PathValue("tenant"), r.PathValue("project"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("PATCH /v1/tenants/{tenant}/projects/{project}", authed(a, tp, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct {
			Name       string  `json:"name"`
			ConfigRepo *string `json:"config_repo"`
			Why        string  `json:"why"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		if in.Name == "" && in.ConfigRepo == nil {
			return errors.Join(catalog.ErrInvalid, errors.New("set name or config_repo"))
		}
		var out catalog.Project
		var err error
		if in.Name != "" {
			if out, err = c.RenameProject(r.Context(), p, r.PathValue("tenant"), r.PathValue("project"), in.Name, in.Why); err != nil {
				return err
			}
		}
		if in.ConfigRepo != nil {
			if out, err = c.SetConfigRepo(r.Context(), p, r.PathValue("tenant"), r.PathValue("project"), *in.ConfigRepo, in.Why); err != nil {
				return err
			}
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/projects/{project}/archive", authed(a, tp, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct{ Why string }
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.ArchiveProject(r.Context(), p, r.PathValue("tenant"), r.PathValue("project"), in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))

	mux.Handle("POST /v1/tenants/{tenant}/projects/{project}/environments", authed(a, tp, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct{ Name, Why string }
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.CreateEnvironment(r.Context(), p, r.PathValue("tenant"), r.PathValue("project"), in.Name, in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/projects/{project}/environments", authed(a, tp, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		out, err := c.ListEnvironments(r.Context(), p, r.PathValue("tenant"), r.PathValue("project"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("PATCH /v1/tenants/{tenant}/projects/{project}/environments/{env}", authed(a, []string{"tenant", "project", "env"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct {
			WasteCleanup     *bool  `json:"waste_cleanup"`
			PromotionOrder   *int   `json:"promotion_order"`
			RequiresApproval *bool  `json:"requires_approval"`
			Why              string `json:"why"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		if in.WasteCleanup == nil && in.PromotionOrder == nil && in.RequiresApproval == nil {
			return errors.Join(catalog.ErrInvalid, errors.New("set waste_cleanup, promotion_order or requires_approval"))
		}
		var out catalog.Environment
		var err error
		if in.WasteCleanup != nil {
			if out, err = c.SetWasteCleanup(r.Context(), p, r.PathValue("tenant"), r.PathValue("project"), r.PathValue("env"), *in.WasteCleanup, in.Why); err != nil {
				return err
			}
		}
		if in.PromotionOrder != nil || in.RequiresApproval != nil {
			if out, err = c.SetPromotionPath(r.Context(), p, r.PathValue("tenant"), r.PathValue("project"), r.PathValue("env"), in.PromotionOrder, in.RequiresApproval, in.Why); err != nil {
				return err
			}
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/projects/{project}/environments/{env}/archive", authed(a, []string{"tenant", "project", "env"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct{ Why string }
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.ArchiveEnvironment(r.Context(), p, r.PathValue("tenant"), r.PathValue("project"), r.PathValue("env"), in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))

	mux.Handle("POST /v1/tenants/{tenant}/cloud-accounts", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct {
			EnvironmentID *string `json:"environment_id"`
			Provider      string  `json:"provider"`
			ExternalID    string  `json:"external_id"`
			Name, Why     string
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.CreateCloudAccount(r.Context(), p, r.PathValue("tenant"), in.EnvironmentID, in.Provider, in.ExternalID, in.Name, in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/cloud-accounts", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		out, err := c.ListCloudAccounts(r.Context(), p, r.PathValue("tenant"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/cloud-accounts/{account}/archive", authed(a, []string{"tenant", "account"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct{ Why string }
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.ArchiveCloudAccount(r.Context(), p, r.PathValue("tenant"), r.PathValue("account"), in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))

	mux.Handle("POST /v1/tenants/{tenant}/identity-providers", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct {
			Issuer          string  `json:"issuer"`
			ClientID        string  `json:"client_id"`
			ClientSecretRef string  `json:"client_secret_ref"`
			GroupsClaim     string  `json:"groups_claim"`
			EmailDomain     *string `json:"email_domain"`
			Why             string  `json:"why"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.CreateIdentityProvider(r.Context(), p, r.PathValue("tenant"), catalog.IdentityProvider{
			Issuer: in.Issuer, ClientID: in.ClientID, ClientSecretRef: in.ClientSecretRef, GroupsClaim: in.GroupsClaim, EmailDomain: in.EmailDomain}, in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/identity-providers", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		out, err := c.ListIdentityProviders(r.Context(), p, r.PathValue("tenant"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/identity-providers/{idp}/group-roles", authed(a, []string{"tenant", "idp"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct {
			Group          string   `json:"group"`
			Role           string   `json:"role"`
			TargetTenantID string   `json:"target_tenant_id"`
			TeamIDs        []string `json:"team_ids"`
			Why            string   `json:"why"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := c.AddGroupRole(r.Context(), p, r.PathValue("tenant"), r.PathValue("idp"), catalog.GroupRole{
			Group: in.Group, Role: in.Role, TargetTenantID: in.TargetTenantID, TeamIDs: in.TeamIDs}, in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))

	mux.Handle("GET /v1/tenants/{tenant}/activities", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		q := r.URL.Query()
		f := activity.Filter{ActorUID: q.Get("actor"), Type: q.Get("type"), Subject: q.Get("subject")}
		f.Limit, _ = strconv.Atoi(q.Get("limit"))
		f.BeforeSeq, _ = strconv.ParseInt(q.Get("before"), 10, 64)
		if v := q.Get("since"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return errors.Join(catalog.ErrInvalid, err)
			}
			f.Since = t
		}
		out, err := c.ListActivities(r.Context(), p, r.PathValue("tenant"), f)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
}
