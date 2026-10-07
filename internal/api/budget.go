package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// BudgetDeps serves Budget endpoints.
type BudgetDeps struct {
	Authz   catalog.Authorizer
	Catalog *catalog.Service
	Budgets budget.Service
	// Resolve looks up webhook hosts; tests may stub it. Default net.DefaultResolver.
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
}

func (d BudgetDeps) allow(r *http.Request, p auth.Principal, action, tenant, project string) error {
	team := ""
	if project != "" {
		var err error
		if team, err = d.Catalog.ProjectTeam(r.Context(), tenant, project); err != nil {
			return err
		}
	}
	dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action,
		Resource: authz.Resource{Type: "budget", TenantID: tenant, ProjectID: project, TeamID: team}})
	if err != nil {
		return err
	}
	if !dec.Allow {
		return catalog.ErrForbidden
	}
	return nil
}

// safeWebhook refuses non-https URLs and hosts that resolve to private,
// loopback or link-local addresses, so a webhook can't be aimed inside Keel's
// network (SSRF).
func (d BudgetDeps) safeWebhook(ctx context.Context, raw *string) error {
	if raw == nil || *raw == "" {
		return nil
	}
	u, err := url.Parse(*raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.Join(catalog.ErrInvalid, errors.New("webhook_url must be an https URL"))
	}
	resolve := d.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	ips, err := resolve(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return errors.Join(catalog.ErrInvalid, errors.New("webhook host does not resolve"))
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return errors.Join(catalog.ErrInvalid, errors.New("webhook host resolves to a private address"))
		}
	}
	return nil
}

func budgetErr(err error) error {
	switch {
	case errors.Is(err, budget.ErrInvalid):
		return errors.Join(catalog.ErrInvalid, err)
	case errors.Is(err, budget.ErrConflict):
		return errors.Join(catalog.ErrConflict, err)
	case errors.Is(err, budget.ErrNotFound):
		return catalog.ErrNotFound
	}
	return err
}

func actor(p auth.Principal) activity.Actor {
	return activity.Actor{Type: activity.ActorHuman, UID: p.Subject, Session: &activity.Session{Issuer: p.Issuer, MFA: p.MFA}}
}

type budgetBody struct {
	ProjectID      string             `json:"project_id"`
	EnvironmentID  *string            `json:"environment_id"`
	Provider       *string            `json:"provider"`
	Name           string             `json:"name"`
	Year           int                `json:"year"`
	Amount         string             `json:"amount"`
	MonthlyWeights []string           `json:"monthly_weights"`
	CostBasis      string             `json:"cost_basis"`
	Thresholds     []budget.Threshold `json:"thresholds"`
	WebhookURL     *string            `json:"webhook_url"`
	MirrorNative   bool               `json:"mirror_native"`
}

func (b budgetBody) budget() budget.Budget {
	return budget.Budget{ProjectID: b.ProjectID, EnvironmentID: b.EnvironmentID, Provider: b.Provider, Name: b.Name, Year: b.Year, Amount: b.Amount,
		MonthlyWeights: b.MonthlyWeights, CostBasis: b.CostBasis, Thresholds: b.Thresholds, WebhookURL: b.WebhookURL, MirrorNative: b.MirrorNative}
}

func mountBudgets(mux Mux, a auth.Authenticator, d BudgetDeps) {
	t := []string{"tenant"}
	tb := []string{"tenant", "budget"}

	mux.Handle("PATCH /v1/tenants/{tenant}", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct{ Currency, Why string }
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Catalog.SetTenantCurrency(r.Context(), p, r.PathValue("tenant"), in.Currency, in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/budgets", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in budgetBody
		if err := decode(r, &in); err != nil {
			return err
		}
		if !catalog.ValidID(in.ProjectID) || (in.EnvironmentID != nil && !catalog.ValidID(*in.EnvironmentID)) {
			return errors.Join(catalog.ErrInvalid, errors.New("project_id (and environment_id if set) must be uuids"))
		}
		if err := d.allow(r, p, "budget.create", r.PathValue("tenant"), in.ProjectID); err != nil {
			return err
		}
		if err := d.safeWebhook(r.Context(), in.WebhookURL); err != nil {
			return err
		}
		out, err := d.Budgets.Create(r.Context(), r.PathValue("tenant"), in.budget(), actor(p))
		if err != nil {
			return budgetErr(err)
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/budgets", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		project := r.URL.Query().Get("project")
		if project != "" && !catalog.ValidID(project) {
			return errors.Join(catalog.ErrInvalid, errors.New("project must be a uuid"))
		}
		if err := d.allow(r, p, "budget.read", r.PathValue("tenant"), ""); err != nil {
			return err
		}
		out, err := d.Budgets.List(r.Context(), r.PathValue("tenant"), project)
		if err != nil {
			return budgetErr(err)
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("PATCH /v1/tenants/{tenant}/budgets/{budget}", authed(a, tb, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		cur, err := d.Budgets.Get(r.Context(), r.PathValue("tenant"), r.PathValue("budget"))
		if err != nil && !errors.Is(err, budget.ErrNotFound) {
			return err
		}
		if err := d.allow(r, p, "budget.update", r.PathValue("tenant"), cur.ProjectID); err != nil {
			return err
		}
		if cur.ID == "" {
			return catalog.ErrNotFound
		}
		in := budgetBody{Name: cur.Name, Amount: cur.Amount, MonthlyWeights: cur.MonthlyWeights, CostBasis: cur.CostBasis, Thresholds: cur.Thresholds, WebhookURL: cur.WebhookURL, Year: cur.Year, MirrorNative: cur.MirrorNative}
		if err := decode(r, &in); err != nil {
			return err
		}
		if err := d.safeWebhook(r.Context(), in.WebhookURL); err != nil {
			return err
		}
		out, err := d.Budgets.Update(r.Context(), r.PathValue("tenant"), cur.ID, in.budget(), actor(p))
		if err != nil {
			return budgetErr(err)
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/budgets/{budget}/archive", authed(a, tb, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		cur, err := d.Budgets.Get(r.Context(), r.PathValue("tenant"), r.PathValue("budget"))
		if err != nil && !errors.Is(err, budget.ErrNotFound) {
			return err
		}
		if err := d.allow(r, p, "budget.archive", r.PathValue("tenant"), cur.ProjectID); err != nil {
			return err
		}
		if err := d.Budgets.Archive(r.Context(), r.PathValue("tenant"), r.PathValue("budget"), actor(p)); err != nil {
			return budgetErr(err)
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/budgets/{budget}/mirrors", authed(a, tb, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := d.allow(r, p, "budget.read", r.PathValue("tenant"), ""); err != nil {
			return err
		}
		out, err := d.Budgets.Mirrors(r.Context(), r.PathValue("tenant"), r.PathValue("budget"))
		if err != nil {
			return budgetErr(err)
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/budgets/{budget}/status", authed(a, tb, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		if err := d.allow(r, p, "budget.read", r.PathValue("tenant"), ""); err != nil {
			return err
		}
		period := budget.Period(r.URL.Query().Get("period"))
		if period == "" {
			period = budget.Month
		}
		if period != budget.Day && period != budget.Month && period != budget.Year {
			return errors.Join(catalog.ErrInvalid, errors.New("period is day, month or year"))
		}
		asOf := time.Now().UTC()
		if v := r.URL.Query().Get("date"); v != "" {
			var err error
			if asOf, err = time.Parse("2006-01-02", v); err != nil {
				return errors.Join(catalog.ErrInvalid, errors.New("date must be YYYY-MM-DD"))
			}
		}
		st, err := d.Budgets.Status(r.Context(), r.PathValue("tenant"), r.PathValue("budget"), period, asOf)
		if err != nil {
			return budgetErr(err)
		}
		writeJSON(w, http.StatusOK, st)
		return nil
	}))
}
