package api

import (
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cost"
)

// CostDeps serves cost endpoints.
type CostDeps struct {
	Authz    catalog.Authorizer
	Queries  cost.Queries
	Ingester *cost.Ingester
	Rules    cost.Rules
}

const maxBillUpload = 512 << 20

func (d CostDeps) allow(r *http.Request, p auth.Principal, action, tenant string) error {
	dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "cost", TenantID: tenant}})
	if err != nil {
		return err
	}
	if !dec.Allow {
		return catalog.ErrForbidden
	}
	return nil
}

func dayRange(r *http.Request) (time.Time, time.Time, error) {
	q := r.URL.Query()
	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	var err error
	if v := q.Get("from"); v != "" {
		if from, err = time.Parse("2006-01-02", v); err != nil {
			return from, to, errors.Join(catalog.ErrInvalid, errors.New("from must be YYYY-MM-DD"))
		}
	}
	if v := q.Get("to"); v != "" {
		if to, err = time.Parse("2006-01-02", v); err != nil {
			return from, to, errors.Join(catalog.ErrInvalid, errors.New("to must be YYYY-MM-DD (exclusive)"))
		}
	}
	if !to.After(from) || to.Sub(from) > 3*366*24*time.Hour {
		return from, to, errors.Join(catalog.ErrInvalid, errors.New("to must be after from, within 3 years"))
	}
	return from, to, nil
}

func mountCost(mux Mux, a auth.Authenticator, d CostDeps) {
	t := []string{"tenant"}
	mux.Handle("GET /v1/tenants/{tenant}/costs/daily", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "cost.read", tenant); err != nil {
			return err
		}
		from, to, err := dayRange(r)
		if err != nil {
			return err
		}
		f := cost.DailyFilter{From: from, To: to, ProjectID: r.URL.Query().Get("project"), EnvironmentID: r.URL.Query().Get("environment")}
		for _, id := range []string{f.ProjectID, f.EnvironmentID} {
			if id != "" && !catalog.ValidID(id) {
				return errors.Join(catalog.ErrInvalid, errors.New("project and environment must be uuids"))
			}
		}
		rows, err := d.Queries.Daily(r.Context(), tenant, f)
		if err != nil {
			return err
		}
		if r.URL.Query().Get("format") == "csv" {
			return writeDailyCSV(w, rows)
		}
		writeJSON(w, http.StatusOK, items(rows))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/costs/breakdown", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "cost.read", tenant); err != nil {
			return err
		}
		from, to, err := dayRange(r)
		if err != nil {
			return err
		}
		q := r.URL.Query()
		by := q.Get("by")
		if by == "" {
			by = "service"
		}
		if by != "service" && by != "resource" {
			return errors.Join(catalog.ErrInvalid, errors.New("by is service or resource"))
		}
		f := cost.DailyFilter{From: from, To: to, ProjectID: q.Get("project"), EnvironmentID: q.Get("environment")}
		for _, id := range []string{f.ProjectID, f.EnvironmentID} {
			if id != "" && !catalog.ValidID(id) {
				return errors.Join(catalog.ErrInvalid, errors.New("project and environment must be uuids"))
			}
		}
		limit, _ := strconv.Atoi(q.Get("limit"))
		rows, err := d.Queries.Breakdown(r.Context(), tenant, f, by, limit)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(rows))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/costs/unallocated", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "cost.read_unallocated", tenant); err != nil {
			return err
		}
		from, to, err := dayRange(r)
		if err != nil {
			return err
		}
		k, err := d.Queries.Unallocated(r.Context(), tenant, from, to)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, k)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/cost-loads", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "cost.read_unallocated", tenant); err != nil {
			return err
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		out, err := d.Queries.Loads(r.Context(), tenant, limit)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	// Shared-cost allocation rules (#35): home Tenant only.
	home := func(r *http.Request, p auth.Principal) (string, error) {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "cost.allocate", tenant); err != nil {
			return "", err
		}
		if !p.Home || p.TenantID != tenant {
			return "", catalog.ErrForbidden
		}
		return tenant, nil
	}
	ruleErr := func(err error) error {
		switch {
		case errors.Is(err, cost.ErrInvalidRule):
			return errors.Join(catalog.ErrInvalid, err)
		case errors.Is(err, cost.ErrRuleExists):
			return errors.Join(catalog.ErrConflict, err)
		case errors.Is(err, pgx.ErrNoRows):
			return catalog.ErrNotFound
		}
		return err
	}
	mux.Handle("GET /v1/tenants/{tenant}/allocation-rules", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant, err := home(r, p)
		if err != nil {
			return err
		}
		out, err := d.Rules.List(r.Context(), tenant)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/allocation-rules", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant, err := home(r, p)
		if err != nil {
			return err
		}
		var in cost.Rule
		if err := decode(r, &in); err != nil {
			return err
		}
		out, err := d.Rules.Create(r.Context(), tenant, in)
		if err != nil {
			return ruleErr(err)
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/allocation-rules/{rule}/archive", authed(a, []string{"tenant", "rule"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant, err := home(r, p)
		if err != nil {
			return err
		}
		if err := d.Rules.Archive(r.Context(), tenant, r.PathValue("rule")); err != nil {
			return ruleErr(err)
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.Handle("PUT /v1/tenants/{tenant}/k8s-namespaces/{cluster}/{namespace}", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant, err := home(r, p)
		if err != nil {
			return err
		}
		var in struct {
			ProjectID     string  `json:"project_id"`
			EnvironmentID *string `json:"environment_id"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		if !catalog.ValidID(in.ProjectID) || (in.EnvironmentID != nil && !catalog.ValidID(*in.EnvironmentID)) {
			return errors.Join(catalog.ErrInvalid, errors.New("project_id (and environment_id) must be uuids"))
		}
		if err := d.Rules.MapNamespace(r.Context(), tenant, r.PathValue("cluster"), r.PathValue("namespace"), in.ProjectID, in.EnvironmentID); err != nil {
			return ruleErr(err)
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Manual load of a FOCUS export (CSV, .gz or .zip body). Lines are
	// attributed across all Tenants by Cloud Account, so only the home
	// Tenant's admins and FinOps leads may load.
	mux.Handle("POST /v1/tenants/{tenant}/cost-loads", authed(a, t, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := d.allow(r, p, "cost.load", tenant); err != nil {
			return err
		}
		if !p.Home || p.TenantID != tenant {
			return catalog.ErrForbidden
		}
		q := r.URL.Query()
		period, err := time.Parse("2006-01", q.Get("period"))
		if err != nil || q.Get("provider") == "" || q.Get("billing_account") == "" {
			return errors.Join(catalog.ErrInvalid, errors.New("query needs provider, billing_account and period=YYYY-MM"))
		}
		final, _ := strconv.ParseBool(q.Get("final"))
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBillUpload))
		if err != nil {
			return errors.Join(catalog.ErrInvalid, err)
		}
		lines, err := cost.ParseFOCUS(raw)
		if err != nil {
			return errors.Join(catalog.ErrInvalid, err)
		}
		res, err := d.Ingester.Load(r.Context(), cost.Load{Provider: q.Get("provider"), BillingAccountID: q.Get("billing_account"),
			BillingPeriod: period, Source: "upload:" + p.Subject, Final: final, Lines: lines})
		if errors.Is(err, cost.ErrPeriodFinal) {
			return errors.Join(catalog.ErrConflict, err)
		}
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, res)
		return nil
	}))
}

func writeDailyCSV(w http.ResponseWriter, rows []cost.DailyRow) error {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="keel-daily-costs.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"day", "project", "environment", "provider", "currency", "billed", "effective"})
	for _, r := range rows {
		proj, eff := "", ""
		if r.ProjectSlug != nil {
			proj = *r.ProjectSlug
		}
		if r.Effective != nil {
			eff = *r.Effective
		}
		_ = cw.Write([]string{r.Day.Format("2006-01-02"), proj, r.EnvironmentName, r.Provider, r.Currency, r.Billed, eff})
	}
	cw.Flush()
	return cw.Error()
}
