package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

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
