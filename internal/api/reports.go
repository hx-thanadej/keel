package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/reports"
)

// ReportDeps serves monthly Tenant reports (#152).
type ReportDeps struct {
	Authz   catalog.Authorizer
	Service reports.Service
}

func mountReports(mux Mux, a auth.Authenticator, d ReportDeps) {
	allow := func(r *http.Request, p auth.Principal, tenant string) error {
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "report.read", Resource: authz.Resource{Type: "report", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		return nil
	}
	mux.Handle("GET /v1/tenants/{tenant}/reports", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, tenant); err != nil {
			return err
		}
		out, err := d.Service.List(r.Context(), tenant)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	// The report as data, or with ?format=html as the stored page to download.
	mux.Handle("GET /v1/tenants/{tenant}/reports/{period}", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, tenant); err != nil {
			return err
		}
		period, err := reports.ParsePeriod(r.PathValue("period"))
		if err != nil {
			return errors.Join(catalog.ErrInvalid, err)
		}
		rep, page, err := d.Service.Get(r.Context(), tenant, period)
		if errors.Is(err, reports.ErrNotFound) {
			return catalog.ErrNotFound
		}
		if err != nil {
			return err
		}
		if r.URL.Query().Get("format") == "html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="keel-report-%s.html"`, rep.Period))
			// The page is ours, but keep it inert if opened from the API origin.
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(page))
			return err
		}
		writeJSON(w, http.StatusOK, rep)
		return nil
	}))
}
