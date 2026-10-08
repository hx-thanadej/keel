package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/dora"
	"github.com/hx-thanadej/keel/internal/reports"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestReportDownloadForTenantMembers(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	if err := s.InTenant(t.Context(), tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO tenant_reports (tenant_id, period, data, html) VALUES ($1, '2026-09-01', '{"period": "2026-09"}', '<p>September</p>')`, tat)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		Reports: &api.ReportDeps{Authz: az, Service: reports.Service{Store: s}}}))
	t.Cleanup(srv.Close)
	viewer, _ := json.Marshal(auth.Principal{Subject: "user:board@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	get := func(path string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Header.Set("X-Test-Principal", string(viewer))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res, string(b)
	}
	res, body := get("/v1/tenants/" + tat + "/reports")
	if res.StatusCode != 200 || !strings.Contains(body, `"2026-09"`) {
		t.Fatalf("list: %d %s", res.StatusCode, body)
	}
	res, body = get("/v1/tenants/" + tat + "/reports/2026-09?format=html")
	if res.StatusCode != 200 || body != "<p>September</p>" {
		t.Fatalf("html: %d %s", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type %q", ct)
	}
	if !strings.Contains(res.Header.Get("Content-Disposition"), "keel-report-2026-09.html") || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("headers %v", res.Header)
	}
	if res, _ = get("/v1/tenants/" + tat + "/reports/2026-08"); res.StatusCode != 404 {
		t.Fatalf("missing month: %d", res.StatusCode)
	}
	if res, _ = get("/v1/tenants/" + tat + "/reports/sept"); res.StatusCode != 400 {
		t.Fatalf("bad period: %d", res.StatusCode)
	}
}

func TestRegenerateReportOnDemand(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	svc := reports.Service{Store: s, Budgets: budget.Service{Store: s}, DORA: dora.Service{Store: s},
		Savings: rightsize.Tracker{Service: rightsize.Service{Store: s}}, Now: func() time.Time { return now }}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		Reports: &api.ReportDeps{Authz: az, Service: svc}}))
	t.Cleanup(srv.Close)
	regenerate := func(role, subject string) (int, string) {
		p, _ := json.Marshal(auth.Principal{Subject: subject, Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: role, TenantID: tat}}})
		req, _ := http.NewRequest("POST", srv.URL+"/v1/tenants/"+tat+"/reports/2026-09/regenerate", strings.NewReader("{}"))
		req.Header.Set("X-Test-Principal", string(p))
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := regenerate(auth.RoleTenantViewer, "user:board@tat.or.th"); code != 403 {
		t.Fatalf("tenant viewer: %d %s", code, body)
	}
	code, body := regenerate(auth.RolePlatformAdmin, "user:admin@harmonyx.co")
	if code != 200 || !strings.Contains(body, `"period":"2026-09"`) {
		t.Fatalf("platform admin: %d %s", code, body)
	}
	var actor string
	if err := s.InTenant(t.Context(), tat, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT actor_uid FROM activities WHERE type = 'keel.report.generated'`).Scan(&actor)
	}); err != nil || actor != "user:admin@harmonyx.co" {
		t.Fatalf("generation actor %q (%v)", actor, err)
	}
}
