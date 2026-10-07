package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/reports"
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
