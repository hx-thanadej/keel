package api_test

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/fx"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func stubResolve(_ context.Context, host string) ([]net.IP, error) {
	if host == "internal.example" {
		return []net.IP{net.ParseIP("10.0.0.5")}, nil
	}
	return []net.IP{net.ParseIP("203.0.113.10")}, nil
}

func TestBudgetsEndToEnd(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	cat := catalog.New(s, az)
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: cat,
		Budgets: &api.BudgetDeps{Authz: az, Catalog: cat, Budgets: budget.Service{Store: s}, Resolve: stubResolve}}))
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}
	admin := c.as(homeAdmin(home))

	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants/"+home+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	team := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants/"+home+"/teams", map[string]any{"slug": "other", "name": "Other"})
	other := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": team, "slug": "tat-crm", "name": "TAT CRM"})
	project := body["id"].(string)
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects/"+project+"/environments", map[string]any{"name": "prod"})
	prod := body["id"].(string)
	inTAT.do("POST", "/v1/tenants/"+tat+"/cloud-accounts", map[string]any{"environment_id": prod, "provider": "tencent", "external_id": "200048351622", "name": "prod"})

	st, body := inTAT.do("PATCH", "/v1/tenants/"+tat, map[string]any{"currency": "THB", "why": "client reports in baht"})
	mustStatus(t, st, 200, body)
	if _, err := (fx.DB{Store: s}).SaveRates(t.Context(), []fx.Rate{{Day: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC), Currency: "USD", PerEUR: "1.10"}, {Day: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC), Currency: "THB", PerEUR: "38.50"}}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile("../cost/testdata/tencent-focus-2026-09.csv")
	lines, _ := cost.ParseFOCUS(raw)
	if _, err := (&cost.Ingester{Store: s}).Load(t.Context(), cost.Load{Provider: "tencent", BillingAccountID: "p", BillingPeriod: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Lines: lines}); err != nil {
		t.Fatal(err)
	}

	lead := c.as(auth.Principal{Subject: "user:lead@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true,
		Bindings: []auth.Binding{{Role: auth.RoleTeamLead, TenantID: tat, TeamIDs: []string{team}}}})
	otherLead := c.as(auth.Principal{Subject: "user:x@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true,
		Bindings: []auth.Binding{{Role: auth.RoleTeamLead, TenantID: tat, TeamIDs: []string{other}}}})
	viewer := c.as(auth.Principal{Subject: "user:v@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})

	create := map[string]any{"project_id": project, "environment_id": prod, "name": "prod 2026", "year": 2026, "amount": "365000"}
	st, body = viewer.do("POST", "/v1/tenants/"+tat+"/budgets", create)
	mustStatus(t, st, 403, body)
	st, body = otherLead.do("POST", "/v1/tenants/"+tat+"/budgets", create)
	mustStatus(t, st, 403, body)
	create["webhook_url"] = "https://internal.example/hook"
	st, body = lead.do("POST", "/v1/tenants/"+tat+"/budgets", create)
	mustStatus(t, st, 400, body)
	create["webhook_url"] = "http://hooks.example/x"
	st, body = lead.do("POST", "/v1/tenants/"+tat+"/budgets", create)
	mustStatus(t, st, 400, body)
	create["webhook_url"] = "https://hooks.example/x"
	st, body = lead.do("POST", "/v1/tenants/"+tat+"/budgets", create)
	mustStatus(t, st, 201, body)
	if body["currency"] != "THB" {
		t.Fatalf("budget currency %v", body["currency"])
	}
	id := body["id"].(string)
	st, body = lead.do("POST", "/v1/tenants/"+tat+"/budgets", create)
	mustStatus(t, st, 409, body)

	for _, period := range []string{"day", "month", "year"} {
		st, body = viewer.do("GET", "/v1/tenants/"+tat+"/budgets/"+id+"/status?period="+period+"&date=2026-09-02", nil)
		mustStatus(t, st, 200, body)
		if body["actual"] != "217.00" && period == "day" || body["actual"] != "434.00" && period != "day" {
			t.Errorf("%s actual = %v", period, body["actual"])
		}
	}
	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/budgets/"+id+"/status?period=week", nil)
	mustStatus(t, st, 400, body)

	st, body = lead.do("PATCH", "/v1/tenants/"+tat+"/budgets/"+id, map[string]any{"amount": "730000"})
	mustStatus(t, st, 200, body)
	if body["amount"] != "730000" || body["name"] != "prod 2026" {
		t.Errorf("patch kept other fields? %v", body)
	}
	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/budgets", nil)
	mustStatus(t, st, 200, body)
	if len(items(t, body)) != 1 {
		t.Errorf("list %v", body)
	}
	st, body = lead.do("POST", "/v1/tenants/"+tat+"/budgets/"+id+"/archive", map[string]any{})
	mustStatus(t, st, 204, body)
	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/budgets", nil)
	mustStatus(t, st, 200, body)
	if len(items(t, body)) != 0 {
		t.Errorf("archived budget still listed")
	}
	st, body = viewer.do("PATCH", "/v1/tenants/"+tat, map[string]any{"currency": "USD"})
	mustStatus(t, st, 403, body)
}
