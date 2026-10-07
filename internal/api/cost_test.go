package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestCostUploadAndQuery(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		Cost: &api.CostDeps{Authz: az, Queries: cost.Queries{Store: s}, Ingester: &cost.Ingester{Store: s}}}))
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}
	admin := c.as(homeAdmin(home))

	// Catalog: TAT with dev/prod accounts.
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants/"+home+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	team := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": team, "slug": "tat-crm", "name": "TAT CRM"})
	project := body["id"].(string)
	for env, uin := range map[string]string{"dev": "200046202634", "prod": "200048351622"} {
		_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects/"+project+"/environments", map[string]any{"name": env})
		inTAT.do("POST", "/v1/tenants/"+tat+"/cloud-accounts", map[string]any{"environment_id": body["id"], "provider": "tencent", "external_id": uin, "name": "tat-crm-" + env})
	}

	finops := auth.Principal{Subject: "user:fin@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true,
		Bindings: []auth.Binding{{Role: auth.RoleFinOpsLead, TenantID: home}}}
	viewer := auth.Principal{Subject: "user:v@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}}

	bill, _ := os.ReadFile("../cost/testdata/tencent-focus-2026-09.csv.gz")
	upload := func(p auth.Principal, tenant, query string) (int, string) {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/tenants/"+tenant+"/cost-loads?"+query, strings.NewReader(string(bill)))
		pj, _ := json.Marshal(p)
		req.Header.Set("X-Test-Principal", string(pj))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	q := "provider=tencent&billing_account=200045645249&period=2026-09"
	if st, b := upload(viewer, tat, q); st != 403 {
		t.Fatalf("viewer upload: %d %s", st, b)
	}
	if st, b := upload(finops, home, "provider=tencent"); st != 400 {
		t.Fatalf("missing params: %d %s", st, b)
	}
	if st, b := upload(finops, home, q); st != 201 || !strings.Contains(b, `"Unallocated":2`) {
		t.Fatalf("upload: %d %s", st, b)
	}
	if st, b := upload(finops, home, q+"&final=true"); st != 201 {
		t.Fatalf("final upload: %d %s", st, b)
	}
	if st, b := upload(finops, home, q); st != 409 {
		t.Fatalf("upload after final: %d %s, want 409", st, b)
	}

	v := c.as(viewer)
	st, body := v.do("GET", "/v1/tenants/"+tat+"/costs/daily?from=2026-09-01&to=2026-10-01", nil)
	mustStatus(t, st, 200, body)
	got := map[string]string{}
	for _, r := range items(t, body) {
		got[r["day"].(string)[:10]+"/"+r["environment_name"].(string)] = r["billed"].(string)
	}
	if got["2026-09-01/prod"] != "35.20" || got["2026-09-02/dev"] != "1.20" {
		t.Errorf("daily = %v", got)
	}
	st, body = v.do("GET", "/v1/tenants/"+tat+"/costs/daily?from=bad", nil)
	mustStatus(t, st, 400, body)
	st, body = v.do("GET", "/v1/tenants/"+tat+"/costs/unallocated", nil)
	mustStatus(t, st, 403, body)

	st, body = c.as(finops).do("GET", "/v1/tenants/"+home+"/costs/unallocated?from=2026-09-01&to=2026-10-01", nil)
	mustStatus(t, st, 200, body)
	if body["unallocated"] != "4.00" || body["total"] != "46.80" {
		t.Errorf("kpi %v", body)
	}
}
