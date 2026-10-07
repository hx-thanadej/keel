package api_test

import (
	"net/http/httptest"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestAllocationRulesAPI(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		Cost: &api.CostDeps{Authz: az, Queries: cost.Queries{Store: s}, Ingester: &cost.Ingester{Store: s}, Rules: cost.Rules{Store: s}}}))
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants/"+home+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	team := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": team, "slug": "tat-crm", "name": "TAT CRM"})
	project := body["id"].(string)

	fin := c.as(auth.Principal{Subject: "user:fin@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true, Bindings: []auth.Binding{{Role: auth.RoleFinOpsLead, TenantID: home}}})
	clientAdmin := c.as(auth.Principal{Subject: "user:a@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: tat}}})

	rule := map[string]any{"provider": "tencent", "sub_account_id": "shared-uin", "service_name": "Tencent Container Registry", "kind": "weights",
		"shares": []map[string]any{{"project_id": project, "weight": "1"}}}
	st, body := clientAdmin.do("POST", "/v1/tenants/"+tat+"/allocation-rules", rule)
	mustStatus(t, st, 403, body)
	st, body = fin.do("POST", "/v1/tenants/"+home+"/allocation-rules", map[string]any{"provider": "tencent", "sub_account_id": "x", "kind": "weights"})
	mustStatus(t, st, 400, body)
	st, body = fin.do("POST", "/v1/tenants/"+home+"/allocation-rules", rule)
	mustStatus(t, st, 201, body)
	id := body["id"].(string)
	if body["shares"].([]any)[0].(map[string]any)["tenant_id"] != tat {
		t.Errorf("share tenant not resolved: %v", body)
	}
	st, body = fin.do("POST", "/v1/tenants/"+home+"/allocation-rules", rule)
	mustStatus(t, st, 409, body)
	st, body = fin.do("PUT", "/v1/tenants/"+home+"/k8s-namespaces/shared-tke/tat-crm-prod", map[string]any{"project_id": project})
	mustStatus(t, st, 204, body)
	st, body = fin.do("GET", "/v1/tenants/"+home+"/allocation-rules", nil)
	mustStatus(t, st, 200, body)
	if len(items(t, body)) != 1 {
		t.Errorf("rules %v", body)
	}
	st, body = fin.do("POST", "/v1/tenants/"+home+"/allocation-rules/"+id+"/archive", map[string]any{})
	mustStatus(t, st, 204, body)
	st, body = fin.do("POST", "/v1/tenants/"+home+"/allocation-rules/"+id+"/archive", map[string]any{})
	mustStatus(t, st, 404, body)
}
