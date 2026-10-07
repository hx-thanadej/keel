package api_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/discovery"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type fakeOrg []discovery.Account

func (fakeOrg) Provider() string { return "tencent" }
func (f fakeOrg) ListAccounts(context.Context) ([]discovery.Account, error) {
	return f, nil
}

func TestDiscoverTencentAccountsAndMap(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	org := fakeOrg{
		{Provider: "tencent", ExternalID: "200046202634", Name: "tat-crm-dev", Parent: "TAT"},
		{Provider: "tencent", ExternalID: "200048351622", Name: "tat-crm-prod", Parent: "TAT"},
		{Provider: "tencent", ExternalID: "200045645249", Name: "payer", Parent: "root"},
	}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az), Discovery: map[string]discovery.Source{"tencent": org}}))
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}
	admin := c.as(homeAdmin(home))

	st, body := admin.do("POST", "/v1/tenants/"+home+"/discoveries/tencent", map[string]any{})
	mustStatus(t, st, 200, body)
	got := items(t, body)
	if len(got) != 3 {
		t.Fatalf("discovered %d, want 3", len(got))
	}
	byName := map[string]map[string]any{}
	for _, a := range got {
		byName[a["name"].(string)] = a
	}
	sug := byName["tat-crm-prod"]["suggestion"].(map[string]any)
	if sug["project_slug"] != "tat-crm" || sug["environment"] != "prod" || byName["tat-crm-prod"]["registered"] != false {
		t.Errorf("tat-crm-prod = %v", byName["tat-crm-prod"])
	}
	if _, has := byName["payer"]["suggestion"]; has {
		t.Errorf("payer should have no suggestion: %v", byName["payer"])
	}

	// Map tat-crm-prod into a client Tenant; discovery then reports it registered.
	_, body = admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants/"+home+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	team := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": team, "slug": "tat-crm", "name": "TAT CRM"})
	project := body["id"].(string)
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects/"+project+"/environments", map[string]any{"name": "prod"})
	env := body["id"].(string)
	st, body = inTAT.do("POST", "/v1/tenants/"+tat+"/cloud-accounts", map[string]any{"environment_id": env, "provider": "tencent", "external_id": "200048351622", "name": "tat-crm-prod"})
	mustStatus(t, st, 201, body)

	st, body = admin.do("GET", "/v1/tenants/"+home+"/discovered-accounts", nil)
	mustStatus(t, st, 200, body)
	for _, a := range items(t, body) {
		if a["name"] == "tat-crm-prod" && a["registered"] != true {
			t.Errorf("mapped account not reported registered: %v", a)
		}
		if a["name"] == "tat-crm-dev" && a["registered"] != false {
			t.Errorf("unmapped account reported registered: %v", a)
		}
	}

	// Re-running discovery is idempotent.
	st, body = admin.do("POST", "/v1/tenants/"+home+"/discoveries/tencent", map[string]any{})
	mustStatus(t, st, 200, body)
	if len(items(t, body)) != 3 {
		t.Errorf("re-discovery duplicated rows")
	}

	// Only the home Tenant runs discovery.
	st, body = inTAT.do("POST", "/v1/tenants/"+tat+"/discoveries/tencent", map[string]any{})
	mustStatus(t, st, 400, body)

	// The run is an Activity.
	st, body = admin.do("GET", "/v1/tenants/"+home+"/activities?type=keel.cloud_accounts.discovered", nil)
	mustStatus(t, st, 200, body)
	if len(items(t, body)) != 2 {
		t.Errorf("discovery activities = %d, want 2", len(items(t, body)))
	}
}
