package api_test

import (
	"net/http/httptest"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestRecommendationsAPI(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	svc := rightsize.Service{Store: s}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az), Rightsize: &api.RightsizeDeps{Authz: az, Service: svc}}))
	t.Cleanup(srv.Close)
	mk := func(res, savings string) string {
		r, _, err := svc.Upsert(t.Context(), tat, rightsize.Recommendation{Source: "engine:vm", Provider: "tencent", ResourceID: res, ResourceType: "vm",
			Action: "resize", Recommended: map[string]any{"sku": "S5.MEDIUM4"}, MonthlySavings: savings, Currency: "USD", Confidence: 0.8})
		if err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	small, big := mk("ins-small", "12.00"), mk("ins-big", "180.00")

	c := client{t: t, url: srv.URL}
	viewer := c.as(auth.Principal{Subject: "user:v@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	eng := c.as(auth.Principal{Subject: "user:e@harmonyx.co", Kind: auth.KindHuman, TenantID: "x", Home: true, Bindings: []auth.Binding{{Role: auth.RoleEngineer, TenantID: tat}}})

	st, body := viewer.do("GET", "/v1/tenants/"+tat+"/recommendations?state=open", nil)
	mustStatus(t, st, 200, body)
	if got := items(t, body); len(got) != 2 || got[0]["id"] != big {
		t.Fatalf("not ordered by savings: %v", got)
	}
	st, body = viewer.do("POST", "/v1/tenants/"+tat+"/recommendations/"+big+"/accept", map[string]any{})
	mustStatus(t, st, 403, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/recommendations/"+big+"/accept", map[string]any{})
	mustStatus(t, st, 200, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/recommendations/"+big+"/accept", map[string]any{})
	mustStatus(t, st, 409, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/recommendations/"+small+"/dismiss", map[string]any{})
	mustStatus(t, st, 400, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/recommendations/"+small+"/dismiss", map[string]any{"reason": "reserved for launch traffic"})
	mustStatus(t, st, 200, body)
	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/recommendations?state=bogus", nil)
	mustStatus(t, st, 400, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/recommendations/00000000-0000-4000-8000-000000000000/accept", map[string]any{})
	mustStatus(t, st, 404, body)

	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/savings", nil)
	mustStatus(t, st, 200, body)
	if body["accepted"] != "180.00" || body["open"] != "0.00" {
		t.Fatalf("savings %s", body)
	}
	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/savings?project=nope", nil)
	mustStatus(t, st, 400, body)
}
