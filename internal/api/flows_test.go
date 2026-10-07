package api_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/riverqueue/river"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/store/storetest"
	"github.com/hx-thanadej/keel/internal/vending"
)

func TestFlowsAPI(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	e := flow.New(s, flow.Def{Kind: "demo", Steps: []flow.Step{{Name: "only", Do: func(context.Context, *flow.Run) (map[string]any, error) {
		return nil, flow.Permanent(errors.New("boom"))
	}}}})
	w := river.NewWorkers()
	e.Register(w)
	c, err := flow.NewClient(s.AppPool(), w, flow.ClientOptions{}) // insert-only: never started
	if err != nil {
		t.Fatal(err)
	}
	e.SetClient(c)
	f, _, err := e.Start(t.Context(), tat, "demo", "environment/x", nil, activity.Actor{Type: activity.ActorHuman, UID: "user:a"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az), Flows: &api.FlowDeps{Authz: az, Engine: e}}))
	t.Cleanup(srv.Close)
	cl := client{t: t, url: srv.URL}
	viewer := cl.as(auth.Principal{Subject: "user:v@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	admin := cl.as(auth.Principal{Subject: "user:a@harmonyx.co", Kind: auth.KindHuman, TenantID: "x", Home: true, Bindings: []auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: tat}}})

	st, body := viewer.do("GET", "/v1/tenants/"+tat+"/flows", nil)
	mustStatus(t, st, 200, body)
	if got := items(t, body); len(got) != 1 || got[0]["kind"] != "demo" {
		t.Fatalf("list %v", got)
	}
	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/flows/"+f.ID, nil)
	mustStatus(t, st, 200, body)
	if steps, _ := body["steps"].([]any); len(steps) != 1 {
		t.Fatalf("get %v", body)
	}
	st, body = viewer.do("POST", "/v1/tenants/"+tat+"/flows/"+f.ID+"/cancel", map[string]any{"reason": "x"})
	mustStatus(t, st, 403, body)
	st, body = admin.do("POST", "/v1/tenants/"+tat+"/flows/"+f.ID+"/retry", map[string]any{})
	mustStatus(t, st, 409, body) // still running, not failed
	st, body = admin.do("POST", "/v1/tenants/"+tat+"/flows/"+f.ID+"/cancel", map[string]any{})
	mustStatus(t, st, 400, body)
	st, body = admin.do("POST", "/v1/tenants/"+tat+"/flows/"+f.ID+"/cancel", map[string]any{"reason": "wrong env"})
	mustStatus(t, st, 200, body)
	if body["state"] != "cancelling" {
		t.Fatalf("cancel %v", body)
	}
	st, body = admin.do("GET", "/v1/tenants/"+tat+"/flows/00000000-0000-4000-8000-000000000000", nil)
	mustStatus(t, st, 404, body)
}

type stubOrg struct{}

func (stubOrg) Provider() string                                          { return "tencent" }
func (stubOrg) EnsureUnit(context.Context, string) (string, error)        { return "1", nil }
func (stubOrg) FindAccount(context.Context, string) (string, bool, error) { return "", false, nil }
func (stubOrg) CreateAccount(context.Context, string, string, map[string]string) (string, error) {
	return "100001", nil
}
func (stubOrg) AccountReady(context.Context, string) (bool, error) { return true, nil }

func TestVendingAPI(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	v := vending.Vendor{Store: s, Org: stubOrg{}}
	e := flow.New(s, v.Def())
	w := river.NewWorkers()
	e.Register(w)
	c, err := flow.NewClient(s.AppPool(), w, flow.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e.SetClient(c)
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		Vending: &api.VendingDeps{Authz: az, Engine: e, Vendors: map[string]vending.Vendor{"tencent": v}}}))
	t.Cleanup(srv.Close)
	cl := client{t: t, url: srv.URL}
	admin := cl.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	inTAT := cl.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": body["id"], "slug": "tat-crm", "name": "TAT CRM"})
	project := body["id"].(string)
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects/"+project+"/environments", map[string]any{"name": "dev"})
	env := body["id"].(string)
	url := "/v1/tenants/" + tat + "/projects/" + project + "/environments/" + env + "/vend"

	lead := cl.as(auth.Principal{Subject: "user:l@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true, Bindings: []auth.Binding{{Role: auth.RoleTeamLead, TenantID: tat}}})
	st, body := lead.do("POST", url, map[string]any{"provider": "tencent"})
	mustStatus(t, st, 403, body)
	st, body = inTAT.do("POST", url, map[string]any{"provider": "aws"})
	mustStatus(t, st, 400, body)
	st, body = inTAT.do("POST", url, map[string]any{"provider": "tencent"})
	mustStatus(t, st, 202, body)
	if body["kind"] != "vend_environment_tencent" || body["input"].(map[string]any)["account_name"] != "tat-tat-crm-dev" {
		t.Fatalf("flow %v", body)
	}
	st, body = inTAT.do("POST", url, map[string]any{"provider": "tencent"})
	mustStatus(t, st, 200, body) // same run, not a second one
	st, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects/"+project+"/environments/00000000-0000-4000-8000-000000000000/vend", map[string]any{"provider": "tencent"})
	mustStatus(t, st, 404, body)
}
