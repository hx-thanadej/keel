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
