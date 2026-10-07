package api_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/promotion"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestPromotionsAPI(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	promo, err := promotion.New(promotion.Service{Store: s})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az), Promotion: &api.PromotionDeps{Authz: az, Service: promo}}))
	t.Cleanup(srv.Close)
	cl := client{t: t, url: srv.URL}
	admin := cl.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	inTAT := cl.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	team := body["id"].(string)
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": team, "slug": "tat-crm", "name": "TAT CRM"})
	project := body["id"].(string)
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects/"+project+"/environments", map[string]any{"name": "prod"})
	env := body["id"].(string)
	var svc string
	if err := s.InTenant(t.Context(), tat, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'CRM API') RETURNING id::text`, tat, project, team).Scan(&svc)
	}); err != nil {
		t.Fatal(err)
	}
	eng := cl.as(auth.Principal{Subject: "user:e@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true, Bindings: []auth.Binding{{Role: auth.RoleEngineer, TenantID: tat}}})
	lead := cl.as(auth.Principal{Subject: "user:l@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true, Bindings: []auth.Binding{{Role: auth.RoleTeamLead, TenantID: tat}}})
	viewer := cl.as(auth.Principal{Subject: "user:v@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	approver := cl.as(auth.Principal{Subject: "user:a@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantApprover, TenantID: tat}}})

	// Team lead sets the config repo, but only a Platform Admin can change who must approve.
	st, body := lead.do("PATCH", "/v1/tenants/"+tat+"/projects/"+project, map[string]any{"config_repo": "hx/tat-crm-config"})
	mustStatus(t, st, 200, body)
	st, body = lead.do("PATCH", "/v1/tenants/"+tat+"/projects/"+project+"/environments/"+env, map[string]any{"requires_approval": false})
	mustStatus(t, st, 403, body)
	st, body = inTAT.do("PATCH", "/v1/tenants/"+tat+"/projects/"+project+"/environments/"+env, map[string]any{"requires_approval": true, "promotion_order": 1})
	mustStatus(t, st, 200, body)

	img := []map[string]string{{"name": "ccr.ccs.tencentyun.com/tat/crm-api", "digest": "sha256:" + strings.Repeat("c", 64)}}
	st, body = viewer.do("POST", "/v1/tenants/"+tat+"/services/"+svc+"/releases", map[string]any{"version": "1.0.0", "images": img})
	mustStatus(t, st, 403, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/services/"+svc+"/releases", map[string]any{"version": "1.0.0", "images": []map[string]string{{"name": "x", "digest": "latest"}}})
	mustStatus(t, st, 400, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/services/"+svc+"/releases", map[string]any{"version": "1.0.0", "images": img, "commit_sha": "abc"})
	mustStatus(t, st, 201, body)
	rel := body["id"].(string)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/releases/"+rel+"/promote", map[string]any{"environment_id": env})
	mustStatus(t, st, 200, body)
	if body["state"] != "pending_approval" {
		t.Fatalf("promotion %v", body)
	}
	promo1 := body["id"].(string)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/promotions/"+promo1+"/approve", map[string]any{})
	mustStatus(t, st, 403, body)
	// The approver may approve; without a configured Git client the PR step fails and is recorded.
	st, body = approver.do("POST", "/v1/tenants/"+tat+"/promotions/"+promo1+"/approve", map[string]any{})
	mustStatus(t, st, 200, body)
	if body["state"] != "failed" || !strings.Contains(body["error"].(string), "not configured") {
		t.Fatalf("approve %v", body)
	}
	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/promotions?release="+rel, nil)
	mustStatus(t, st, 200, body)
	if got := items(t, body); len(got) != 1 {
		t.Fatalf("list %v", got)
	}
}
