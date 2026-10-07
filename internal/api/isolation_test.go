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
	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/discovery"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/promotion"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store/storetest"
	"github.com/hx-thanadej/keel/internal/templates"
	"github.com/hx-thanadej/keel/internal/vending"
)

// Routes that are not Tenant-scoped, with the reason. Every other route must
// contain {tenant} and is attacked below. Adding a route that is neither
// fails this suite: it is release-blocking (#23).
var notTenantScoped = map[string]string{
	"GET /healthz":       "no data",
	"POST /v1/tenants":   "creates a new Tenant; policy-gated to home platform admins (authz tests)",
	"GET /auth/login":    "pre-authentication",
	"GET /auth/callback": "pre-authentication",
	"POST /auth/logout":  "acts on caller's own session",
	"GET /auth/me":       "returns caller's own principal",
}

type victim struct {
	ids     map[string]string // path param → id
	secrets []string          // strings that must never appear in another Tenant's responses
}

// TestCrossTenantIsolationEveryRoute calls every Tenant-scoped route with
// Tenant A's identifiers as principals from Tenant B, and requires a 4xx with
// none of A's identifiers in the body.
func TestCrossTenantIsolationEveryRoute(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, err := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	if err != nil {
		t.Fatal(err)
	}
	promo, err := promotion.New(promotion.Service{Store: s})
	if err != nil {
		t.Fatal(err)
	}
	router := api.NewRouter(api.Info{Version: "test"}, api.Deps{Auth: headerAuth{}, Sessions: noRoutes{}, Catalog: catalog.New(s, az),
		Discovery: map[string]discovery.Source{"tencent": fakeOrg{{Provider: "tencent", ExternalID: "victim-uin-123", Name: "victim-prod"}}},
		Cost:      &api.CostDeps{Authz: az, Queries: cost.Queries{Store: s}, Ingester: &cost.Ingester{Store: s}, Rules: cost.Rules{Store: s}},
		Budgets:   &api.BudgetDeps{Authz: az, Catalog: catalog.New(s, az), Budgets: budget.Service{Store: s}, Resolve: stubResolve},
		Authz:     az,
		Rightsize: &api.RightsizeDeps{Authz: az, Service: rightsize.Service{Store: s}},
		Flows:     &api.FlowDeps{Authz: az, Engine: flow.New(s)},
		Promotion: &api.PromotionDeps{Authz: az, Service: promo},
		Registry:  &api.RegistryDeps{Authz: az, Store: s},
		Templates: &api.TemplateDeps{Authz: az, Engine: flow.New(s), Creator: templates.Creator{Store: s, Org: "acme", Templates: map[string]templates.Template{"go": {Name: "go", Repo: "acme/tmpl"}}}},
		Vending:   &api.VendingDeps{Authz: az, Engine: flow.New(s), Vendors: map[string]vending.Vendor{"tencent": {Store: s, Org: stubOrg{}}}}})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}

	// Seed Tenant A fully, through the API.
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "victim", "name": "Victim Co"})
	a := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants", map[string]any{"slug": "attacker", "name": "Attacker Co"})
	b := body["id"].(string)
	inA := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: a}))
	_, body = inA.do("POST", "/v1/tenants/"+a+"/teams", map[string]any{"slug": "victim-team", "name": "Victim Team"})
	team := body["id"].(string)
	_, body = inA.do("POST", "/v1/tenants/"+a+"/projects", map[string]any{"team_id": team, "slug": "victim-project", "name": "Victim Project"})
	project := body["id"].(string)
	_, body = inA.do("POST", "/v1/tenants/"+a+"/projects/"+project+"/environments", map[string]any{"name": "prod"})
	env := body["id"].(string)
	_, body = inA.do("POST", "/v1/tenants/"+a+"/cloud-accounts", map[string]any{"environment_id": env, "provider": "tencent", "external_id": "victim-uin-123", "name": "victim-prod"})
	account := body["id"].(string)
	_, body = inA.do("POST", "/v1/tenants/"+a+"/identity-providers", map[string]any{"issuer": "https://idp.victim.example", "client_id": "victim-client", "client_secret_ref": "VICTIM_SECRET"})
	idp := body["id"].(string)
	// A valid body per write route, so requests reach the policy check rather
	// than failing validation first.
	bodies := map[string]map[string]any{
		"POST /v1/tenants/{tenant}/teams":                                         {"slug": "pwn-team", "name": "Pwn"},
		"POST /v1/tenants/{tenant}/projects":                                      {"team_id": team, "slug": "pwn-project", "name": "Pwn"},
		"PATCH /v1/tenants/{tenant}/projects/{project}":                           {"name": "Pwned"},
		"POST /v1/tenants/{tenant}/projects/{project}/archive":                    {"why": "pwn"},
		"POST /v1/tenants/{tenant}/projects/{project}/environments":               {"name": "pwn"},
		"POST /v1/tenants/{tenant}/projects/{project}/environments/{env}/archive": {"why": "pwn"},
		"POST /v1/tenants/{tenant}/cloud-accounts":                                {"provider": "aws", "external_id": "pwn-1", "name": "pwn"},
		"POST /v1/tenants/{tenant}/cloud-accounts/{account}/archive":              {"why": "pwn"},
		"POST /v1/tenants/{tenant}/identity-providers":                            {"issuer": "https://pwn.example", "client_id": "pwn", "client_secret_ref": "PWN"},
		"POST /v1/tenants/{tenant}/identity-providers/{idp}/group-roles":          {"group": "pwn", "role": "platform_admin", "target_tenant_id": a},
		"POST /v1/tenants/{tenant}/discoveries/{provider}":                        {},
		"POST /v1/tenants/{tenant}/cost-loads":                                    {},
		"PATCH /v1/tenants/{tenant}":                                              {"currency": "THB"},
		"POST /v1/tenants/{tenant}/budgets":                                       {"project_id": project, "name": "pwn", "year": 2026, "amount": "1"},
		"PATCH /v1/tenants/{tenant}/budgets/{budget}":                             {"amount": "1"},
		"POST /v1/tenants/{tenant}/budgets/{budget}/archive":                      {},
		"POST /v1/tenants/{tenant}/findings/{finding}/resolve":                    {"resolution": "pwn"},
		"POST /v1/tenants/{tenant}/allocation-rules":                              {"provider": "tencent", "sub_account_id": "pwn", "kind": "k8s", "cluster": "pwn"},
		"POST /v1/tenants/{tenant}/allocation-rules/{rule}/archive":               {},
		"PUT /v1/tenants/{tenant}/k8s-namespaces/{cluster}/{namespace}":           {"project_id": project},
		"POST /v1/tenants/{tenant}/recommendations/{recommendation}/accept":       {},
		"POST /v1/tenants/{tenant}/recommendations/{recommendation}/apply":        {},
		"PATCH /v1/tenants/{tenant}/projects/{project}/environments/{env}":        {"waste_cleanup": false},
		"POST /v1/tenants/{tenant}/recommendations/{recommendation}/dismiss":      {"reason": "pwn"},
		"POST /v1/tenants/{tenant}/flows/{flow}/retry":                            {},
		"POST /v1/tenants/{tenant}/flows/{flow}/cancel":                           {"reason": "pwn"},
		"POST /v1/tenants/{tenant}/projects/{project}/environments/{env}/vend":    {"provider": "tencent"},
		"POST /v1/tenants/{tenant}/services/{service}/releases":                   {"version": "pwn", "images": []map[string]string{{"name": "x", "digest": "sha256:" + strings.Repeat("a", 64)}}},
		"POST /v1/tenants/{tenant}/releases/{release}/promote":                    {"environment_id": env},
		"POST /v1/tenants/{tenant}/releases/{release}/preview":                    {"environment_id": env},
		"POST /v1/tenants/{tenant}/promotions/{promotion}/approve":                {},
		"POST /v1/tenants/{tenant}/projects/{project}/services":                   {"slug": "pwn", "template": "go"},
	}
	_, body = inA.do("POST", "/v1/tenants/"+a+"/budgets", map[string]any{"project_id": project, "name": "Victim Budget", "year": 2026, "amount": "123456"})
	victimBudget := body["id"].(string)
	var victimFinding string
	if err := s.InTenant(t.Context(), a, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title) VALUES ($1, 'cost_anomaly', 'victim-fp', 'high', 'Victim Finding') RETURNING id::text`, a).Scan(&victimFinding)
	}); err != nil {
		t.Fatal(err)
	}
	victimRec, _, err := (rightsize.Service{Store: s}).Upsert(t.Context(), a, rightsize.Recommendation{Source: "engine:k8s", Provider: "tencent", ResourceID: "victim-workload",
		ResourceType: "k8s_workload", Action: "resize_requests", MonthlySavings: "99.00", Currency: "USD", Confidence: 0.9, ProjectID: &project})
	if err != nil {
		t.Fatal(err)
	}
	var victimFlow string
	if err := s.InTenant(t.Context(), a, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `INSERT INTO flows (tenant_id, kind, subject, input, state, created_by) VALUES ($1, 'vend_environment', 'environment/victim-flow-subject', '{"name":"victim-flow-input"}', 'failed', 'user:victim') RETURNING id::text`, a).Scan(&victimFlow)
	}); err != nil {
		t.Fatal(err)
	}
	var victimService, victimRelease, victimPromotion string
	if err := s.InTenant(t.Context(), a, func(tx pgx.Tx) error {
		if err := tx.QueryRow(t.Context(), `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'victim-svc', 'Victim Service') RETURNING id::text`, a, project, team).Scan(&victimService); err != nil {
			return err
		}
		if err := tx.QueryRow(t.Context(), `INSERT INTO releases (tenant_id, service_id, version, images, created_by) VALUES ($1, $2, 'victim-1.0', '[{"name":"victim/img","digest":"sha256:victim"}]', 'u') RETURNING id::text`, a, victimService).Scan(&victimRelease); err != nil {
			return err
		}
		return tx.QueryRow(t.Context(), `INSERT INTO promotions (tenant_id, release_id, environment_id, state, requested_by) VALUES ($1, $2, $3, 'pending_approval', 'user:victim') RETURNING id::text`, a, victimRelease, env).Scan(&victimPromotion)
	}); err != nil {
		t.Fatal(err)
	}
	v := victim{
		ids:     map[string]string{"tenant": a, "project": project, "env": env, "account": account, "idp": idp, "provider": "tencent", "budget": victimBudget, "finding": victimFinding, "rule": victimFinding, "cluster": "victim-cluster", "namespace": "victim-ns", "recommendation": victimRec.ID, "flow": victimFlow, "service": victimService, "release": victimRelease, "promotion": victimPromotion},
		secrets: []string{a, team, project, env, account, idp, "Victim Co", "victim-project", "victim-uin-123", "idp.victim.example", "victim-client", victimBudget, "Victim Budget", "123456", victimFinding, "Victim Finding", victimRec.ID, "victim-workload", victimFlow, "victim-flow-subject", "victim-flow-input", victimService, victimRelease, victimPromotion, "victim-1.0", "victim/img"},
	}

	attackers := map[string]auth.Principal{
		"B tenant member (admin role)": {Subject: "user:mallory@attacker.example", Kind: auth.KindHuman, TenantID: b,
			Bindings: []auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: b}, {Role: auth.RoleTeamLead, TenantID: b}}},
		"B member forging a binding into A": {Subject: "user:mallory@attacker.example", Kind: auth.KindHuman, TenantID: b,
			Bindings: []auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: a}}},
		"home admin without a binding in A": homeAdmin(home),
	}

	covered := 0
	for _, pattern := range router.Patterns() {
		method, path, _ := strings.Cut(pattern, " ")
		if !strings.Contains(path, "{tenant}") {
			if _, ok := notTenantScoped[pattern]; !ok {
				t.Errorf("route %q is not Tenant-scoped and not in notTenantScoped: add an isolation case or an exemption with a reason", pattern)
			}
			continue
		}
		covered++
		url := path
		for param, id := range v.ids {
			url = strings.ReplaceAll(url, "{"+param+"}", id)
		}
		if strings.Contains(url, "{") {
			t.Errorf("route %q has a path parameter the suite does not know; extend victim.ids", pattern)
			continue
		}
		var body map[string]any
		if method != "GET" {
			var ok bool
			if body, ok = bodies[pattern]; !ok {
				t.Errorf("write route %q has no valid body in the suite; add one so the policy check is exercised", pattern)
				continue
			}
		}
		for name, p := range attackers {
			st, raw := rawDo(t, srv.URL, method, url, p, body)
			if st < 400 || st >= 500 {
				t.Errorf("%s %s as %s: status %d, want 4xx", method, url, name, st)
			}
			for _, secret := range v.secrets {
				if strings.Contains(raw, secret) {
					t.Errorf("%s %s as %s: response leaks %q: %s", method, url, name, secret, raw)
				}
			}
		}
	}
	if covered == 0 {
		t.Fatal("no Tenant-scoped routes found")
	}
	t.Logf("attacked %d Tenant-scoped routes × %d principals", covered, len(attackers))
}

type noRoutes struct{}

func (noRoutes) Mount(m interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}) {
	for p := range notTenantScoped {
		if strings.HasPrefix(p, "GET /auth") || strings.HasPrefix(p, "POST /auth") {
			m.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
		}
	}
}

func rawDo(t *testing.T, base, method, path string, p auth.Principal, body map[string]any) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, base+path, rd)
	pj, _ := json.Marshal(p)
	req.Header.Set("X-Test-Principal", string(pj))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(raw)
}
