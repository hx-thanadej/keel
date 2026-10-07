package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// headerAuth trusts a JSON principal in a header. Test-only.
type headerAuth struct{}

func (headerAuth) Authenticate(r *http.Request) (auth.Principal, error) {
	var p auth.Principal
	h := r.Header.Get("X-Test-Principal")
	if h == "" {
		return p, auth.ErrUnauthenticated
	}
	err := json.Unmarshal([]byte(h), &p)
	return p, err
}

type client struct {
	t   *testing.T
	url string
	p   *auth.Principal
}

func (c client) as(p auth.Principal) client { c.p = &p; return c }

func (c client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.url+path, rd)
	if c.p != nil {
		b, _ := json.Marshal(c.p)
		req.Header.Set("X-Test-Principal", string(b))
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var out map[string]any
	raw, _ := io.ReadAll(res.Body)
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	} else if len(raw) > 0 {
		out = map[string]any{"_raw": string(raw)}
	}
	return res.StatusCode, out
}

func setup(t *testing.T) (client, string) {
	t.Helper()
	s := storetest.New(t)
	az, err := authz.New()
	if err != nil {
		t.Fatal(err)
	}
	homeID, err := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.NewRouter(api.Info{Version: "test"}, api.Deps{
		Auth:    headerAuth{},
		Catalog: catalog.New(s, az),
	}))
	t.Cleanup(srv.Close)
	return client{t: t, url: srv.URL}, homeID
}

func homeAdmin(home string, extra ...auth.Binding) auth.Principal {
	return auth.Principal{
		Subject: "user:admin@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true,
		Bindings: append([]auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: home}}, extra...),
	}
}

func items(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	raw, ok := body["items"].([]any)
	if !ok {
		t.Fatalf("no items in %v", body)
	}
	out := make([]map[string]any, len(raw))
	for i, r := range raw {
		out[i] = r.(map[string]any)
	}
	return out
}

func mustStatus(t *testing.T, got, want int, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("status = %d, want %d; body %v", got, want, body)
	}
}

// Tracer bullet: tenant → team → project → environments → cloud accounts,
// every write recorded as exactly one Activity.
func TestCatalogFlowRecordsOneActivityPerWrite(t *testing.T) {
	c, home := setup(t)
	admin := c.as(homeAdmin(home))

	st, body := c.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	mustStatus(t, st, 401, body)

	st, body = admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT", "why": "new client"})
	mustStatus(t, st, 201, body)
	tat := body["id"].(string)

	st, body = admin.do("POST", "/v1/tenants/"+home+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	mustStatus(t, st, 201, body)
	team := body["id"].(string)

	// Admin needs a binding in the client Tenant to act there.
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	st, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": team, "slug": "tat-crm", "name": "TAT CRM"})
	mustStatus(t, st, 201, body)
	project := body["id"].(string)

	envs := map[string]string{}
	for _, e := range []string{"dev", "prod"} {
		st, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects/"+project+"/environments", map[string]any{"name": e})
		mustStatus(t, st, 201, body)
		envs[e] = body["id"].(string)
	}
	st, body = inTAT.do("POST", "/v1/tenants/"+tat+"/cloud-accounts", map[string]any{
		"environment_id": envs["prod"], "provider": "tencent", "external_id": "200048351622", "name": "tat-crm-prod"})
	mustStatus(t, st, 201, body)

	st, body = inTAT.do("PATCH", "/v1/tenants/"+tat+"/projects/"+project, map[string]any{"name": "TAT CRM Platform"})
	mustStatus(t, st, 200, body)
	if body["name"] != "TAT CRM Platform" {
		t.Errorf("rename not applied: %v", body)
	}

	st, body = inTAT.do("GET", "/v1/tenants/"+tat+"/projects/"+project+"/environments", nil)
	mustStatus(t, st, 200, body)
	if n := len(items(t, body)); n != 2 {
		t.Errorf("environments = %d, want 2", n)
	}

	// TAT's log: project create, 2 env creates, account create, project update = 5.
	// The tenant-created Activity also belongs to TAT (it is about TAT) = 6.
	st, body = inTAT.do("GET", "/v1/tenants/"+tat+"/activities", nil)
	mustStatus(t, st, 200, body)
	acts := items(t, body)
	if len(acts) != 6 {
		types := []any{}
		for _, a := range acts {
			types = append(types, a["type"])
		}
		t.Fatalf("TAT activities = %d %v, want 6", len(acts), types)
	}
	if acts[0]["type"] != "keel.project.updated" || acts[len(acts)-1]["type"] != "keel.tenant.created" {
		t.Errorf("unexpected order/types: first %v last %v", acts[0]["type"], acts[len(acts)-1]["type"])
	}
}

func TestDeniedWritesAreRecorded(t *testing.T) {
	c, home := setup(t)
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)

	viewer := c.as(auth.Principal{Subject: "user:viewer@tat.go.th", Kind: auth.KindHuman, TenantID: tat,
		Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	st, body := viewer.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": "00000000-0000-4000-8000-000000000000", "slug": "xx", "name": "X"})
	mustStatus(t, st, 403, body)

	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/activities", nil)
	mustStatus(t, st, 200, body)
	acts := items(t, body)
	found := false
	for _, a := range acts {
		if a["type"] == "keel.project.create.denied" && a["actor_uid"] == "user:viewer@tat.go.th" {
			found = true
			ev := a["event"].(map[string]any)["data"].(map[string]any)
			if ev["status_id"].(float64) != 2 || ev["status_detail"] == "" {
				t.Errorf("denied activity lacks failure status/detail: %v", ev)
			}
		}
	}
	if !found {
		t.Fatalf("denied write not recorded; activities %v", acts)
	}
}

func TestTenantsCannotSeeEachOther(t *testing.T) {
	c, home := setup(t)
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	acme := body["id"].(string)

	acmeViewer := c.as(auth.Principal{Subject: "user:v@acme.com", Kind: auth.KindHuman, TenantID: acme,
		Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: acme}}})
	for _, path := range []string{"/v1/tenants/" + tat, "/v1/tenants/" + tat + "/projects", "/v1/tenants/" + tat + "/activities", "/v1/tenants/" + tat + "/cloud-accounts"} {
		st, body := acmeViewer.do("GET", path, nil)
		if st != 403 {
			t.Errorf("GET %s as other tenant: status %d body %v, want 403", path, st, body)
		}
	}
	st, _ := acmeViewer.do("GET", "/v1/tenants/"+acme, nil)
	if st != 200 {
		t.Errorf("own tenant: %d", st)
	}
}

func TestValidationAndConflicts(t *testing.T) {
	c, home := setup(t)
	admin := c.as(homeAdmin(home))
	st, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "Bad Slug!", "name": "x"})
	mustStatus(t, st, 400, body)
	st, body = admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	mustStatus(t, st, 201, body)
	st, body = admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT again"})
	mustStatus(t, st, 409, body)
	st, body = admin.do("GET", "/v1/tenants/not-a-uuid", nil)
	mustStatus(t, st, 400, body)
}

func TestArchiveHidesFromList(t *testing.T) {
	c, home := setup(t)
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants/"+home+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	team := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants/"+home+"/projects", map[string]any{"team_id": team, "slug": "keel", "name": "Keel"})
	project := body["id"].(string)

	st, body := admin.do("POST", "/v1/tenants/"+home+"/projects/"+project+"/archive", map[string]any{"why": "done"})
	mustStatus(t, st, 200, body)
	st, body = admin.do("GET", "/v1/tenants/"+home+"/projects", nil)
	mustStatus(t, st, 200, body)
	if n := len(items(t, body)); n != 0 {
		t.Errorf("archived project still listed (%d)", n)
	}
}
