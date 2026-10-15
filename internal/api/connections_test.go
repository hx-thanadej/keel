package api_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/connections"
	"github.com/hx-thanadej/keel/internal/secrets"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

const (
	connSecretID  = "TESTIDz8krbsJ5yKBZQpn74WFkmLPx3FAKE"
	connSecretKey = "Gu5t9xGARNpq86cd98joQYCN3EXAMPLEKEY"
)

func testSealer(t *testing.T) *secrets.Sealer {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	s, err := secrets.FromEnv(func(n string) string {
		if n == "KEEL_SECRETS_KEY" {
			return base64.StdEncoding.EncodeToString(k)
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func noKeys(t *testing.T, body map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	for _, s := range []string{connSecretID, connSecretKey, "rotated-secret-key-0123456789"} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("response carries key material: %s", raw)
		}
	}
}

// TestCloudConnectionsAPI: only a home platform admin manages connections;
// home security and finops leads may read them; nobody outside the home
// Tenant sees them. Responses show the SecretId masked and never the key.
func TestCloudConnectionsAPI(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	svc := connections.Service{Store: s, Sealer: testSealer(t), Identify: func(_ context.Context, k connections.Keys, _ string) (string, error) {
		return "100000000001", nil
	}}
	deps := &api.ConnectionDeps{Authz: az, Service: svc, Home: func(*http.Request) (string, error) { return home, nil }}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az), Connections: deps}))
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}
	admin := c.as(homeAdmin(home))
	reader := c.as(auth.Principal{Subject: "user:sec@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true, Bindings: []auth.Binding{{Role: auth.RoleSecurityLead, TenantID: home}}})
	clientAdmin := c.as(auth.Principal{Subject: "user:admin@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: tat}}})
	homeAdminInTAT := c.as(auth.Principal{Subject: "user:a@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true, Bindings: []auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: tat}}})

	body := map[string]any{"provider": "tencent", "name": "HarmonyX payer", "payer_uin": "100000000001", "default_region": "ap-bangkok",
		"keys": map[string]any{"secret_id": connSecretID, "secret_key": connSecretKey}}
	for _, who := range []client{clientAdmin, homeAdminInTAT, reader} {
		st, b := who.do("POST", "/v1/cloud-connections", body)
		mustStatus(t, st, 403, b)
	}
	st, b := admin.do("POST", "/v1/cloud-connections", map[string]any{"provider": "tencent", "name": "x", "payer_uin": "100000000001", "default_region": "ap-bangkok",
		"mode": "read_write", "keys": map[string]any{"secret_id": connSecretID, "secret_key": connSecretKey}})
	mustStatus(t, st, 400, b)
	noKeys(t, b)

	st, created := admin.do("POST", "/v1/cloud-connections", body)
	mustStatus(t, st, 201, created)
	noKeys(t, created)
	if created["secret_id"] != "****FAKE" || created["mode"] != "read_only" {
		t.Fatalf("created %v", created)
	}
	id := created["id"].(string)
	path := "/v1/cloud-connections/" + id

	for _, who := range []client{clientAdmin, homeAdminInTAT} {
		st, b := who.do("GET", "/v1/cloud-connections", nil)
		mustStatus(t, st, 403, b)
		noKeys(t, b)
	}
	for _, who := range []client{clientAdmin, homeAdminInTAT, reader} {
		for _, call := range []struct{ method, path string }{{"PATCH", path}, {"DELETE", path}, {"POST", path + "/test"}} {
			st, b := who.do(call.method, call.path, map[string]any{"name": "pwn"})
			mustStatus(t, st, 403, b)
		}
	}
	for _, who := range []client{admin, reader} {
		st, b := who.do("GET", "/v1/cloud-connections", nil)
		mustStatus(t, st, 200, b)
		noKeys(t, b)
		if got := items(t, b); len(got) != 1 || got[0]["secret_id"] != "****FAKE" {
			t.Fatalf("list %v", got)
		}
	}

	st, b = admin.do("POST", path+"/test", nil)
	mustStatus(t, st, 200, b)
	if last, _ := b["last_test"].(map[string]any); last == nil || last["ok"] != true || last["caller_uin"] != "100000000001" {
		t.Fatalf("test %v", b)
	}
	st, b = admin.do("PATCH", path, map[string]any{"keys": map[string]any{"secret_id": "TESTIDrotatedrotatedrotated9ZZZ", "secret_key": "rotated-secret-key-0123456789"}})
	mustStatus(t, st, 200, b)
	noKeys(t, b)
	if b["secret_id"] != "****9ZZZ" || b["rotated_at"] == nil || b["last_test"] != nil {
		t.Fatalf("rotated %v", b)
	}
	st, b = admin.do("POST", "/v1/cloud-connections", body)
	mustStatus(t, st, 409, b)
	st, b = admin.do("DELETE", path, nil)
	mustStatus(t, st, 204, b)
	st, b = admin.do("DELETE", path, nil)
	mustStatus(t, st, 404, b)
}

// TestCloudConnectionsNeedSecretsKey: without KEEL_SECRETS_KEY Keel lists
// connections but refuses to store a key.
func TestCloudConnectionsNeedSecretsKey(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	deps := &api.ConnectionDeps{Authz: az, Service: connections.Service{Store: s}, Home: func(*http.Request) (string, error) { return home, nil }}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az), Connections: deps}))
	t.Cleanup(srv.Close)
	admin := client{t: t, url: srv.URL}.as(homeAdmin(home))
	st, b := admin.do("GET", "/v1/cloud-connections", nil)
	mustStatus(t, st, 200, b)
	st, b = admin.do("POST", "/v1/cloud-connections", map[string]any{"provider": "tencent", "name": "x", "payer_uin": "100000000001", "default_region": "ap-bangkok",
		"keys": map[string]any{"secret_id": connSecretID, "secret_key": connSecretKey}})
	mustStatus(t, st, 409, b)
	if !strings.Contains(b["error"].(string), "KEEL_SECRETS_KEY") {
		t.Fatalf("error %v", b)
	}
}
