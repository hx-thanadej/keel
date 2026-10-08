package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/breakglass"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestBreakGlassIsHomeOnly(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		BreakGlass: &api.BreakGlassDeps{Authz: az, Service: breakglass.Service{Store: s}, Home: func(*http.Request) (string, error) { return home, nil }}}))
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}
	homeSec := c.as(auth.Principal{Subject: "user:sec@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true, Bindings: []auth.Binding{{Role: auth.RoleSecurityLead, TenantID: home}}})
	clientAdmin := c.as(auth.Principal{Subject: "user:admin@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: tat}}})
	homeAdminInTAT := c.as(auth.Principal{Subject: "user:a@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true, Bindings: []auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: tat}}})

	body := map[string]any{"account": "200045645249", "principal_id": "100099", "name": "breakglass-1", "holder": "CTO safe", "hardware_mfa": true}
	for _, who := range []client{clientAdmin, homeAdminInTAT} {
		st, b := who.do("POST", "/v1/breakglass", body)
		mustStatus(t, st, 403, b)
		st, b = who.do("GET", "/v1/breakglass", nil)
		mustStatus(t, st, 403, b)
	}
	st, b := homeSec.do("POST", "/v1/breakglass", body)
	mustStatus(t, st, 201, b)
	st, b = homeSec.do("GET", "/v1/breakglass", nil)
	mustStatus(t, st, 200, b)
	if got := items(t, b); len(got) != 1 {
		t.Fatalf("list %v", got)
	}
}
