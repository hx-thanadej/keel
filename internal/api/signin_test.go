package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/oidcauth"
	"github.com/hx-thanadej/keel/internal/oidcauth/oidctest"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type world struct {
	t       *testing.T
	keel    string
	homeIdP *oidctest.Provider
	tatIdP  *oidctest.Provider
	home    string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	s := storetest.New(t)
	az, err := authz.New()
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t,
		homeIdP: oidctest.New(t, "keel-home", "home-secret"),
		tatIdP:  oidctest.New(t, "keel-tat", "tat-secret"),
	}
	secrets := map[string]string{"HOME_SECRET": "home-secret", "TAT_SECRET": "tat-secret"}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	w.keel = srv.URL

	sessions, err := oidcauth.New(s, oidcauth.Config{
		BaseURL:   srv.URL,
		CookieKey: []byte("0123456789abcdef0123456789abcdef"),
		Secrets: func(ref string) (string, error) {
			return secrets[ref], nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w.home, err = oidcauth.Bootstrap(t.Context(), s, oidcauth.BootstrapInput{
		HomeSlug: "harmonyx", HomeName: "HarmonyX",
		Issuer: w.homeIdP.URL, ClientID: "keel-home", ClientSecretRef: "HOME_SECRET",
		AdminGroup: "keel-admins", EmailDomain: "harmonyx.co",
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", api.NewRouter(api.Info{Version: "test"}, api.Deps{Auth: sessions, Sessions: sessions, Catalog: catalog.New(s, az)}))
	return w
}

// browser follows redirects across Keel and the IdP, keeping cookies.
func browser(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func call(t *testing.T, c *http.Client, method, url string, body any, header ...string) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, url, rd)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var out map[string]any
	raw, _ := io.ReadAll(res.Body)
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return res.StatusCode, out
}

func (w *world) login(c *http.Client, tenantSlug string) int {
	w.t.Helper()
	res, err := c.Get(w.keel + "/auth/login?tenant=" + tenantSlug + "&return_to=/auth/me")
	if err != nil {
		w.t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

func bindingRoles(me map[string]any) []string {
	var out []string
	bs, _ := me["bindings"].([]any)
	for _, b := range bs {
		m := b.(map[string]any)
		out = append(out, m["role"].(string)+"@"+m["tenant_id"].(string))
	}
	return out
}

func TestHomeStaffSignInAndOnboardClientWithOwnIdP(t *testing.T) {
	w := newWorld(t)
	admin := browser(t)

	w.homeIdP.LoginAs(map[string]any{"sub": "a1", "email": "admin@harmonyx.co", "email_verified": true, "groups": []string{"keel-admins"}, "amr": []string{"pwd", "mfa"}})
	if st := w.login(admin, "harmonyx"); st != 200 {
		t.Fatalf("login landed on %d, want 200", st)
	}
	st, me := call(t, admin, "GET", w.keel+"/auth/me", nil)
	if st != 200 || me["subject"] != "user:admin@harmonyx.co" || me["home"] != true || me["mfa"] != true {
		t.Fatalf("me = %d %v", st, me)
	}
	if roles := bindingRoles(me); len(roles) != 1 || roles[0] != "platform_admin@"+w.home {
		t.Fatalf("bindings = %v", roles)
	}

	// Onboard TAT with its own IdP; TAT viewers group → tenant_viewer in TAT.
	st, body := call(t, admin, "POST", w.keel+"/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	if st != 201 {
		t.Fatalf("create tenant %d %v", st, body)
	}
	tat := body["id"].(string)
	// Admin must hold a binding in TAT to configure it: map a home group into TAT.
	st, body = call(t, admin, "POST", w.keel+"/v1/tenants/"+w.home+"/identity-providers", nil)
	if st != 400 {
		t.Fatalf("empty idp body: %d %v", st, body)
	}
	st, idps := call(t, admin, "GET", w.keel+"/v1/tenants/"+w.home+"/identity-providers", nil)
	if st != 200 {
		t.Fatalf("list idps %d %v", st, idps)
	}
	homeIdP := idps["items"].([]any)[0].(map[string]any)["id"].(string)
	st, body = call(t, admin, "POST", w.keel+"/v1/tenants/"+w.home+"/identity-providers/"+homeIdP+"/group-roles",
		map[string]any{"group": "keel-admins", "role": "platform_admin", "target_tenant_id": tat})
	if st != 201 {
		t.Fatalf("map admins into TAT %d %v", st, body)
	}
	// Re-login picks up the new binding.
	if st := w.login(admin, "harmonyx"); st != 200 {
		t.Fatal("relogin failed")
	}
	st, body = call(t, admin, "POST", w.keel+"/v1/tenants/"+tat+"/identity-providers",
		map[string]any{"issuer": w.tatIdP.URL, "client_id": "keel-tat", "client_secret_ref": "TAT_SECRET", "email_domain": "tat.or.th"})
	if st != 201 {
		t.Fatalf("create tat idp %d %v", st, body)
	}
	tatIdP := body["id"].(string)
	st, body = call(t, admin, "POST", w.keel+"/v1/tenants/"+tat+"/identity-providers/"+tatIdP+"/group-roles",
		map[string]any{"group": "keel-viewers", "role": "tenant_viewer", "target_tenant_id": tat})
	if st != 201 {
		t.Fatalf("map tat viewers %d %v", st, body)
	}
	st, body = call(t, admin, "POST", w.keel+"/v1/tenants/"+tat+"/identity-providers/"+tatIdP+"/group-roles",
		map[string]any{"group": "keel-viewers", "role": "platform_admin", "target_tenant_id": w.home})
	if st != 400 {
		t.Fatalf("client IdP granting into home: %d %v, want 400", st, body)
	}

	// A TAT staff member signs in through TAT's IdP, side by side with admin.
	member := browser(t)
	w.tatIdP.LoginAs(map[string]any{"sub": "m1", "email": "somchai@tat.or.th", "email_verified": true, "groups": []string{"keel-viewers"}})
	if st := w.login(member, "tat"); st != 200 {
		t.Fatalf("member login %d", st)
	}
	st, me = call(t, member, "GET", w.keel+"/auth/me", nil)
	if st != 200 || me["home"] != false || me["tenant_id"] != tat {
		t.Fatalf("member me %d %v", st, me)
	}
	if roles := bindingRoles(me); len(roles) != 1 || roles[0] != "tenant_viewer@"+tat {
		t.Fatalf("member bindings = %v", roles)
	}
	if st, _ := call(t, member, "GET", w.keel+"/v1/tenants/"+tat+"/projects", nil); st != 200 {
		t.Errorf("member reads own projects: %d", st)
	}
	if st, _ := call(t, member, "GET", w.keel+"/v1/tenants/"+w.home, nil); st != 403 {
		t.Errorf("member reads home tenant: %d, want 403", st)
	}
	// Admin's session is unaffected.
	if st, me := call(t, admin, "GET", w.keel+"/auth/me", nil); st != 200 || me["subject"] != "user:admin@harmonyx.co" {
		t.Errorf("admin session clobbered: %d %v", st, me)
	}

	// TAT can see who from their org signed in.
	st, body = call(t, member, "GET", w.keel+"/v1/tenants/"+tat+"/activities?type=keel.session.signed_in", nil)
	if st != 200 || len(body["items"].([]any)) != 1 {
		t.Fatalf("tat sign-in activities %d %v", st, body)
	}
}

func TestSignInRejectsWrongEmailDomainAndRecordsIt(t *testing.T) {
	w := newWorld(t)
	c := browser(t)
	w.homeIdP.LoginAs(map[string]any{"sub": "x", "email": "mallory@evil.com", "email_verified": true, "groups": []string{"keel-admins"}})
	if st := w.login(c, "harmonyx"); st != 403 {
		t.Fatalf("login status %d, want 403", st)
	}
	if st, _ := call(t, c, "GET", w.keel+"/auth/me", nil); st != 401 {
		t.Fatalf("me after failed login: %d", st)
	}
	// Admin signs in and sees the failure.
	admin := browser(t)
	w.homeIdP.LoginAs(map[string]any{"sub": "a1", "email": "admin@harmonyx.co", "email_verified": true, "groups": []string{"keel-admins"}})
	w.login(admin, "harmonyx")
	st, body := call(t, admin, "GET", w.keel+"/v1/tenants/"+w.home+"/activities?type=keel.session.sign_in_failed", nil)
	if st != 200 || len(body["items"].([]any)) != 1 {
		t.Fatalf("failed sign-in not recorded: %d %v", st, body)
	}
}

func TestReturnToRejectsOffsiteRedirects(t *testing.T) {
	w := newWorld(t)
	w.homeIdP.LoginAs(map[string]any{"sub": "a1", "email": "admin@harmonyx.co", "email_verified": true, "groups": []string{"keel-admins"}})
	for _, rt := range []string{"https://evil.example/", "//evil.example/", "/\\evil.example"} {
		jar, _ := cookiejar.New(nil)
		var final string
		c := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			final = req.URL.String()
			return nil
		}}
		res, err := c.Get(w.keel + "/auth/login?tenant=harmonyx&return_to=" + url.QueryEscape(rt))
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if !strings.HasPrefix(final, w.keel+"/") || strings.Contains(final, "evil") {
			t.Errorf("return_to %q redirected to %q", rt, final)
		}
	}
}

func TestUnverifiedEmailRejected(t *testing.T) {
	w := newWorld(t)
	c := browser(t)
	w.homeIdP.LoginAs(map[string]any{"sub": "x", "email": "admin@harmonyx.co", "email_verified": false, "groups": []string{"keel-admins"}})
	if st := w.login(c, "harmonyx"); st != 403 {
		t.Fatalf("unverified email login %d, want 403", st)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	w := newWorld(t)
	c := browser(t)
	w.homeIdP.LoginAs(map[string]any{"sub": "a1", "email": "admin@harmonyx.co", "email_verified": true, "groups": []string{"keel-admins"}})
	w.login(c, "harmonyx")
	if st, _ := call(t, c, "POST", w.keel+"/auth/logout", nil); st != 204 {
		t.Fatalf("logout %d", st)
	}
	if st, _ := call(t, c, "GET", w.keel+"/auth/me", nil); st != 401 {
		t.Fatalf("me after logout %d, want 401", st)
	}
}

func TestBearerTokens(t *testing.T) {
	w := newWorld(t)
	plain := &http.Client{Timeout: 5 * time.Second}

	good := w.homeIdP.Mint(t, map[string]any{"sub": "ci", "email": "ci@harmonyx.co", "email_verified": true, "groups": []string{"keel-admins"}})
	st, me := call(t, plain, "GET", w.keel+"/auth/me", nil, "Authorization", "Bearer "+good)
	if st != 200 || me["subject"] != "user:ci@harmonyx.co" {
		t.Fatalf("bearer me %d %v", st, me)
	}
	wrongAud := w.homeIdP.Mint(t, map[string]any{"sub": "ci", "aud": "someone-else", "email": "ci@harmonyx.co", "email_verified": true})
	expired := w.homeIdP.Mint(t, map[string]any{"sub": "ci", "exp": time.Now().Add(-time.Hour).Unix(), "email": "ci@harmonyx.co", "email_verified": true})
	unknown := oidctest.New(t, "keel-home", "x").Mint(t, map[string]any{"sub": "ci", "email": "ci@harmonyx.co", "email_verified": true})
	for name, tok := range map[string]string{"wrong audience": wrongAud, "expired": expired, "unknown issuer": unknown, "garbage": "abc.def.ghi"} {
		if st, _ := call(t, plain, "GET", w.keel+"/auth/me", nil, "Authorization", "Bearer "+tok); st != 401 {
			t.Errorf("%s: status %d, want 401", name, st)
		}
	}
}

func TestCrossOriginWritesBlocked(t *testing.T) {
	w := newWorld(t)
	c := browser(t)
	w.homeIdP.LoginAs(map[string]any{"sub": "a1", "email": "admin@harmonyx.co", "email_verified": true, "groups": []string{"keel-admins"}})
	w.login(c, "harmonyx")
	st, _ := call(t, c, "POST", w.keel+"/v1/tenants", map[string]any{"slug": "csrf", "name": "x"}, "Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site")
	if st != 403 {
		t.Fatalf("cross-site POST with session cookie: %d, want 403", st)
	}
}
