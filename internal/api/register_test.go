package api_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/discovery"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// discoveredSetup serves the API with a fake Tencent organisation holding ids,
// already discovered into the home Tenant.
func discoveredSetup(t *testing.T, ids ...string) (client, string) {
	t.Helper()
	s := storetest.New(t)
	az, err := authz.New()
	if err != nil {
		t.Fatal(err)
	}
	home, err := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	if err != nil {
		t.Fatal(err)
	}
	org := fakeOrg{}
	for _, id := range ids {
		org = append(org, discovery.Account{Provider: "tencent", ExternalID: id, Name: "acct-" + id})
	}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az), Discovery: map[string]discovery.Source{"tencent": org}}))
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}
	st, body := c.as(homeAdmin(home)).do("POST", "/v1/tenants/"+home+"/discoveries/tencent", map[string]any{})
	mustStatus(t, st, 200, body)
	return c, home
}

func registerBody(team string, accounts ...map[string]any) map[string]any {
	return map[string]any{"team_id": team, "why": "found by discovery", "accounts": accounts}
}

func discovered(id, name, project, env string) map[string]any {
	return map[string]any{"provider": "tencent", "external_id": id, "name": name, "project": project, "environment": env}
}

func outcomes(t *testing.T, body map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, o := range items(t, body) {
		out[o["external_id"].(string)] = o
	}
	return out
}

func TestRegisterDiscoveredAccounts(t *testing.T) {
	c, home := discoveredSetup(t, "200046202634", "200048351622", "200045645249", "200099999999", "200088888888", "200077777777", "200066666666", "200055555555", "1", "2", "3")
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	team := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants/"+home+"/teams", map[string]any{"slug": "platform", "name": "Platform"})
	homeTeam := body["id"].(string)
	// A same-slug Project in the home Tenant must not be reused for TAT.
	st, body := admin.do("POST", "/v1/tenants/"+home+"/projects", map[string]any{"team_id": homeTeam, "slug": "tat-crm", "name": "decoy"})
	mustStatus(t, st, 201, body)

	path := "/v1/tenants/" + tat + "/cloud-accounts/register"
	st, body = inTAT.do("POST", path, registerBody(team,
		discovered("200046202634", "tat-crm-dev", "tat-crm", "dev"),
		discovered("200048351622", "tat-crm-prod", "tat-crm", "prod"),
		discovered("200045645249", "payer", "", ""),
	))
	mustStatus(t, st, 200, body)
	got := outcomes(t, body)
	for id, o := range got {
		if o["status"] != "registered" {
			t.Fatalf("%s: %v", id, o)
		}
	}
	if got["200046202634"]["project_created"] != true || got["200046202634"]["environment_created"] != true {
		t.Errorf("first account should create project and environment: %v", got["200046202634"])
	}
	if got["200048351622"]["project_created"] != false || got["200048351622"]["environment_created"] != true {
		t.Errorf("second account reuses the project: %v", got["200048351622"])
	}
	if acct := got["200045645249"]["cloud_account"].(map[string]any); acct["environment_id"] != nil || acct["ownership"] != "platform" {
		t.Errorf("account without a suggestion registers with no environment: %v", acct)
	}

	_, body = inTAT.do("GET", "/v1/tenants/"+tat+"/projects", nil)
	projects := items(t, body)
	if len(projects) != 1 || projects[0]["slug"] != "tat-crm" || projects[0]["team_id"] != team {
		t.Fatalf("TAT projects = %v", projects)
	}
	_, body = admin.do("GET", "/v1/tenants/"+home+"/projects", nil)
	if p := items(t, body); len(p) != 1 || p[0]["name"] != "decoy" {
		t.Errorf("home projects changed: %v", p)
	}

	activities := func() map[string]int {
		_, body := inTAT.do("GET", "/v1/tenants/"+tat+"/activities?limit=200", nil)
		n := map[string]int{}
		for _, a := range items(t, body) {
			n[a["type"].(string)]++
		}
		return n
	}
	before := activities()
	if before["keel.project.created"] != 1 || before["keel.environment.created"] != 2 || before["keel.cloud_account.created"] != 3 {
		t.Errorf("activities = %v", before)
	}

	// Re-registering converges: nothing new is created or logged.
	st, body = inTAT.do("POST", path, registerBody(team, discovered("200046202634", "tat-crm-dev", "tat-crm", "dev"), discovered("200045645249", "payer", "", "")))
	mustStatus(t, st, 200, body)
	for id, o := range outcomes(t, body) {
		if o["status"] != "already_registered" {
			t.Errorf("re-register %s: %v", id, o)
		}
	}
	if after := activities(); after["keel.cloud_account.created"] != 3 || after["keel.environment.created"] != 2 {
		t.Errorf("re-register logged activities: %v", after)
	}

	// One account per provider per Environment: the second fails alone and
	// rolls back, the other in the batch still registers.
	st, body = inTAT.do("POST", path, registerBody(team,
		discovered("200099999999", "tat-crm-dev-2", "tat-crm", "dev"),
		discovered("200088888888", "tat-web-uat", "tat-web", "uat"),
	))
	mustStatus(t, st, 200, body)
	got = outcomes(t, body)
	if o := got["200099999999"]; o["status"] != "failed" || !strings.Contains(o["error"].(string), "cloud_accounts_environment_id_provider_key") {
		t.Errorf("env conflict: %v", o)
	}
	if got["200088888888"]["status"] != "registered" {
		t.Errorf("batch neighbour: %v", got["200088888888"])
	}

	// The same account under another Environment is a conflict, not a move.
	st, body = inTAT.do("POST", path, registerBody(team, discovered("200046202634", "tat-crm-dev", "tat-crm", "prod")))
	mustStatus(t, st, 200, body)
	if o := outcomes(t, body)["200046202634"]; o["status"] != "failed" || !strings.Contains(o["error"].(string), "already registered") {
		t.Errorf("moved account: %v", o)
	}

	// An account registered in another Tenant conflicts on its global key.
	st, body = admin.do("POST", "/v1/tenants/"+home+"/cloud-accounts/register", registerBody(homeTeam, discovered("200048351622", "tat-crm-prod", "", "")))
	mustStatus(t, st, 200, body)
	if o := outcomes(t, body)["200048351622"]; o["status"] != "failed" || !strings.Contains(o["error"].(string), "cloud_accounts_provider_external_id_key") {
		t.Errorf("cross-tenant duplicate: %v", o)
	}

	// Validation is per account and in words.
	st, body = inTAT.do("POST", path, registerBody(team,
		discovered("1", "half", "tat-crm", ""),
		discovered("2", "Bad Slug", "Bad Slug", "dev"),
		map[string]any{"provider": "tencent", "external_id": "3", "name": "client", "ownership": "client"},
	))
	mustStatus(t, st, 200, body)
	got = outcomes(t, body)
	for id, want := range map[string]string{"1": "both a project and an environment", "2": "lowercase letters", "3": "read_only_role"} {
		if o := got[id]; o["status"] != "failed" || !strings.Contains(o["error"].(string), want) {
			t.Errorf("%s: want %q, got %v", id, want, o)
		}
	}

	// RLS: a Team from another Tenant cannot own a new Project here.
	st, body = inTAT.do("POST", path, registerBody(homeTeam, discovered("200077777777", "tat-erp-dev", "tat-erp", "dev")))
	mustStatus(t, st, 200, body)
	if o := outcomes(t, body)["200077777777"]; o["status"] != "failed" || !strings.Contains(o["error"].(string), "team") {
		t.Errorf("foreign team: %v", o)
	}

	// A new Project needs a Team; an existing one does not.
	st, body = inTAT.do("POST", path, registerBody("", discovered("200066666666", "tat-crm-qa", "tat-crm", "qa")))
	mustStatus(t, st, 200, body)
	if o := outcomes(t, body)["200066666666"]; o["status"] != "registered" {
		t.Errorf("existing project without team: %v", o)
	}

	// Authz: only a platform admin of the target Tenant registers; denial is logged.
	lead := c.as(auth.Principal{Subject: "user:lead@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true,
		Bindings: []auth.Binding{{Role: auth.RoleTeamLead, TenantID: tat}}})
	st, body = lead.do("POST", path, registerBody(team, discovered("200055555555", "tat-crm-stg", "tat-crm", "stg")))
	mustStatus(t, st, 403, body)
	st, body = admin.do("POST", path, registerBody(team, discovered("200055555555", "tat-crm-stg", "tat-crm", "stg")))
	mustStatus(t, st, 403, body)
	denials := 0
	for typ, n := range activities() {
		if strings.HasSuffix(typ, ".denied") {
			denials += n
		}
	}
	if denials != 2 {
		t.Errorf("denials not logged: %v", activities())
	}

	st, body = inTAT.do("POST", path, map[string]any{"team_id": team, "accounts": []any{}})
	mustStatus(t, st, 400, body)
}

// A Team-scoped admin may not use registration to reach past its Teams: each
// step is authorised as its own endpoint would authorise it, all before any
// write.
func TestRegisterAuthorizesEachStepLikeItsEndpoint(t *testing.T) {
	c, home := discoveredSetup(t, "200011111111", "200022222222", "200033333333")
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	crm := body["id"].(string)
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/teams", map[string]any{"slug": "other", "name": "Other"})
	other := body["id"].(string)
	st, body := inTAT.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": other, "slug": "other-proj", "name": "Other"})
	mustStatus(t, st, 201, body)
	otherProj := body["id"].(string)

	crmAdmin := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat, TeamIDs: []string{crm}}))
	path := "/v1/tenants/" + tat + "/cloud-accounts/register"
	envsOf := func() int {
		_, body := inTAT.do("GET", "/v1/tenants/"+tat+"/projects/"+otherProj+"/environments", nil)
		return len(items(t, body))
	}
	accounts := func() int {
		_, body := inTAT.do("GET", "/v1/tenants/"+tat+"/cloud-accounts", nil)
		return len(items(t, body))
	}

	// The per-object endpoints deny this principal, so registration must too.
	st, body = crmAdmin.do("POST", "/v1/tenants/"+tat+"/projects/"+otherProj+"/environments", map[string]any{"name": "sneaky"})
	mustStatus(t, st, 403, body)
	st, body = crmAdmin.do("POST", path, registerBody(crm, discovered("200011111111", "sneaky", "other-proj", "sneaky")))
	mustStatus(t, st, 403, body)
	st, body = crmAdmin.do("POST", path, registerBody(crm, discovered("200022222222", "loose", "", "")))
	mustStatus(t, st, 403, body)
	// One denied account denies the batch: its allowed neighbour is not written.
	st, body = crmAdmin.do("POST", path, registerBody(crm, discovered("200033333333", "mine", "crm-new", "dev"), discovered("200011111111", "sneaky", "other-proj", "sneaky")))
	mustStatus(t, st, 403, body)
	if n, a := envsOf(), accounts(); n != 0 || a != 0 {
		t.Fatalf("denied registration wrote %d environments and %d accounts", n, a)
	}
	_, body = inTAT.do("GET", "/v1/tenants/"+tat+"/projects", nil)
	if p := items(t, body); len(p) != 1 {
		t.Fatalf("denied registration created projects: %v", p)
	}

	// A Tenant-wide admin registers into another Team's existing Project; the
	// request's team only owns new Projects.
	st, body = inTAT.do("POST", path, registerBody(crm, discovered("200011111111", "other-dev", "other-proj", "dev"), discovered("200022222222", "crm-dev", "crm-app", "dev")))
	mustStatus(t, st, 200, body)
	got := outcomes(t, body)
	if got["200011111111"]["status"] != "registered" || got["200011111111"]["project_created"] != false {
		t.Errorf("existing project: %v", got["200011111111"])
	}
	if got["200022222222"]["status"] != "registered" || got["200022222222"]["project_created"] != true {
		t.Errorf("new project: %v", got["200022222222"])
	}
	_, body = inTAT.do("GET", "/v1/tenants/"+tat+"/projects", nil)
	for _, p := range items(t, body) {
		want := map[string]string{"other-proj": other, "crm-app": crm}[p["slug"].(string)]
		if p["team_id"] != want {
			t.Errorf("project %v owned by %v, want %s", p["slug"], p["team_id"], want)
		}
	}
}

// Registration is for accounts discovery found; any other id goes through
// POST /cloud-accounts.
func TestRegisterOnlyDiscoveredAccounts(t *testing.T) {
	c, home := discoveredSetup(t, "200011111111")
	admin := c.as(homeAdmin(home))
	path := "/v1/tenants/" + home + "/cloud-accounts/register"
	st, body := admin.do("POST", path, registerBody("", discovered("200011111111", "found", "", ""), discovered("999999999999", "invented", "", ""),
		map[string]any{"provider": "aws", "external_id": "200011111111", "name": "wrong provider"}))
	mustStatus(t, st, 200, body)
	got := map[string]map[string]any{}
	for _, o := range items(t, body) {
		got[o["provider"].(string)+"/"+o["external_id"].(string)] = o
	}
	if got["tencent/200011111111"]["status"] != "registered" {
		t.Errorf("discovered: %v", got["tencent/200011111111"])
	}
	for _, k := range []string{"tencent/999999999999", "aws/200011111111"} {
		if o := got[k]; o["status"] != "failed" || !strings.Contains(o["error"].(string), "not found by discovery") {
			t.Errorf("%s: %v", k, o)
		}
	}
	_, body = admin.do("GET", "/v1/tenants/"+home+"/cloud-accounts", nil)
	if a := items(t, body); len(a) != 1 {
		t.Errorf("cloud accounts = %v", a)
	}
}
