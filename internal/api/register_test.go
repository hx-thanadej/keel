package api_test

import (
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/auth"
)

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
	c, home := setup(t)
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
	if activities()["keel.cloud_account.register.denied"] != 2 {
		t.Errorf("denials not logged: %v", activities())
	}

	st, body = inTAT.do("POST", path, map[string]any{"team_id": team, "accounts": []any{}})
	mustStatus(t, st, 400, body)
}
