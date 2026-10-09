package api_test

import (
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/auth"
)

var clientRoles = map[string]map[string]any{
	"tencent": {"role_arn": "qcs::cam::uin/100000000001:roleName/keel-readonly"},
	"aws":     {"role_arn": "arn:aws:iam::123456789012:role/keel/keel-readonly"},
	"alibaba": {"role_arn": "acs:ram::1234567890123456:role/keel-readonly"},
	"azure":   {"tenant_id": "6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f", "client_id": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"},
	"gcp":     {"workload_identity_provider": "projects/123456789/locations/global/workloadIdentityPools/keel-pool/providers/keel-oidc", "service_account": "keel-readonly@client-proj.iam.gserviceaccount.com"},
}

func TestCloudAccountOwnership(t *testing.T) {
	c, home := setup(t)
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	accounts := "/v1/tenants/" + tat + "/cloud-accounts"

	st, body := inTAT.do("POST", accounts, map[string]any{"provider": "tencent", "external_id": "200000000001", "name": "ours"})
	mustStatus(t, st, 201, body)
	if body["ownership"] != "platform" || body["read_only_role"] != nil {
		t.Errorf("default ownership: %v", body)
	}
	ours := body["id"].(string)

	for provider, role := range clientRoles {
		st, body := inTAT.do("POST", accounts, map[string]any{"provider": provider, "external_id": "client-" + provider, "name": "theirs-" + provider,
			"ownership": "client", "read_only_role": role})
		mustStatus(t, st, 201, body)
		got, _ := body["read_only_role"].(map[string]any)
		if body["ownership"] != "client" || len(got) != len(role) {
			t.Errorf("%s: client-owned account = %v, want role %v", provider, body, role)
		}
		for k, v := range role {
			if got[k] != v {
				t.Errorf("%s: read_only_role.%s = %v, want %v", provider, k, got[k], v)
			}
		}
	}
	st, body = inTAT.do("GET", accounts, nil)
	mustStatus(t, st, 200, body)
	owned := map[string]int{}
	for _, a := range items(t, body) {
		owned[a["ownership"].(string)]++
	}
	if owned["platform"] != 1 || owned["client"] != len(clientRoles) {
		t.Errorf("listed ownership = %v", owned)
	}

	invalid := map[string]map[string]any{
		"client without a role":      {"provider": "aws", "ownership": "client"},
		"platform with a role":       {"provider": "aws", "ownership": "platform", "read_only_role": clientRoles["aws"]},
		"unknown ownership":          {"provider": "aws", "ownership": "shared"},
		"another provider's fields":  {"provider": "aws", "ownership": "client", "read_only_role": clientRoles["azure"]},
		"extra field":                {"provider": "aws", "ownership": "client", "read_only_role": map[string]any{"role_arn": clientRoles["aws"]["role_arn"], "client_id": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"}},
		"a secret instead of a role": {"provider": "aws", "ownership": "client", "read_only_role": map[string]any{"role_arn": clientRoles["aws"]["role_arn"], "secret_access_key": "x"}},
		"malformed aws arn":          {"provider": "aws", "ownership": "client", "read_only_role": map[string]any{"role_arn": "arn:aws:iam::12:role/x"}},
		"tencent arn on aws":         {"provider": "aws", "ownership": "client", "read_only_role": clientRoles["tencent"]},
		"azure ids not uuids":        {"provider": "azure", "ownership": "client", "read_only_role": map[string]any{"tenant_id": "contoso", "client_id": "app"}},
		"gcp without sa":             {"provider": "gcp", "ownership": "client", "read_only_role": map[string]any{"workload_identity_provider": clientRoles["gcp"]["workload_identity_provider"]}},
	}
	for name, in := range invalid {
		in["external_id"], in["name"] = "bad-"+strings.ReplaceAll(name, " ", "-"), "bad"
		if st, body := inTAT.do("POST", accounts, in); st != 400 {
			t.Errorf("create %s: status %d body %v, want 400", name, st, body)
		}
	}

	st, body = inTAT.do("PATCH", accounts+"/"+ours, map[string]any{"ownership": "client", "why": "TAT owns this organisation"})
	mustStatus(t, st, 400, body)
	st, body = inTAT.do("PATCH", accounts+"/"+ours, map[string]any{"ownership": "client", "read_only_role": clientRoles["aws"], "why": "TAT owns this organisation"})
	mustStatus(t, st, 400, body)
	st, body = inTAT.do("PATCH", accounts+"/"+ours, map[string]any{"ownership": "client", "read_only_role": clientRoles["tencent"], "why": "TAT owns this organisation"})
	mustStatus(t, st, 200, body)
	if body["ownership"] != "client" || body["read_only_role"].(map[string]any)["role_arn"] != clientRoles["tencent"]["role_arn"] {
		t.Errorf("after PATCH to client: %v", body)
	}
	st, body = inTAT.do("PATCH", accounts+"/"+ours, map[string]any{"ownership": "platform", "why": "moved into our organisation"})
	mustStatus(t, st, 200, body)
	if body["ownership"] != "platform" || body["read_only_role"] != nil {
		t.Errorf("after PATCH to platform: %v", body)
	}
	st, body = inTAT.do("PATCH", accounts+"/00000000-0000-4000-8000-000000000000", map[string]any{"ownership": "platform", "why": "x"})
	mustStatus(t, st, 404, body)

	teamLead := c.as(auth.Principal{Subject: "user:lead@tat.go.th", Kind: auth.KindHuman, TenantID: tat,
		Bindings: []auth.Binding{{Role: auth.RoleTeamLead, TenantID: tat}, {Role: auth.RoleTenantViewer, TenantID: tat}}})
	st, body = teamLead.do("PATCH", accounts+"/"+ours, map[string]any{"ownership": "client", "read_only_role": clientRoles["tencent"], "why": "x"})
	mustStatus(t, st, 403, body)
	st, body = teamLead.do("POST", accounts, map[string]any{"provider": "aws", "external_id": "lead-1", "name": "x", "ownership": "client", "read_only_role": clientRoles["aws"]})
	mustStatus(t, st, 403, body)

	st, body = inTAT.do("GET", "/v1/tenants/"+tat+"/activities?subject=cloud_account/"+ours, nil)
	mustStatus(t, st, 200, body)
	var changes []string
	denied := 0
	for _, a := range items(t, body) {
		switch a["type"] {
		case "keel.cloud_account.ownership_changed":
			changes = append(changes, a["event"].(map[string]any)["data"].(map[string]any)["status_detail"].(string))
		case "keel.cloud_account.update.denied":
			denied++
		}
	}
	if len(changes) != 2 || !strings.HasPrefix(changes[0], "ownership client → platform") || !strings.HasPrefix(changes[1], "ownership platform → client") {
		t.Errorf("ownership Activities = %q, want client → platform then platform → client", changes)
	}
	if denied != 1 {
		t.Errorf("denied ownership changes recorded = %d, want 1", denied)
	}
}
