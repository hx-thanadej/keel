package api_test

import (
	"regexp"
	"testing"

	"github.com/hx-thanadej/keel/internal/auth"
)

// TestClientPayer: only a client-owned Tencent Cloud Account can be marked
// as its client's payer, delivery fields are checked, and an empty bucket
// records a payer whose delivery is not set up yet.
func TestClientPayer(t *testing.T) {
	c, home := setup(t)
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	accounts := "/v1/tenants/" + tat + "/cloud-accounts"
	create := func(provider, ext, ownership string) string {
		in := map[string]any{"provider": provider, "external_id": ext, "name": ext, "ownership": ownership}
		if ownership == "client" {
			in["read_only_role"] = clientRoles[provider]
		}
		st, body := inTAT.do("POST", accounts, in)
		mustStatus(t, st, 201, body)
		return body["id"].(string)
	}
	payer := create("tencent", "100000000001", "client")
	ours := create("tencent", "200000000001", "platform")
	aws := create("aws", "123456789012", "client")

	st, body := inTAT.do("PUT", accounts+"/"+payer+"/client-payer", map[string]any{"why": "TAT pays its own bill"})
	mustStatus(t, st, 200, body)
	if body["bucket"] != "" || body["mode"] != "cumulative" || body["region"] != "ap-bangkok" {
		t.Errorf("payer without delivery = %v", body)
	}
	ext, _ := body["external_id"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(ext) {
		t.Errorf("first PUT external_id %q, want a fresh 32-hex id for the client's trust policy", ext)
	}
	st, body = inTAT.do("PUT", accounts+"/"+payer+"/client-payer", map[string]any{"bucket": "tat-bills-1250000001", "prefix": "focus/", "region": "ap-singapore", "mode": "per-day", "why": "delivery set up"})
	mustStatus(t, st, 200, body)
	if body["bucket"] != "tat-bills-1250000001" || body["prefix"] != "focus/" || body["region"] != "ap-singapore" || body["mode"] != "per-day" {
		t.Errorf("payer with delivery = %v", body)
	}
	if _, shown := body["external_id"]; shown {
		t.Errorf("external_id shown again on update: %v", body)
	}
	other := create("tencent", "100000000002", "client")
	st, body = inTAT.do("PUT", accounts+"/"+other+"/client-payer", map[string]any{"why": "second payer"})
	mustStatus(t, st, 200, body)
	if body["external_id"] == ext {
		t.Errorf("two payers share external_id %s", ext)
	}

	for name, tc := range map[string]struct {
		account string
		in      map[string]any
	}{
		"platform-owned account": {ours, map[string]any{}},
		"aws account":            {aws, map[string]any{}},
		"bucket without appid":   {payer, map[string]any{"bucket": "tat-bills"}},
		"unknown mode":           {payer, map[string]any{"mode": "hourly"}},
		"malformed region":       {payer, map[string]any{"region": "Bangkok"}},
	} {
		tc.in["why"] = "x"
		if st, body := inTAT.do("PUT", accounts+"/"+tc.account+"/client-payer", tc.in); st != 400 {
			t.Errorf("%s: status %d body %v, want 400", name, st, body)
		}
	}
}
