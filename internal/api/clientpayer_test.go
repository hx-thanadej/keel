package api_test

import (
	"regexp"
	"testing"

	"github.com/hx-thanadej/keel/internal/auth"
)

// TestClientPayer: only a client-owned Tencent or AWS Cloud Account can be
// marked as its client's payer, delivery fields are checked per provider,
// and an empty bucket records a payer whose delivery is not set up yet.
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
	azure := create("azure", "00000000-0000-0000-0000-000000000001", "client")

	st, body := inTAT.do("PUT", accounts+"/"+payer+"/client-payer", map[string]any{"why": "TAT pays its own bill"})
	mustStatus(t, st, 200, body)
	if body["bucket"] != "" || body["mode"] != "cumulative" || body["region"] != "ap-bangkok" {
		t.Errorf("payer without delivery = %v", body)
	}
	ext, _ := body["role_external_id"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(ext) {
		t.Errorf("first PUT role_external_id %q, want a fresh 32-hex id for the client's trust policy", ext)
	}
	st, body = inTAT.do("PUT", accounts+"/"+payer+"/client-payer", map[string]any{"bucket": "tat-bills-1250000001", "prefix": "focus/", "region": "ap-singapore", "mode": "per-day", "why": "delivery set up"})
	mustStatus(t, st, 200, body)
	if body["bucket"] != "tat-bills-1250000001" || body["prefix"] != "focus/" || body["region"] != "ap-singapore" || body["mode"] != "per-day" {
		t.Errorf("payer with delivery = %v", body)
	}
	if _, shown := body["role_external_id"]; shown {
		t.Errorf("role_external_id shown again on update: %v", body)
	}
	other := create("tencent", "100000000002", "client")
	st, body = inTAT.do("PUT", accounts+"/"+other+"/client-payer", map[string]any{"why": "second payer"})
	mustStatus(t, st, 200, body)
	if body["role_external_id"] == ext {
		t.Errorf("two payers share role_external_id %s", ext)
	}

	st, body = inTAT.do("PUT", accounts+"/"+aws+"/client-payer", map[string]any{"why": "TAT pays its own AWS bill"})
	mustStatus(t, st, 200, body)
	if body["bucket"] != "" || body["mode"] != "export-folder" || body["region"] != "us-east-1" || body["role_external_id"] == ext {
		t.Errorf("aws payer without delivery = %v, want export-folder in us-east-1 with its own ExternalId", body)
	}
	st, body = inTAT.do("PUT", accounts+"/"+aws+"/client-payer", map[string]any{"bucket": "tat-cur.exports", "prefix": "focus", "region": "us-gov-west-1",
		"kms_key_arn": "arn:aws-us-gov:kms:us-gov-west-1:100000000003:key/1234abcd-12ab-34cd-56ef-1234567890ab", "why": "export set up"})
	mustStatus(t, st, 200, body)
	if body["bucket"] != "tat-cur.exports" || body["region"] != "us-gov-west-1" || body["mode"] != "export-folder" || body["kms_key_arn"] != "arn:aws-us-gov:kms:us-gov-west-1:100000000003:key/1234abcd-12ab-34cd-56ef-1234567890ab" {
		t.Errorf("aws payer with delivery = %v", body)
	}

	for name, tc := range map[string]struct {
		account string
		in      map[string]any
	}{
		"platform-owned account":  {ours, map[string]any{}},
		"azure account":           {azure, map[string]any{}},
		"aws with a tencent mode": {aws, map[string]any{"mode": "cumulative"}},
		"aws bucket uppercase":    {aws, map[string]any{"bucket": "TAT-Bills"}},
		"bucket without appid":    {payer, map[string]any{"bucket": "tat-bills"}},
		"unknown mode":            {payer, map[string]any{"mode": "hourly"}},
		"malformed region":        {payer, map[string]any{"region": "Bangkok"}},
		"tencent with a kms key":  {payer, map[string]any{"kms_key_arn": "arn:aws:kms:ap-bangkok:100000000003:key/1234abcd-12ab-34cd-56ef-1234567890ab"}},
		"aws kms key elsewhere":   {aws, map[string]any{"bucket": "tat-cur.exports", "kms_key_arn": "arn:aws:kms:us-west-2:100000000003:key/1234abcd-12ab-34cd-56ef-1234567890ab"}},
		"aws wildcard prefix":     {aws, map[string]any{"bucket": "tat-cur.exports", "prefix": "focus/*"}},
	} {
		tc.in["why"] = "x"
		if st, body := inTAT.do("PUT", accounts+"/"+tc.account+"/client-payer", tc.in); st != 400 {
			t.Errorf("%s: status %d body %v, want 400", name, st, body)
		}
	}
}

// TestRotateAndUnarchiveRoutes: a platform admin rotates a payer's
// ExternalId over HTTP and sees the new id once; a viewer and another
// Tenant's admin get 403. An archived payer is re-onboarded by unarchive.
func TestRotateAndUnarchiveRoutes(t *testing.T) {
	c, home := setup(t)
	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	_, body = admin.do("POST", "/v1/tenants", map[string]any{"slug": "other", "name": "Other"})
	other := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	accounts := "/v1/tenants/" + tat + "/cloud-accounts"
	st, body := inTAT.do("POST", accounts, map[string]any{"provider": "tencent", "external_id": "100000000001", "name": "payer", "ownership": "client", "read_only_role": clientRoles["tencent"]})
	mustStatus(t, st, 201, body)
	payer := accounts + "/" + body["id"].(string)
	st, body = inTAT.do("PUT", payer+"/client-payer", map[string]any{"why": "pays its own bill"})
	mustStatus(t, st, 200, body)
	first := body["role_external_id"]

	st, body = inTAT.do("POST", payer+"/client-payer/rotate-external-id", map[string]any{"why": "id lost"})
	mustStatus(t, st, 200, body)
	ext, _ := body["role_external_id"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(ext) || ext == first {
		t.Errorf("rotated role_external_id %q (first %v), want a new 32-hex id", ext, first)
	}
	viewer := c.as(auth.Principal{Subject: "user:v@tat", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	otherAdmin := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: other}))
	for name, who := range map[string]client{"viewer": viewer, "other Tenant's admin": otherAdmin} {
		for _, path := range []string{payer + "/client-payer/rotate-external-id", payer + "/unarchive"} {
			if st, body := who.do("POST", path, map[string]any{"why": "x"}); st != 403 {
				t.Errorf("%s POST %s = %d %v, want 403", name, path, st, body)
			}
		}
	}

	st, body = inTAT.do("POST", payer+"/archive", map[string]any{"why": "client left"})
	mustStatus(t, st, 200, body)
	st, body = inTAT.do("POST", payer+"/unarchive", map[string]any{"why": "client is back"})
	mustStatus(t, st, 200, body)
	if _, archived := body["archived_at"]; archived || body["ownership"] != "client" {
		t.Errorf("unarchived payer = %v", body)
	}
}
