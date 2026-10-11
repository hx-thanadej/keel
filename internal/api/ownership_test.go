package api_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/access"
	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
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

// directory is an Identity Center that knows every user. beforeAssign, when
// set, runs inside Assign, while the grant's cloud write is in flight.
type directory struct {
	mu           sync.Mutex
	assigned     map[string]bool
	beforeAssign func()
}

func (*directory) EnsureRoleConfiguration(context.Context, string, string, string, int) (string, error) {
	return "rc-1", nil
}
func (*directory) UserID(context.Context, string) (string, bool, error) { return "u-1", true, nil }
func (d *directory) Assign(_ context.Context, cfg string, account int64, user string) error {
	if d.beforeAssign != nil {
		d.beforeAssign()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.assigned[fmt.Sprint(cfg, account, user)] = true
	return nil
}
func (d *directory) Unassign(_ context.Context, cfg string, account int64, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.assigned, fmt.Sprint(cfg, account, user))
	return nil
}
func (*directory) Assignments(context.Context, int64) ([]access.Assignment, error) { return nil, nil }

func (d *directory) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.assigned)
}

// grantFixture is a TAT tenant with one platform-owned Tencent Cloud Account
// and a read-only Access Role in its Environment.
type grantFixture struct {
	store              *store.Store
	inTAT, eng         client
	tat, account, role string
	accountID          string
	dir                *directory
}

func (f grantFixture) request() (int, map[string]any) {
	return f.eng.do("POST", "/v1/tenants/"+f.tat+"/access/grants", map[string]any{"role_id": f.role, "hours": 1, "reason": "look at failing pods"})
}

func (f grantFixture) toClient() (int, map[string]any) {
	return f.inTAT.do("PATCH", f.account, map[string]any{"ownership": "client", "read_only_role": clientRoles["tencent"], "why": "TAT owns this organisation"})
}

func newGrantFixture(t *testing.T) grantFixture {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	dir := &directory{assigned: map[string]bool{}}
	grants, err := access.New(s, dir)
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := flowtest.Client(t, s, grants.Register)
	grants.SetClient(rc)
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az), Access: &api.AccessDeps{Authz: az, Service: grants}}))
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}

	admin := c.as(homeAdmin(home))
	_, body := admin.do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/teams", map[string]any{"slug": "crm", "name": "CRM"})
	team := body["id"].(string)
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects", map[string]any{"team_id": team, "slug": "tat-crm", "name": "TAT CRM"})
	project := body["id"].(string)
	_, body = inTAT.do("POST", "/v1/tenants/"+tat+"/projects/"+project+"/environments", map[string]any{"name": "dev"})
	env := body["id"].(string)
	st, body := inTAT.do("POST", "/v1/tenants/"+tat+"/cloud-accounts", map[string]any{"environment_id": env, "provider": "tencent", "external_id": "200000000001", "name": "ours"})
	mustStatus(t, st, 201, body)
	accountID := body["id"].(string)
	st, body = inTAT.do("POST", "/v1/tenants/"+tat+"/access/roles", map[string]any{"environment_id": env, "team_id": team, "template": "read-only"})
	mustStatus(t, st, 200, body)
	eng := c.as(auth.Principal{Subject: "user:eng@harmonyx.co", Kind: auth.KindHuman, TenantID: home, Home: true,
		Bindings: []auth.Binding{{Role: auth.RoleEngineer, TenantID: tat}}})
	return grantFixture{store: s, inTAT: inTAT, eng: eng, tat: tat, account: "/v1/tenants/" + tat + "/cloud-accounts/" + accountID,
		role: body["id"].(string), accountID: accountID, dir: dir}
}

// TestClientOwnedAccessGrants: an account with an active Access Grant cannot
// become client-owned until the grant ends, so Keel removes the assignment
// while it still may; once client-owned, no grant activates there (ADR-0018).
func TestClientOwnedAccessGrants(t *testing.T) {
	f := newGrantFixture(t)
	st, body := f.request()
	mustStatus(t, st, 200, body)
	if body["state"] != "active" || f.dir.count() != 1 {
		t.Fatalf("grant on a platform-owned account: %v, assigned %v", body, f.dir.assigned)
	}
	grant := body["id"].(string)

	st, body = f.toClient()
	mustStatus(t, st, 409, body)
	if msg, _ := body["error"].(string); !strings.Contains(msg, "access_grant/"+grant) || !strings.Contains(msg, "user:eng@harmonyx.co") {
		t.Errorf("flip with an active grant: %v, want the grant listed", body)
	}
	st, body = f.inTAT.do("POST", "/v1/tenants/"+f.tat+"/access/grants/"+grant+"/revoke", map[string]any{"reason": "handing the account to TAT"})
	mustStatus(t, st, 200, body)
	if body["state"] != "revoked" || f.dir.count() != 0 {
		t.Fatalf("revoke before the flip: %v, assigned %v", body, f.dir.assigned)
	}
	st, body = f.toClient()
	mustStatus(t, st, 200, body)

	st, body = f.request()
	mustStatus(t, st, 409, body)
	if msg, _ := body["error"].(string); !strings.Contains(msg, "client-owned") || !strings.Contains(msg, "ADR-0018") {
		t.Errorf("grant on a client-owned account: %v", body)
	}
	if f.dir.count() != 0 {
		t.Errorf("client-owned account assigned: %v", f.dir.assigned)
	}
}

// TestOwnershipSwitchDuringGrantActivation: a switch to client-owned and a
// grant's Identity Center assignment serialize on the account row, so Keel
// never assigns a role in an account that is client-owned (ADR-0018).
func TestOwnershipSwitchDuringGrantActivation(t *testing.T) {
	t.Run("switch while the assignment is in flight", func(t *testing.T) {
		f := newGrantFixture(t)
		var switched int
		f.dir.beforeAssign = func() { switched, _ = f.toClient() }
		st, body := f.request()
		mustStatus(t, st, 200, body)
		if switched != 409 {
			t.Errorf("switch during activation: status %d, want 409 while the grant is requested", switched)
		}
		if body["state"] != "active" {
			t.Errorf("grant = %v, want active on the still platform-owned account", body)
		}
		st, body = f.inTAT.do("GET", "/v1/tenants/"+f.tat+"/cloud-accounts", nil)
		mustStatus(t, st, 200, body)
		if a := items(t, body)[0]; a["ownership"] != "platform" {
			t.Errorf("ownership = %v, want platform: the grant is still active there", a["ownership"])
		}
	})

	t.Run("activation while the switch holds the account", func(t *testing.T) {
		f := newGrantFixture(t)
		locked, release, switchDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			switchDone <- f.store.InTenant(context.Background(), f.tat, func(tx pgx.Tx) error {
				if _, err := tx.Exec(context.Background(), `SELECT 1 FROM cloud_accounts WHERE id = $1 FOR UPDATE`, f.accountID); err != nil {
					return err
				}
				if _, err := tx.Exec(context.Background(), `UPDATE cloud_accounts SET ownership = 'client', read_only_role = $2 WHERE id = $1`, f.accountID, clientRoles["tencent"]); err != nil {
					return err
				}
				close(locked)
				<-release
				return nil
			})
		}()
		<-locked
		type result struct {
			st   int
			body map[string]any
		}
		granted := make(chan result, 1)
		go func() {
			st, body := f.request()
			granted <- result{st, body}
		}()
		var r result
		select {
		case r = <-granted:
			t.Errorf("grant finished while the switch held the account: status %d, assigned %d", r.st, f.dir.count())
			close(release)
		case <-time.After(300 * time.Millisecond):
			close(release)
			r = <-granted
		}
		if err := <-switchDone; err != nil {
			t.Fatal(err)
		}
		if r.st != 409 || f.dir.count() != 0 {
			t.Errorf("grant after the switch committed: status %d %v, assigned %d; want 409 and nothing assigned", r.st, r.body, f.dir.count())
		}
	})
}

func TestRoleHealthRouteForTenantMembers(t *testing.T) {
	c, home := setup(t)
	_, body := c.as(homeAdmin(home)).do("POST", "/v1/tenants", map[string]any{"slug": "tat", "name": "TAT"})
	tat := body["id"].(string)
	inTAT := c.as(homeAdmin(home, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tat}))
	accounts := "/v1/tenants/" + tat + "/cloud-accounts"
	st, body := inTAT.do("POST", accounts, map[string]any{"provider": "tencent", "external_id": "200000000001", "name": "theirs", "ownership": "client", "read_only_role": clientRoles["tencent"]})
	mustStatus(t, st, 201, body)
	theirs := body["id"].(string)
	st, body = inTAT.do("POST", accounts, map[string]any{"provider": "tencent", "external_id": "200000000002", "name": "ours"})
	mustStatus(t, st, 201, body)

	viewer := c.as(auth.Principal{Subject: "user:somchai@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	st, body = viewer.do("GET", accounts+"/role-health", nil)
	mustStatus(t, st, 200, body)
	got := items(t, body)
	if len(got) != 1 {
		t.Fatalf("viewer role health = %v, want one client-owned account", got)
	}
	if got[0]["cloud_account_id"] != theirs || got[0]["client_payer"] != false || got[0]["last_assume_at"] != nil || got[0]["last_ingest_at"] != nil {
		t.Errorf("viewer role health = %v, want only the client-owned account, never assumed or ingested", got)
	}
	if f, ok := got[0]["findings"].([]any); !ok || len(f) != 0 {
		t.Errorf("findings = %v, want an empty list", got[0]["findings"])
	}
}
