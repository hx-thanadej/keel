package catalog_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/access"
	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/boundary"
	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/ciidentity"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/landingzone"
	"github.com/hx-thanadej/keel/internal/leaks"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
	"github.com/hx-thanadej/keel/internal/vending"
)

// cloud records every write a fake cloud client receives.
type cloud struct{ writes []string }

func (c *cloud) write(op string) error {
	c.writes = append(c.writes, op)
	return nil
}

type lzOrg struct{ *cloud }

func (o lzOrg) EnsurePolicy(_ context.Context, p landingzone.Policy) (string, error) {
	return "p-" + p.Name, o.write("landingzone.EnsurePolicy")
}
func (lzOrg) FindPolicy(context.Context, string, string) (string, string, bool, error) {
	return "", "", false, nil
}
func (lzOrg) Attached(context.Context, string, string) (map[string]bool, error) {
	return map[string]bool{}, nil
}
func (o lzOrg) Attach(context.Context, string, string, string) error {
	return o.write("landingzone.Attach")
}

type boundaryIAM struct{ *cloud }

func (b boundaryIAM) EnsurePolicy(context.Context, string, string, string) (int64, error) {
	return 1, b.write("boundary.EnsurePolicy")
}
func (boundaryIAM) Roles(context.Context) ([]boundary.Role, error) {
	return []boundary.Role{{ID: "r1", Name: "keel-deploy"}}, nil
}
func (boundaryIAM) RoleBoundary(context.Context, string) (int64, error) { return 0, nil }
func (b boundaryIAM) PutBoundary(context.Context, string, int64) error {
	return b.write("boundary.PutBoundary")
}

type ciIAM struct{ *cloud }

func (ciIAM) OIDCProvider(context.Context, string) (ciidentity.Provider, bool, error) {
	return ciidentity.Provider{}, false, nil
}
func (c ciIAM) CreateOIDCProvider(context.Context, string, ciidentity.Provider) error {
	return c.write("ciidentity.CreateOIDCProvider")
}
func (c ciIAM) UpdateOIDCProvider(context.Context, string, ciidentity.Provider) error {
	return c.write("ciidentity.UpdateOIDCProvider")
}
func (ciIAM) RoleTrust(context.Context, string) (string, bool, error) { return "", false, nil }
func (c ciIAM) CreateRole(context.Context, string, string, string) error {
	return c.write("ciidentity.CreateRole")
}
func (c ciIAM) UpdateRoleTrust(context.Context, string, string) error {
	return c.write("ciidentity.UpdateRoleTrust")
}

// directory's role configurations live in the Identity Center zone, not in
// a Cloud Account, so only assignments count as writes.
type directory struct{ *cloud }

func (directory) EnsureRoleConfiguration(context.Context, string, string, string, int) (string, error) {
	return "rc-1", nil
}
func (directory) UserID(context.Context, string) (string, bool, error) { return "u-1", true, nil }
func (d directory) Assign(context.Context, string, int64, string) error {
	return d.write("access.Assign")
}
func (d directory) Unassign(context.Context, string, int64, string) error {
	return d.write("access.Unassign")
}
func (directory) Assignments(context.Context, int64) ([]access.Assignment, error) { return nil, nil }

type native struct{ *cloud }

func (native) Provider() string { return "tencent" }
func (n native) Create(context.Context, budget.NativeSpec) (string, error) {
	return "nb-1", n.write("budget.Create")
}
func (n native) Update(context.Context, string, budget.NativeSpec) error {
	return n.write("budget.Update")
}
func (native) Get(context.Context, string) (budget.NativeSpec, bool, error) {
	return budget.NativeSpec{}, false, nil
}
func (n native) Delete(context.Context, string) error { return n.write("budget.Delete") }

type waste struct{ *cloud }

func (waste) Scan(context.Context) ([]rightsize.WasteItem, error) {
	return []rightsize.WasteItem{{ResourceID: "disk-1", ResourceType: "disk", Kind: "unattached_disk"}}, nil
}
func (w waste) Delete(context.Context, rightsize.WasteItem) (string, error) {
	return "snap-1", w.write("rightsize.Delete")
}

type keys struct{ *cloud }

func (keys) Provider() string { return "tencent" }
func (keys) Find(_ context.Context, id string, accounts []string) (leaks.Key, bool, error) {
	if !slices.Contains(accounts, external) {
		return leaks.Key{}, false, nil
	}
	return leaks.Key{Provider: "tencent", KeyID: id, Account: external, OwnerUin: "3001", Owner: "deploy-bot"}, true, nil
}
func (k keys) Disable(context.Context, leaks.Key) error { return k.write("leaks.Disable") }

type alerts struct{}

func (alerts) Secret(context.Context, string, int) (string, string, error) {
	return "tencent_cloud_secret_id", "SecretId=AKID" + strings.Repeat("a", 32), nil
}

// vendOrg finds the account already in the organisation, so vending adopts
// the Catalog row. Units are ours, never in a Cloud Account.
type vendOrg struct{ *cloud }

func (vendOrg) Provider() string                                   { return "tencent" }
func (vendOrg) EnsureUnit(context.Context, string) (string, error) { return "unit-1", nil }
func (vendOrg) FindAccount(context.Context, string) (string, bool, error) {
	return external, true, nil
}
func (v vendOrg) CreateAccount(context.Context, string, string, map[string]string) (string, error) {
	return external, v.write("vending.CreateAccount")
}
func (vendOrg) AccountReady(context.Context, string) (bool, error) { return true, nil }

const external = "100001"

// world is one Tenant with a dev Environment whose Tencent account carries
// every marker the daily jobs select on.
type world struct {
	s                             *store.Store
	tenant, team, project, env, a string
}

func newWorld(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	w := world{s: storetest.New(t)}
	var err error
	if w.tenant, err = w.s.CreateTenant(ctx, "tat", "TAT", true); err != nil {
		t.Fatal(err)
	}
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.tenant).Scan(&w.team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tenant, w.team).Scan(&w.project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name, waste_cleanup) VALUES ($1, $2, 'dev', true) RETURNING id`, w.tenant, w.project).Scan(&w.env); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name, baseline_version, boundary_version, ci_identity_at)
			VALUES ($1, $2, 'tencent', $3, 'tat-tat-crm-dev', 'keel-baseline@1', $4, now()) RETURNING id`, w.tenant, w.env, external, boundary.Version).Scan(&w.a)
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

// flip makes the account client-owned the way a platform admin does, leaving
// every marker in place.
func (w world) flip(t *testing.T) {
	t.Helper()
	if err := w.s.InTenant(context.Background(), w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE cloud_accounts SET ownership = 'client', read_only_role = '{"role_arn": "qcs::cam::uin/100001:roleName/keel-readonly"}' WHERE id = $1`, w.a)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (w world) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.s.InTenant(context.Background(), w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// run is a vending flow run whose account and register steps are done.
func (w world) run() *flow.Run {
	in := map[string]any{"environment_id": w.env, "project_id": w.project, "environment_name": "dev", "tenant_slug": "tat", "project_slug": "tat-crm", "account_name": "tat-tat-crm-dev"}
	return &flow.Run{ID: "run-1", Tenant: w.tenant, Input: in, Outputs: map[string]map[string]any{
		"account": {"account_id": external}, "register": {"cloud_account_id": w.a},
	}}
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:test"}

func engineer(w world) auth.Principal {
	return auth.Principal{Subject: "user:eng@harmonyx.co", Kind: auth.KindHuman, TenantID: "home", Home: true,
		Bindings: []auth.Binding{{Role: "engineer", TenantID: w.tenant, TeamIDs: []string{w.team}}}}
}

func grants(t *testing.T, w world, c *cloud) *access.Service {
	t.Helper()
	svc, err := access.New(w.s, directory{c})
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := flowtest.Client(t, w.s, svc.Register)
	svc.SetClient(rc)
	return svc
}

// mutator is one flow that writes to a Cloud Account. prepare runs while the
// account is still platform-owned; run is the next run after it may have
// flipped to client-owned.
type mutator struct {
	name    string
	prepare func(t *testing.T, w world, c *cloud) any
	run     func(t *testing.T, w world, c *cloud, prepared any) error
	// refusal is false only for a flow that leaves a client-owned account
	// out of scope instead of refusing it.
	refusal bool
	// client checks what a client-owned run must still report.
	client func(t *testing.T, w world)
}

var mutators = []mutator{
	{name: "vending adopts the account", refusal: true, run: func(t *testing.T, w world, c *cloud, _ any) error {
		baseline := flow.Step{Name: "baseline", Do: func(context.Context, *flow.Run) (map[string]any, error) {
			return nil, c.write("vending.baseline")
		}}
		r := w.run()
		r.Outputs = map[string]map[string]any{}
		for _, s := range (vending.Vendor{Store: w.s, Org: vendOrg{c}, Baseline: []flow.Step{baseline}}).Def().Steps {
			out, err := s.Do(context.Background(), r)
			if err != nil {
				return err
			}
			r.Outputs[s.Name] = out
		}
		return nil
	}},
	{name: "landing zone vending step", refusal: true, run: func(t *testing.T, w world, c *cloud, _ any) error {
		_, err := landingzone.Step(w.s, lzOrg{c}, landingzone.Tencent(landingzone.Options{})).Do(context.Background(), w.run())
		return err
	}},
	{name: "landing zone remediation", refusal: true, run: func(t *testing.T, w world, c *cloud, _ any) error {
		_, err := landingzone.Watcher{Store: w.s, Provider: "tencent", Org: lzOrg{c}, Baseline: landingzone.Tencent(landingzone.Options{}), Remediate: true}.Run(context.Background())
		return err
	}, client: func(t *testing.T, w world) {
		if n := w.count(t, `SELECT count(*) FROM findings WHERE kind = 'landing_zone_drift' AND status = 'open' AND detail->>'remediated' = 'false'`); n == 0 {
			t.Error("drift on a client-owned account was not reported")
		}
	}},
	{name: "boundary vending step", refusal: true, run: func(t *testing.T, w world, c *cloud, _ any) error {
		_, err := boundary.Manager{Store: w.s, Provider: "tencent", IAM: func(string) (boundary.IAM, error) { return boundaryIAM{c}, nil }}.Step().Do(context.Background(), w.run())
		return err
	}},
	{name: "boundary daily check", refusal: true, run: func(t *testing.T, w world, c *cloud, _ any) error {
		_, err := boundary.Manager{Store: w.s, Provider: "tencent", IAM: func(string) (boundary.IAM, error) { return boundaryIAM{c}, nil }}.Check(context.Background())
		return err
	}},
	{name: "CI identity vending step", refusal: true, run: func(t *testing.T, w world, c *cloud, _ any) error {
		_, err := ciManager(w, c).Step().Do(context.Background(), w.run())
		return err
	}},
	{name: "CI identity sync", refusal: true, run: func(t *testing.T, w world, c *cloud, _ any) error {
		_, err := ciManager(w, c).Sync(context.Background())
		return err
	}},
	{name: "access grant activation", refusal: true, run: func(t *testing.T, w world, c *cloud, _ any) error {
		svc := grants(t, w, c)
		role, err := svc.RequestRole(context.Background(), w.tenant, w.env, w.team, "read-only", keelActor)
		if err != nil {
			return err
		}
		_, err = svc.RequestGrant(context.Background(), w.tenant, role.ID, 1, "look at failing pods", engineer(w))
		return err
	}},
	{name: "access grant revocation", refusal: true, prepare: func(t *testing.T, w world, c *cloud) any {
		svc := grants(t, w, c)
		role, err := svc.RequestRole(context.Background(), w.tenant, w.env, w.team, "read-only", keelActor)
		if err != nil {
			t.Fatal(err)
		}
		g, err := svc.RequestGrant(context.Background(), w.tenant, role.ID, 1, "look at failing pods", engineer(w))
		if err != nil || g.State != "active" {
			t.Fatalf("grant %+v %v", g, err)
		}
		return g.ID
	}, run: func(t *testing.T, w world, c *cloud, grant any) error {
		g, err := grants(t, w, c).Revoke(context.Background(), w.tenant, grant.(string), "done", keelActor)
		if err == nil && g.State != "revoked" {
			t.Errorf("grant %s after revoke, want revoked", g.State)
		}
		return err
	}},
	{name: "budget mirror", run: func(t *testing.T, w world, c *cloud, _ any) error {
		svc := budget.Service{Store: w.s}
		if _, err := svc.Create(context.Background(), w.tenant, budget.Budget{ProjectID: w.project, Name: "tat-crm 2026", Year: 2026, Amount: "12000", MirrorNative: true}); err != nil {
			return err
		}
		_, err := budget.Mirror{Service: svc, Natives: map[string]budget.Native{"tencent": native{c}}, BillingCurrency: map[string]string{"tencent": "USD"},
			Now: func() time.Time { return time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC) }}.SyncAll(context.Background())
		return err
	}},
	{name: "waste cleanup", refusal: true, prepare: func(t *testing.T, w world, c *cloud) any {
		if _, err := wasteEngine(w, c, time.Now().AddDate(0, 0, -8), false).Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		return nil
	}, run: func(t *testing.T, w world, c *cloud, _ any) error {
		res, err := wasteEngine(w, c, time.Now(), true).Run(context.Background())
		if len(res.Errors) > 0 {
			t.Errorf("waste errors: %v", res.Errors)
		}
		return err
	}},
	{name: "leaked key", refusal: true, run: func(t *testing.T, w world, c *cloud, _ any) error {
		return (&leaks.Service{Store: w.s, Alerts: alerts{}, Keys: map[string]leaks.Keys{"tencent": keys{c}}}).Process(context.Background(), "tat/crm", 1)
	}, client: func(t *testing.T, w world) {
		if n := w.count(t, `SELECT count(*) FROM findings WHERE kind = 'leaked_key' AND severity = 'critical' AND title LIKE '%client-owned 100001 is still active' AND detail->>'action' LIKE '%the client must disable it now%'`); n != 1 {
			t.Error("no critical Finding telling the client to disable the leaked key")
		}
	}},
}

func ciManager(w world, c *cloud) ciidentity.Manager {
	return ciidentity.Manager{Store: w.s, Provider: "tencent", IAM: func(string) (ciidentity.IAM, error) { return ciIAM{c}, nil },
		JWKS: func(context.Context) (string, error) { return `{"keys":[{"kid":"k1"}]}`, nil }}
}

func wasteEngine(w world, c *cloud, now time.Time, cleanup bool) rightsize.WasteEngine {
	return rightsize.WasteEngine{Service: rightsize.Service{Store: w.s}, GraceDays: 7, CleanupEnabled: cleanup, Now: func() time.Time { return now },
		Scanner: func(string) (rightsize.WasteScanner, rightsize.Cleaner, error) { return waste{c}, waste{c}, nil }}
}

// TestMutatorsRefuseClientOwnedAccounts runs every flow that writes to a
// Cloud Account twice. Platform-owned, it must write, so the case reaches
// the write. Flipped to client-owned, it must make no write and record the
// refusal (ADR-0018).
func TestMutatorsRefuseClientOwnedAccounts(t *testing.T) {
	for _, m := range mutators {
		t.Run(m.name, func(t *testing.T) {
			for _, client := range []bool{false, true} {
				w := newWorld(t)
				c := &cloud{}
				var prepared any
				if m.prepare != nil {
					prepared = m.prepare(t, w, c)
					c.writes = nil
				}
				if client {
					w.flip(t)
				}
				err := m.run(t, w, c, prepared)
				refusals := w.count(t, `SELECT count(*) FROM activities WHERE type = 'keel.cloud_account.change_refused' AND subject = $1`, "cloud_account/"+w.a)
				if !client {
					if err != nil || len(c.writes) == 0 || refusals != 0 {
						t.Fatalf("platform-owned: err %v, writes %v, refusals %d; the case must reach a write", err, c.writes, refusals)
					}
					continue
				}
				if len(c.writes) != 0 {
					t.Errorf("client-owned account written: %v", c.writes)
				}
				if err != nil && !errors.Is(err, catalog.ErrClientOwned) {
					t.Errorf("client-owned: %v", err)
				}
				if m.refusal && refusals == 0 {
					t.Error("no keel.cloud_account.change_refused Activity")
				}
				if m.client != nil {
					m.client(t, w)
				}
			}
		})
	}
}

// accountWrites maps every write method of a cloud adapter to the mutator
// that exercises it, or to why it never writes to a Cloud Account. A new
// write method fails TestEveryCloudWriteIsSwept until it is listed here, and
// a mutator name must be one TestMutatorsRefuseClientOwnedAccounts runs.
var accountWrites = map[string]string{
	"aws.Budgets.Create":                             "budget mirror",
	"aws.Budgets.Update":                             "budget mirror",
	"aws.Budgets.Delete":                             "budget mirror",
	"tencent.Budgets.Create":                         "budget mirror",
	"tencent.Budgets.Update":                         "budget mirror",
	"tencent.Budgets.Delete":                         "budget mirror",
	"tencent.AccountFactory.EnsureUnit":              "not account-scoped: a unit in Keel's own organisation",
	"tencent.AccountFactory.CreateAccount":           "vending adopts the account",
	"tencent.Guardrails.EnsurePolicy":                "landing zone remediation",
	"tencent.Guardrails.Attach":                      "landing zone remediation",
	"tencent.Boundaries.EnsurePolicy":                "boundary daily check",
	"tencent.Boundaries.PutBoundary":                 "boundary vending step",
	"tencent.CIIdentity.CreateOIDCProvider":          "CI identity sync",
	"tencent.CIIdentity.UpdateOIDCProvider":          "CI identity sync",
	"tencent.CIIdentity.CreateRole":                  "CI identity sync",
	"tencent.CIIdentity.UpdateRoleTrust":             "CI identity sync",
	"tencent.IdentityCenter.Assign":                  "access grant activation",
	"tencent.IdentityCenter.Unassign":                "access grant revocation",
	"tencent.IdentityCenter.EnsureRoleConfiguration": "not account-scoped: a role configuration in Keel's Identity Center zone",
	"tencent.AccessKeys.Disable":                     "leaked key",
	"tencent.Waste.Delete":                           "waste cleanup",
	"tencent.Registry.EnsureNamespace":               "not account-scoped: Keel's shared regional registry",
	"tencent.Registry.EnsureImmutableTags":           "not account-scoped: Keel's shared regional registry",
	"tencent.Registry.EnsureRetention":               "not account-scoped: Keel's shared regional registry",
}

var writeVerb = regexp.MustCompile(`^(Create|Update|Delete|Put|Attach|Detach|Assign|Unassign|Disable|Enable|Ensure|Add|Remove|Set|Modify|Stop|Start|Terminate|Reset|Tag|Untag)([A-Z]|$)`)

// TestEveryCloudWriteIsSwept keeps accountWrites complete: every exported
// write method on an exported cloud adapter type must be listed.
func TestEveryCloudWriteIsSwept(t *testing.T) {
	found := map[string]bool{}
	err := filepath.WalkDir("../cloud", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() || !writeVerb.MatchString(fn.Name.Name) {
				continue
			}
			recv := fn.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if id, ok := recv.(*ast.Ident); ok && id.IsExported() {
				found[f.Name.Name+"."+id.Name+"."+fn.Name.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	swept := map[string]bool{}
	for _, m := range mutators {
		swept[m.name] = true
	}
	for method := range found {
		if _, ok := accountWrites[method]; !ok {
			t.Errorf("%s writes to the cloud but is not in accountWrites: guard its flow with catalog.RequirePlatformOwned and add a mutator, or say why it is not account-scoped", method)
		}
	}
	for method, by := range accountWrites {
		if !found[method] {
			t.Errorf("accountWrites lists %s, which no cloud adapter has any more", method)
		}
		if !strings.HasPrefix(by, "not account-scoped: ") && !swept[by] {
			t.Errorf("%s maps to %q, which is not a mutator", method, by)
		}
	}
}
