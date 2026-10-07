package landingzone_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/landingzone"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type fakeOrg struct {
	mu       sync.Mutex
	policies map[string]string          // name → content
	ids      map[string]string          // name → id
	attached map[string]map[string]bool // account → policy ids
	writes   int
}

func newOrg() *fakeOrg {
	return &fakeOrg{policies: map[string]string{}, ids: map[string]string{}, attached: map[string]map[string]bool{}}
}

func (f *fakeOrg) EnsurePolicy(_ context.Context, p landingzone.Policy) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.ids[p.Name]; !ok {
		f.ids[p.Name] = fmt.Sprintf("%d", 100+len(f.ids))
		f.writes++
	}
	if f.policies[p.Name] != p.Content() {
		f.policies[p.Name] = p.Content()
		f.writes++
	}
	return f.ids[p.Name], nil
}
func (f *fakeOrg) FindPolicy(_ context.Context, name, _ string) (string, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.ids[name]
	if !ok {
		return "", "", false, nil
	}
	c, err := landingzone.Canonical(f.policies[name])
	return id, c, true, err
}
func (f *fakeOrg) Attached(_ context.Context, account, _ string) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for k, v := range f.attached[account] {
		out[k] = v
	}
	return out, nil
}
func (f *fakeOrg) Attach(_ context.Context, account, id, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attached[account] == nil {
		f.attached[account] = map[string]bool{}
	}
	f.attached[account][id] = true
	f.writes++
	return nil
}

var base = landingzone.Tencent(landingzone.Options{AutomationRole: "keel-automation"})

func TestApplyIsIdempotent(t *testing.T) {
	org := newOrg()
	ctx := context.Background()
	if err := landingzone.Apply(ctx, org, base, "100001"); err != nil {
		t.Fatal(err)
	}
	first := org.writes
	if first != 3*3 { // create + content + attach for each policy
		t.Fatalf("writes %d", first)
	}
	if err := landingzone.Apply(ctx, org, base, "100001"); err != nil {
		t.Fatal(err)
	}
	if org.writes != first {
		t.Fatalf("second apply wrote %d", org.writes-first)
	}
	if d, err := landingzone.Check(ctx, org, base, "100001"); err != nil || len(d) != 0 {
		t.Fatalf("clean account drift %v %v", d, err)
	}
}

func TestIdentityGuardrailExemptsOnlyKeel(t *testing.T) {
	var identity landingzone.Policy
	for _, p := range base.Policies {
		if p.Name == "keel_identities_via_keel" {
			identity = p
		}
	}
	c := identity.Content()
	for _, want := range []string{`"cam:CreateRole"`, `"cam:CreateAccessKey"`, `"cam:UpdateOIDCConfig"`, `"string_not_equal":{"qcs:role_name":["keel-automation"]}`, `"effect":"deny"`} {
		if !strings.Contains(c, want) {
			t.Fatalf("identity policy lacks %s: %s", want, c)
		}
	}
}

type world struct {
	s                          *store.Store
	tenant, env, account, team string
}

func setup(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s}
	w.tenant, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		var project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.tenant).Scan(&w.team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tenant, w.team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, w.tenant, project).Scan(&w.env); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name, baseline_version) VALUES ($1, $2, 'tencent', '100001', 'tat-tat-crm-prod', $3) RETURNING id`,
			w.tenant, w.env, base.Version).Scan(&w.account)
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

func openFindings(t *testing.T, w world) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := w.s.InTenant(context.Background(), w.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT fingerprint, coalesce(owner_team_id::text, '') FROM findings WHERE kind = 'landing_zone_drift' AND status = 'open'`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var fp, team string
			if err := rows.Scan(&fp, &team); err != nil {
				return err
			}
			out[fp] = team
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDriftRaisesFindingsAndFixResolvesThem(t *testing.T) {
	w := setup(t)
	org := newOrg()
	ctx := context.Background()
	if err := landingzone.Apply(ctx, org, base, "100001"); err != nil {
		t.Fatal(err)
	}
	// Someone detaches the audit guardrail and loosens the identity one.
	delete(org.attached["100001"], org.ids["keel_protect_audit"])
	org.policies["keel_identities_via_keel"] = `{"version":"2.0","statement":[]}`

	wt := landingzone.Watcher{Store: w.s, Provider: "tencent", Org: org, Baseline: base}
	res, err := wt.Run(ctx)
	if err != nil || res.Accounts != 1 || res.Drifted != 1 || res.Remediated != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	f := openFindings(t, w)
	if len(f) != 2 || f["landing_zone:100001:keel_protect_audit:detached"] != w.team || f["landing_zone:100001:keel_identities_via_keel:content_changed"] == "" {
		t.Fatalf("findings %v", f)
	}
	// Re-running does not duplicate.
	if _, err := wt.Run(ctx); err != nil || len(openFindings(t, w)) != 2 {
		t.Fatal("duplicated findings", err)
	}
	// A human fixes it; the next check resolves both.
	if err := landingzone.Apply(ctx, org, base, "100001"); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Run(ctx); err != nil || len(openFindings(t, w)) != 0 {
		t.Fatalf("still open %v %v", openFindings(t, w), err)
	}
}

func TestRemediateRestoresAndRecords(t *testing.T) {
	w := setup(t)
	org := newOrg()
	ctx := context.Background()
	if err := landingzone.Apply(ctx, org, base, "100001"); err != nil {
		t.Fatal(err)
	}
	delete(org.attached["100001"], org.ids["keel_stay_in_organisation"])
	res, err := landingzone.Watcher{Store: w.s, Provider: "tencent", Org: org, Baseline: base, Remediate: true}.Run(ctx)
	if err != nil || res.Remediated != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if !org.attached["100001"][org.ids["keel_stay_in_organisation"]] || len(openFindings(t, w)) != 0 {
		t.Fatal("not restored")
	}
	var resolution string
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT resolution FROM findings WHERE kind = 'landing_zone_drift'`).Scan(&resolution)
	}); err != nil || resolution != "restored by Keel" {
		t.Fatalf("resolution %q %v", resolution, err)
	}
}

func TestOutdatedBaselineIsReported(t *testing.T) {
	w := setup(t)
	org := newOrg()
	ctx := context.Background()
	if err := landingzone.Apply(ctx, org, base, "100001"); err != nil {
		t.Fatal(err)
	}
	next := base
	next.Version = "keel-baseline@2"
	if _, err := (landingzone.Watcher{Store: w.s, Provider: "tencent", Org: org, Baseline: next}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := openFindings(t, w)["landing_zone:100001:*:outdated"]; !ok {
		t.Fatalf("findings %v", openFindings(t, w))
	}
}
