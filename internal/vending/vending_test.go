package vending_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
	"github.com/hx-thanadej/keel/internal/vending"
)

type fakeOrg struct {
	mu       sync.Mutex
	units    map[string]string
	accounts map[string]string // name → id
	tags     map[string]map[string]string
	creates  int
	notReady int // AccountReady says no this many times
	failName string
}

func (f *fakeOrg) Provider() string { return "tencent" }
func (f *fakeOrg) EnsureUnit(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.units[name]; ok {
		return id, nil
	}
	f.units[name] = "node-" + name
	return f.units[name], nil
}
func (f *fakeOrg) FindAccount(_ context.Context, name string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.accounts[name]
	return id, ok, nil
}
func (f *fakeOrg) CreateAccount(_ context.Context, name, unit string, tags map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name == f.failName {
		return "", flow.Permanent(errors.New("InvalidParameter.MemberNameUsed"))
	}
	f.creates++
	id := "1000" + string(rune('0'+f.creates))
	f.accounts[name] = id
	f.tags[id] = tags
	return id, nil
}
func (f *fakeOrg) AccountReady(context.Context, string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.notReady > 0 {
		f.notReady--
		return false, nil
	}
	return true, nil
}

type world struct {
	s                         *store.Store
	tenant, project, dev, prd string
}

func setup(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s}
	w.tenant, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		var team string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tenant, team).Scan(&w.project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'dev') RETURNING id`, w.tenant, w.project).Scan(&w.dev); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, w.tenant, w.project).Scan(&w.prd)
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

var admin = activity.Actor{Type: activity.ActorHuman, UID: "user:admin@harmonyx.co"}

func TestVendEnvironmentEndToEnd(t *testing.T) {
	w := setup(t)
	org := &fakeOrg{units: map[string]string{}, accounts: map[string]string{}, tags: map[string]map[string]string{}, notReady: 2}
	baselineRan := ""
	v := vending.Vendor{Store: w.s, Org: org, Baseline: []flow.Step{{Name: "landing_zone", Do: func(_ context.Context, r *flow.Run) (map[string]any, error) {
		baselineRan = r.Out("account", "account_id")
		return nil, nil
	}}}}
	e := flow.New(w.s, v.Def())
	flowtest.Start(t, w.s, e)
	ctx := context.Background()

	f, created, err := v.Request(ctx, e, w.tenant, w.project, w.dev, admin)
	if err != nil || !created {
		t.Fatal(err, created)
	}
	if again, created, err := v.Request(ctx, e, w.tenant, w.project, w.dev, admin); err != nil || created || again.ID != f.ID {
		t.Fatalf("second request while running: %v %v", created, err)
	}
	f = flowtest.Wait(t, e, w.tenant, f.ID, "succeeded")
	if org.creates != 1 || org.tags["10001"]["keel-env"] != "dev" || org.units["tat"] != "node-tat" || baselineRan != "10001" {
		t.Fatalf("org %+v baseline %q", org, baselineRan)
	}
	if f.Steps[2].Attempts != 3 {
		t.Fatalf("ready step attempts %d, want 3", f.Steps[2].Attempts)
	}
	var name, ext string
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT name, external_id FROM cloud_accounts WHERE environment_id = $1 AND provider = 'tencent'`, w.dev).Scan(&name, &ext)
	}); err != nil {
		t.Fatal(err)
	}
	if name != "tat-tat-crm-dev" || ext != "10001" {
		t.Fatalf("cloud account %s %s", name, ext)
	}
	if _, _, err := v.Request(ctx, e, w.tenant, w.project, w.dev, admin); !errors.Is(err, vending.ErrAlreadyVended) {
		t.Fatalf("re-vend: %v", err)
	}
}

func TestVendingAdoptsAnAccountCreatedBeforeACrash(t *testing.T) {
	w := setup(t)
	// The account exists at the provider (a previous attempt created it) but Keel never recorded it.
	org := &fakeOrg{units: map[string]string{}, accounts: map[string]string{"tat-tat-crm-prod": "20001"}, tags: map[string]map[string]string{}}
	v := vending.Vendor{Store: w.s, Org: org}
	e := flow.New(w.s, v.Def())
	flowtest.Start(t, w.s, e)
	f, _, err := v.Request(context.Background(), e, w.tenant, w.project, w.prd, admin)
	if err != nil {
		t.Fatal(err)
	}
	f = flowtest.Wait(t, e, w.tenant, f.ID, "succeeded")
	if org.creates != 0 || f.Steps[1].Output["account_id"] != "20001" || f.Steps[1].Output["created"] != false {
		t.Fatalf("creates %d step %+v", org.creates, f.Steps[1])
	}
}

func TestVendingFailureStopsWithReasonAndCancelArchives(t *testing.T) {
	w := setup(t)
	org := &fakeOrg{units: map[string]string{}, accounts: map[string]string{}, tags: map[string]map[string]string{}, failName: "tat-tat-crm-dev"}
	v := vending.Vendor{Store: w.s, Org: org}
	e := flow.New(w.s, v.Def())
	flowtest.Start(t, w.s, e)
	f, _, err := v.Request(context.Background(), e, w.tenant, w.project, w.dev, admin)
	if err != nil {
		t.Fatal(err)
	}
	f = flowtest.Wait(t, e, w.tenant, f.ID, "failed")
	if f.Error == nil || !strings.Contains(*f.Error, "account: InvalidParameter.MemberNameUsed") {
		t.Fatalf("error %v", f.Error)
	}
	if err := e.Cancel(context.Background(), w.tenant, f.ID, "rename the project first", admin); err != nil {
		t.Fatal(err)
	}
	flowtest.Wait(t, e, w.tenant, f.ID, "cancelled")
}

func TestAccountNameFitsTencentLimit(t *testing.T) {
	if got := vending.AccountName("tat", "crm", "dev", 25); got != "tat-crm-dev" {
		t.Fatal(got)
	}
	long := vending.AccountName("tourism-authority", "customer-portal", "staging", 25)
	if len(long) > 25 || long != vending.AccountName("tourism-authority", "customer-portal", "staging", 25) || !strings.HasPrefix(long, "tourism-authority") {
		t.Fatalf("%q (%d)", long, len(long))
	}
	if long == vending.AccountName("tourism-authority", "customer-portal", "prod", 25) {
		t.Fatal("collision between environments")
	}
}
