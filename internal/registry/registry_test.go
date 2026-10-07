package registry_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/registry"
	"github.com/hx-thanadej/keel/internal/store/storetest"
	"github.com/hx-thanadej/keel/internal/vending"
)

type fakeReg struct{ namespaces, immutable, retention map[string]int }

func (f *fakeReg) EnsureNamespace(_ context.Context, n string) (int64, bool, error) {
	f.namespaces[n]++
	return 9, f.namespaces[n] == 1, nil
}
func (f *fakeReg) EnsureImmutableTags(_ context.Context, n string) (bool, error) {
	f.immutable[n]++
	return true, nil
}
func (f *fakeReg) EnsureRetention(_ context.Context, n string, _ int64, keep int) (bool, error) {
	f.retention[n] = keep
	return true, nil
}

type org struct{ n int }

func (o *org) Provider() string                                          { return "tencent" }
func (o *org) EnsureUnit(context.Context, string) (string, error)        { return "1", nil }
func (o *org) FindAccount(context.Context, string) (string, bool, error) { return "", false, nil }
func (o *org) CreateAccount(context.Context, string, string, map[string]string) (string, error) {
	o.n++
	return "50000" + string(rune('0'+o.n)), nil
}
func (o *org) AccountReady(context.Context, string) (bool, error) { return true, nil }

func TestNamespacePerProjectAndEgressReport(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	_, _ = s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var project, dev, prod string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'dev') RETURNING id`, tenant, project).Scan(&dev); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&prod)
	}); err != nil {
		t.Fatal(err)
	}
	reg := &fakeReg{namespaces: map[string]int{}, immutable: map[string]int{}, retention: map[string]int{}}
	v := vending.Vendor{Store: s, Org: &org{}, Baseline: []flow.Step{registry.Step(s, reg, 30)}}
	e := flow.New(s, v.Def())
	flowtest.Start(t, s, e)
	by := activity.Actor{Type: activity.ActorHuman, UID: "user:a"}
	for _, env := range []string{dev, prod} {
		f, _, err := v.Request(ctx, e, tenant, project, env, by)
		if err != nil {
			t.Fatal(err)
		}
		flowtest.Wait(t, e, tenant, f.ID, "succeeded")
	}
	if reg.namespaces["tat-tat-crm"] != 2 || reg.retention["tat-tat-crm"] != 30 || reg.immutable["tat-tat-crm"] != 2 {
		t.Fatalf("registry %+v", reg)
	}
	var since time.Time
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT registry_created_at FROM projects WHERE id = $1`, project).Scan(&since)
	}); err != nil {
		t.Fatal(err)
	}
	// 3.00/day of cross-region pulls before, 0.50/day after.
	day := since.UTC().Truncate(24 * time.Hour)
	var lines []cost.Line
	for i := -14; i < 14; i++ {
		d := day.AddDate(0, 0, i)
		amt := "3.00"
		if i >= 0 {
			amt = "0.50"
		}
		lines = append(lines, cost.Line{SubAccountID: "500001", BillingPeriodStart: time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC), ChargePeriodStart: d, ChargePeriodEnd: d.AddDate(0, 0, 1),
			ChargeCategory: "Usage", ServiceCategory: "Networking", BilledCost: amt, BillingCurrency: "USD", ServiceName: "Cloud Virtual Machine", ResourceID: "eip", Tags: map[string]string{}, Vendor: map[string]string{}})
	}
	byPeriod := map[time.Time][]cost.Line{}
	for _, l := range lines {
		byPeriod[l.BillingPeriodStart] = append(byPeriod[l.BillingPeriodStart], l)
	}
	for p, ls := range byPeriod {
		if _, err := (&cost.Ingester{Store: s}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: "payer", BillingPeriod: p, Lines: ls}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := registry.Report(ctx, s, tenant, project, 14, day.AddDate(0, 0, 30))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Namespace != "tat-tat-crm" || rep.Before != "3.00" || rep.After != "0.50" || rep.AfterDays != 14 || rep.Currency != "USD" {
		t.Fatalf("report %+v", rep)
	}
}

func TestNamespaceNameFitsTCR(t *testing.T) {
	n := registry.NamespaceName("tourism-authority-of-thailand", "customer-portal")
	if len(n) > registry.MaxNameLen || !strings.HasPrefix(n, "tourism-authority") || n != strings.ToLower(n) {
		t.Fatalf("%q", n)
	}
}
