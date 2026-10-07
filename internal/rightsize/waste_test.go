package rightsize_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/utilisation"
)

type fakeWaste struct {
	items   []rightsize.WasteItem
	deleted []string
}

func (f *fakeWaste) Scan(context.Context) ([]rightsize.WasteItem, error) { return f.items, nil }
func (f *fakeWaste) Delete(_ context.Context, it rightsize.WasteItem) (string, error) {
	f.deleted = append(f.deleted, it.ResourceID)
	if it.ResourceType == "disk" {
		return "snap-" + it.ResourceID, nil
	}
	return "", nil
}

// wasteWorld: TAT with a dev env (account dev-uin) and prod env (prod-uin);
// each orphan costs 1 USD/day.
func wasteWorld(t *testing.T) (world, string) {
	w := k8sWorld(t)
	ctx := context.Background()
	var dev string
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'dev') RETURNING id`, w.tat, w.project).Scan(&dev); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', 'dev-uin', 'dev')`, w.tat, dev)
		return err
	}))
	var lines []cost.Line
	for d := asOf.AddDate(0, 0, -30); d.Before(asOf); d = d.AddDate(0, 0, 1) {
		for _, x := range [][2]string{{"dev-uin", "disk-dev"}, {"dev-uin", "eip-dev"}, {"prod-uin", "disk-prod"}, {"dev-uin", "ins-idle"}} {
			lines = append(lines, cost.Line{SubAccountID: x[0], BillingPeriodStart: time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC), ChargePeriodStart: d, ChargePeriodEnd: d.AddDate(0, 0, 1),
				ChargeCategory: "Usage", BilledCost: "1.00", BillingCurrency: "USD", ServiceName: "Cloud Block Storage", ResourceID: x[1], Tags: map[string]string{}, Vendor: map[string]string{}})
		}
	}
	byPeriod := map[time.Time][]cost.Line{}
	for _, l := range lines {
		byPeriod[l.BillingPeriodStart] = append(byPeriod[l.BillingPeriodStart], l)
	}
	for p, ls := range byPeriod {
		_, err := (&cost.Ingester{Store: w.s}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: "payer-waste", BillingPeriod: p, Lines: ls})
		must(t, err)
	}
	return w, dev
}

func wasteEngine(w world, scanners map[string]*fakeWaste, now time.Time, cleanup bool) rightsize.WasteEngine {
	return rightsize.WasteEngine{Service: rightsize.Service{Store: w.s},
		Scanner: func(account string) (rightsize.WasteScanner, rightsize.Cleaner, error) {
			f := scanners[account]
			if f == nil {
				f = &fakeWaste{}
			}
			return f, f, nil
		},
		Now: func() time.Time { return now }, GraceDays: 7, CleanupEnabled: cleanup}
}

func TestWasteDetectionPricesAtActualCost(t *testing.T) {
	w, _ := wasteWorld(t)
	dev := &fakeWaste{items: []rightsize.WasteItem{{ResourceID: "disk-dev", ResourceType: "disk", Kind: "unattached_disk"}, {ResourceID: "eip-dev", ResourceType: "eip", Kind: "unbound_eip"}}}
	e := wasteEngine(w, map[string]*fakeWaste{"dev-uin": dev}, asOf, false)
	res, err := e.Run(context.Background())
	must(t, err)
	if res.Raised != 2 {
		t.Fatalf("result %+v", res)
	}
	recs, _ := e.Service.List(context.Background(), w.tat, rightsize.Filter{State: "open"})
	for _, r := range recs {
		if r.Action != "delete" || r.MonthlySavings != "1050.00" || r.Source != "engine:waste" { // 30 USD/month × 35
			t.Fatalf("rec %+v", r)
		}
	}
}

func TestIdleVMFromUtilisation(t *testing.T) {
	w, devEnv := wasteWorld(t)
	var sums []utilisation.Summary
	for i := 1; i <= 15; i++ {
		sums = append(sums, utilisation.Summary{Provider: "tencent", ResourceID: "ins-idle", ResourceType: "vm", Metric: "cpu_pct", Day: asOf.AddDate(0, 0, -i), P95: 0.8, Max: 1.5, Samples: 1440})
	}
	must(t, (utilisation.Store{Store: w.s}).Save(context.Background(), w.tat, &w.project, &devEnv, sums))
	e := wasteEngine(w, nil, asOf, false)
	_, err := e.Run(context.Background())
	must(t, err)
	recs, _ := e.Service.List(context.Background(), w.tat, rightsize.Filter{State: "open"})
	if len(recs) != 1 || recs[0].ResourceID != "ins-idle" || recs[0].Action != "stop" {
		t.Fatalf("idle vm recs %+v", recs)
	}
}

func TestCleanupIsGated(t *testing.T) {
	w, devEnv := wasteWorld(t)
	ctx := context.Background()
	dev := &fakeWaste{items: []rightsize.WasteItem{{ResourceID: "disk-dev", ResourceType: "disk", Kind: "unattached_disk"}, {ResourceID: "eip-dev", ResourceType: "eip", Kind: "unbound_eip"}}}
	prod := &fakeWaste{items: []rightsize.WasteItem{{ResourceID: "disk-prod", ResourceType: "disk", Kind: "unattached_disk"}}}
	scanners := map[string]*fakeWaste{"dev-uin": dev, "prod-uin": prod}
	// Day 0: raised.
	_, err := wasteEngine(w, scanners, asOf, true).Run(ctx)
	must(t, err)

	later := asOf.AddDate(0, 0, 8)
	// Grace passed but the Environment hasn't opted in: nothing deleted.
	_, err = wasteEngine(w, scanners, later, true).Run(ctx)
	must(t, err)
	if len(dev.deleted)+len(prod.deleted) != 0 {
		t.Fatal("deleted without environment opt-in")
	}
	// Opt in dev and prod; global switch off: nothing deleted.
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE environments SET waste_cleanup = true`)
		return err
	}))
	_, err = wasteEngine(w, scanners, later, false).Run(ctx)
	must(t, err)
	if len(dev.deleted)+len(prod.deleted) != 0 {
		t.Fatal("deleted with the global switch off")
	}
	// Dismiss the EIP: it must survive.
	recs, _ := (rightsize.Service{Store: w.s}).List(ctx, w.tat, rightsize.Filter{State: "open"})
	for _, r := range recs {
		if r.ResourceID == "eip-dev" {
			_, err := (rightsize.Service{Store: w.s}).Dismiss(ctx, w.tat, r.ID, "reserved for the launch", by)
			must(t, err)
		}
	}
	// Before grace: nothing.
	_, err = wasteEngine(w, scanners, asOf.AddDate(0, 0, 3), true).Run(ctx)
	must(t, err)
	if len(dev.deleted) != 0 {
		t.Fatal("deleted before the grace period")
	}
	// Everything satisfied: only the dev disk goes; prod never; dismissed EIP stays.
	res, err := wasteEngine(w, scanners, later, true).Run(ctx)
	must(t, err)
	if len(dev.deleted) != 1 || dev.deleted[0] != "disk-dev" || len(prod.deleted) != 0 || res.Deleted != 1 {
		t.Fatalf("deleted dev %v prod %v res %+v", dev.deleted, prod.deleted, res)
	}
	var state, reason string
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, coalesce(decision_reason, '') FROM recommendations WHERE resource_id = 'disk-dev' AND state = 'applied'`).Scan(&state, &reason)
	}))
	if state != "applied" || reason != "deleted by Keel after 7 days; snapshot snap-disk-dev" {
		t.Fatalf("state %s reason %q", state, reason)
	}
	_ = devEnv
}
