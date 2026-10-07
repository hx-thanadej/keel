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

type fakeCatalog struct{}

func (fakeCatalog) Types(context.Context, string) ([]rightsize.InstanceType, error) {
	return []rightsize.InstanceType{
		{Name: "S5.MEDIUM2", Family: "S5", CPU: 2, MemoryGiB: 2, HourlyPrice: 0.04},
		{Name: "S5.MEDIUM4", Family: "S5", CPU: 2, MemoryGiB: 4, HourlyPrice: 0.05},
		{Name: "S5.LARGE8", Family: "S5", CPU: 4, MemoryGiB: 8, HourlyPrice: 0.10},
		{Name: "S5.2XLARGE16", Family: "S5", CPU: 8, MemoryGiB: 16, HourlyPrice: 0.20},
		{Name: "SA3.MEDIUM4", Family: "SA3", CPU: 2, MemoryGiB: 4, HourlyPrice: 0.045}, // cheaper family
	}, nil
}

type fakeInventory map[string]string

func (f fakeInventory) InstanceTypes(context.Context, string, []string) (map[string]string, error) {
	return f, nil
}

func vmWorld(t *testing.T, days int, envName string, cpuP95, memMax float64, withMem bool) world {
	w := k8sWorld(t)
	ctx := context.Background()
	env := w.prod
	if envName != "prod" {
		must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, $3) RETURNING id`, w.tat, w.project, envName).Scan(&env)
		}))
		w.prod = env
	}
	// The instance costs 60 USD/month effective (2 USD/day) after discounts.
	var lines []cost.Line
	for d := asOf.AddDate(0, 0, -30); d.Before(asOf); d = d.AddDate(0, 0, 1) {
		lines = append(lines, cost.Line{SubAccountID: "prod-uin", BillingPeriodStart: time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC), ChargePeriodStart: d, ChargePeriodEnd: d.AddDate(0, 0, 1),
			ChargeCategory: "Usage", BilledCost: "2.00", BillingCurrency: "USD", ServiceName: "Cloud Virtual Machine", ResourceID: "ins-app1", Tags: map[string]string{}, Vendor: map[string]string{}})
	}
	byPeriod := map[time.Time][]cost.Line{}
	for _, l := range lines {
		byPeriod[l.BillingPeriodStart] = append(byPeriod[l.BillingPeriodStart], l)
	}
	for p, ls := range byPeriod {
		_, err := (&cost.Ingester{Store: w.s}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: "payer-vm", BillingPeriod: p, Lines: ls})
		must(t, err)
	}
	var sums []utilisation.Summary
	for i := 1; i <= days; i++ {
		d := asOf.AddDate(0, 0, -i)
		sums = append(sums, utilisation.Summary{Provider: "tencent", ResourceID: "ins-app1", ResourceType: "vm", Metric: "cpu_pct", Day: d, P95: cpuP95, Max: cpuP95 + 5, Samples: 1440})
		if withMem {
			sums = append(sums, utilisation.Summary{Provider: "tencent", ResourceID: "ins-app1", ResourceType: "vm", Metric: "memory_pct", Day: d, P95: memMax - 2, Max: memMax, Samples: 1440})
		}
	}
	must(t, (utilisation.Store{Store: w.s}).Save(ctx, w.tat, &w.project, &env, sums))
	return w
}

func vmEngine(w world) rightsize.VMEngine {
	return rightsize.VMEngine{Service: rightsize.Service{Store: w.s}, Catalog: fakeCatalog{}, Inventory: func(string) rightsize.Inventory { return fakeInventory{"ins-app1": "S5.2XLARGE16"} },
		Region: "ap-bangkok", Now: func() time.Time { return asOf }}
}

func TestVMEngineDownsizes(t *testing.T) {
	// 8 vCPU / 16 GiB at 10% CPU p95 (0.8 cores) and 20% memory (3.2 GiB).
	w := vmWorld(t, 35, "prod", 10, 20, true)
	e := vmEngine(w)
	res, err := e.Run(context.Background())
	must(t, err)
	if res.Raised != 1 {
		t.Fatalf("result %+v", res)
	}
	recs, _ := e.Service.List(context.Background(), w.tat, rightsize.Filter{State: "open"})
	r := recs[0]
	// Needs 0.8/0.7 = 1.14 cores and 3.2 × 1.15 = 3.68 GiB → cheapest fit is SA3.MEDIUM4 (0.045/h).
	if r.Recommended["instance_type"] != "SA3.MEDIUM4" || r.Current["instance_type"] != "S5.2XLARGE16" || r.Action != "change_family" {
		t.Fatalf("rec current %v recommended %v action %s", r.Current, r.Recommended, r.Action)
	}
	// Effective 60 USD/month = 2100 THB × (1 − 0.045/0.20) = 1627.50 THB.
	if r.MonthlySavings != "1627.50" || r.Currency != "THB" {
		t.Fatalf("savings %s %s", r.MonthlySavings, r.Currency)
	}
	if r.Risk["restart"] != true {
		t.Errorf("risk %v", r.Risk)
	}
}

func TestVMEngineWithoutMemoryDataKeepsMemory(t *testing.T) {
	w := vmWorld(t, 35, "prod", 10, 0, false)
	e := vmEngine(w)
	_, err := e.Run(context.Background())
	must(t, err)
	recs, _ := e.Service.List(context.Background(), w.tat, rightsize.Filter{State: "open"})
	if len(recs) != 1 || recs[0].Recommended["instance_type"] != "S5.2XLARGE16" && recs[0].Recommended["memory_gib"] != float64(16) {
		// With memory unmeasured, only types with ≥16 GiB qualify: none is cheaper than S5.2XLARGE16 → no recommendation.
		if len(recs) != 0 {
			t.Fatalf("recs %+v", recs)
		}
	}
	if len(recs) != 0 {
		t.Fatalf("must not shrink memory blindly: %+v", recs[0].Recommended)
	}
}

func TestVMEngineProdNeeds32Days(t *testing.T) {
	w := vmWorld(t, 20, "prod", 10, 20, true)
	res, err := vmEngine(w).Run(context.Background())
	must(t, err)
	if res.Raised != 0 || res.Skipped["low_confidence_prod"] != 1 {
		t.Fatalf("prod 20 days %+v", res)
	}
	w2 := vmWorld(t, 20, "dev", 10, 20, true)
	res, err = vmEngine(w2).Run(context.Background())
	must(t, err)
	if res.Raised != 1 {
		t.Fatalf("dev 20 days %+v", res)
	}
}

func TestVMEngineBusyInstanceUntouched(t *testing.T) {
	w := vmWorld(t, 35, "prod", 75, 80, true)
	res, err := vmEngine(w).Run(context.Background())
	must(t, err)
	if res.Raised != 0 || res.Skipped["no_change"] != 1 {
		t.Fatalf("busy %+v", res)
	}
}
