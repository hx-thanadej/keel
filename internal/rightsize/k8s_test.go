package rightsize_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/utilisation"
)

var asOf = time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)

// k8sWorld: TAT prod (THB, 1 USD = 35 THB) with a dedicated cluster costing
// 30 USD/day of CVM and one workload container per test.
func k8sWorld(t *testing.T) world {
	w := setup(t)
	ctx := context.Background()
	must(t, w.s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO fx_rates (tenant_id, day, currency, per_eur) VALUES ($1, '2026-01-01', 'USD', 1.10), ($1, '2026-01-01', 'THB', 38.50)`, w.home)
		return err
	}))
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', 'prod-uin', 'prod')`, w.tat, w.prod)
		return err
	}))
	var lines []cost.Line
	for d := asOf.AddDate(0, 0, -30); d.Before(asOf); d = d.AddDate(0, 0, 1) {
		lines = append(lines, cost.Line{SubAccountID: "prod-uin", BillingPeriodStart: time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC), ChargePeriodStart: d, ChargePeriodEnd: d.AddDate(0, 0, 1),
			ChargeCategory: "Usage", BilledCost: "30.00", BillingCurrency: "USD", ServiceName: "Cloud Virtual Machine", ResourceID: "ins-node", Tags: map[string]string{}, Vendor: map[string]string{}})
	}
	byPeriod := map[time.Time][]cost.Line{}
	for _, l := range lines {
		byPeriod[l.BillingPeriodStart] = append(byPeriod[l.BillingPeriodStart], l)
	}
	for p, ls := range byPeriod {
		_, err := (&cost.Ingester{Store: w.s}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: "payer", BillingPeriod: p, Lines: ls})
		must(t, err)
	}
	return w
}

// days of summaries for one container: replicas × 1440 samples/day.
func usage(t *testing.T, w world, workload string, days, replicas int, cpuP95, cpuReq, memMax, memReq float64) {
	t.Helper()
	var sums []utilisation.Summary
	for i := 1; i <= days; i++ {
		d := asOf.AddDate(0, 0, -i)
		id := "prod-tke/tat-crm-prod/" + workload + "/app"
		base := utilisation.Summary{Provider: "k8s", ResourceID: id, ResourceType: "k8s_container", Day: d, Samples: replicas * 1440,
			Cluster: "prod-tke", Namespace: "tat-crm-prod", Workload: workload, Container: "app"}
		c := base
		c.Metric, c.P50, c.P95, c.P99, c.Max, c.Request = "cpu_cores", cpuP95/2, cpuP95, cpuP95*1.1, cpuP95*1.2, &cpuReq
		m := base
		m.Metric, m.P50, m.P95, m.P99, m.Max, m.Request = "memory_bytes", memMax*0.8, memMax*0.9, memMax*0.95, memMax, &memReq
		sums = append(sums, c, m)
	}
	must(t, (utilisation.Store{Store: w.s}).Save(context.Background(), w.tat, &w.project, &w.prod, sums))
}

const gi = float64(1 << 30)

func TestK8sEngineRecommendsSmallerRequests(t *testing.T) {
	w := k8sWorld(t)
	usage(t, w, "api", 21, 2, 0.41, 2.0, 1.3*gi, 4*gi)    // heavily over-requested
	usage(t, w, "web", 21, 1, 0.45, 0.5, 0.45*gi, 0.5*gi) // already right-sized
	eng := rightsize.K8sEngine{Service: rightsize.Service{Store: w.s}, Utilisation: utilisation.Store{Store: w.s}, Now: func() time.Time { return asOf }}
	res, err := eng.Run(context.Background())
	must(t, err)
	if res.Raised != 1 {
		t.Fatalf("result %+v", res)
	}
	recs, err := eng.Service.List(context.Background(), w.tat, rightsize.Filter{State: "open"})
	must(t, err)
	r := recs[0]
	if r.ResourceID != "prod-tke/tat-crm-prod/api/app" || r.Action != "resize_requests" || r.Currency != "THB" || r.Source != "engine:k8s" {
		t.Fatalf("rec %+v", r)
	}
	// CPU: max daily p95 0.41 → 410m; memory: 1.3Gi × 1.15 = 1531Mi (ceil).
	if r.Recommended["cpu"] != "410m" || r.Recommended["memory"] != "1531Mi" || r.Current["cpu"] != "2000m" || r.Current["memory"] != "4096Mi" {
		t.Fatalf("sizes current %v recommended %v", r.Current, r.Recommended)
	}
	if r.Evidence["replicas"] != float64(2) || r.Evidence["lookback_days"] != float64(21) {
		t.Fatalf("evidence %v", r.Evidence)
	}
	if r.MonthlySavings == "" || r.MonthlySavings[0] == '-' || r.MonthlySavings == "0.00" {
		t.Fatalf("savings %s", r.MonthlySavings)
	}
	if r.Confidence < 0.8 {
		t.Fatalf("confidence %v", r.Confidence)
	}
}

func TestK8sEngineNeedsHistory(t *testing.T) {
	w := k8sWorld(t)
	usage(t, w, "api", 10, 1, 0.1, 2.0, 0.2*gi, 4*gi)
	eng := rightsize.K8sEngine{Service: rightsize.Service{Store: w.s}, Utilisation: utilisation.Store{Store: w.s}, Now: func() time.Time { return asOf }}
	res, err := eng.Run(context.Background())
	must(t, err)
	if res.Raised != 0 || res.Skipped["insufficient_history"] != 1 {
		t.Fatalf("10 days of history: %+v", res)
	}
}

func TestK8sEngineProdNeedsThreeWeeks(t *testing.T) {
	w := k8sWorld(t)
	usage(t, w, "api", 16, 1, 0.1, 2.0, 0.2*gi, 4*gi) // enough for non-prod, not for prod
	eng := rightsize.K8sEngine{Service: rightsize.Service{Store: w.s}, Utilisation: utilisation.Store{Store: w.s}, Now: func() time.Time { return asOf }}
	res, err := eng.Run(context.Background())
	must(t, err)
	if res.Raised != 0 || res.Skipped["low_confidence_prod"] != 1 {
		t.Fatalf("prod with 16 days: %+v", res)
	}
}

func TestK8sEngineFlagsUnderProvisioned(t *testing.T) {
	w := k8sWorld(t)
	usage(t, w, "worker", 21, 1, 0.9, 0.5, 900*1024*1024, 512*1024*1024) // CPU and memory above request
	eng := rightsize.K8sEngine{Service: rightsize.Service{Store: w.s}, Utilisation: utilisation.Store{Store: w.s}, Now: func() time.Time { return asOf }}
	_, err := eng.Run(context.Background())
	must(t, err)
	recs, _ := eng.Service.List(context.Background(), w.tat, rightsize.Filter{State: "open"})
	if len(recs) != 1 || recs[0].Risk["under_provisioned"] != true || recs[0].MonthlySavings[0] != '-' {
		t.Fatalf("under-provisioned rec %+v", recs)
	}
	_ = fmt.Sprint()
}
