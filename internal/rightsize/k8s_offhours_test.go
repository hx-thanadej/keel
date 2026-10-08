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

// k8sOffHoursWorld: one workload "api" (2 replicas, requests 2 cores and
// 4 GiB each) busy 09:00–18:00 Bangkok on weekdays (02:00–11:00 UTC) at
// 0.5 cores and at 0.02 cores (1% of its request) otherwise. Its
// Environment's cluster costs 30 USD/day of CVM and runs nothing else.
func k8sOffHoursWorld(t *testing.T, env string) world {
	w := k8sWorld(t)
	ctx := context.Background()
	envID := w.prod
	if env != "prod" {
		must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, $3) RETURNING id::text`, w.tat, w.project, env).Scan(&envID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', $3, $3)`, w.tat, envID, env+"-uin")
			return err
		}))
		var lines []cost.Line
		for i := 1; i <= 14; i++ {
			d := asOf.AddDate(0, 0, -i)
			lines = append(lines, cost.Line{SubAccountID: env + "-uin", BillingPeriodStart: time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC), ChargePeriodStart: d, ChargePeriodEnd: d.AddDate(0, 0, 1),
				ChargeCategory: "Usage", BilledCost: "30.00", BillingCurrency: "USD", ServiceName: "Cloud Virtual Machine", ResourceID: "ins-" + env + "-node", Tags: map[string]string{}, Vendor: map[string]string{}})
		}
		_, err := (&cost.Ingester{Store: w.s}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: "payer-" + env, BillingPeriod: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Lines: lines})
		must(t, err)
	}
	cpuReq, memReq := 2.0, 4*gi
	var sums []utilisation.Summary
	for i := 1; i <= 14; i++ {
		d := asOf.AddDate(0, 0, -i)
		hourly := make([]float64, 24)
		for h := range hourly {
			hourly[h] = 0.02
			if h >= 2 && h < 11 && d.Weekday() != time.Saturday && d.Weekday() != time.Sunday {
				hourly[h] = 0.5
			}
		}
		base := utilisation.Summary{Provider: "k8s", ResourceID: "dev-tke/tat-crm/api/app", ResourceType: "k8s_container", Day: d, Samples: 2 * 1440,
			Cluster: "dev-tke", Namespace: "tat-crm", Workload: "api", Container: "app"}
		c := base
		c.Metric, c.P95, c.Max, c.Request, c.Hourly = "cpu_cores", 0.5, 0.5, &cpuReq, hourly
		m := base
		m.Metric, m.P95, m.Max, m.Request = "memory_bytes", 1*gi, 1*gi, &memReq
		sums = append(sums, c, m)
	}
	must(t, utilisation.Store{Store: w.s}.Save(ctx, w.tat, &w.project, &envID, sums))
	return w
}

func k8sOffHours(t *testing.T, w world) (rightsize.OffHoursResult, []rightsize.Recommendation) {
	t.Helper()
	svc := rightsize.Service{Store: w.s}
	res, err := rightsize.K8sOffHoursEngine{Service: svc, Now: func() time.Time { return asOf }}.Run(context.Background())
	must(t, err)
	recs, err := svc.List(context.Background(), w.tat, rightsize.Filter{State: "open"})
	must(t, err)
	return res, recs
}

func TestK8sOffHoursSchedulesNonProdWorkload(t *testing.T) {
	w := k8sOffHoursWorld(t, "dev")
	res, recs := k8sOffHours(t, w)
	if res.Raised != 1 || len(recs) != 1 {
		t.Fatalf("result %+v recs %+v", res, recs)
	}
	r := recs[0]
	if r.Provider != "k8s" || r.ResourceType != "k8s_workload" || r.Action != "schedule" || r.ResourceID != "dev-tke/tat-crm/api" ||
		r.Fingerprint != rightsize.Fingerprint("k8s", "dev-tke/tat-crm/api", "schedule") {
		t.Fatalf("rec %+v", r)
	}
	s, _ := r.Recommended["schedule"].(map[string]any)
	// Busy 09–18 local; an hour's warm-up: on 08:00–18:00 Mon–Fri = 50 h/week, off 118 h.
	if s["start"] != "08:00" || s["stop"] != "18:00" || s["days"] != "Mon–Fri" || s["timezone"] != "Asia/Bangkok" || s["weekends_off"] != true {
		t.Fatalf("schedule %v", r.Recommended)
	}
	if r.Current["replicas"] != float64(2) || r.Evidence["workload"] != "api" || r.Evidence["off_hours_per_week"] != float64(118) ||
		r.Evidence["conditional_on"] != "cluster autoscaler removes idle nodes" {
		t.Fatalf("current %v evidence %v", r.Current, r.Evidence)
	}
	// The workload requests everything in its Environment, so (2 cores + 4 GiB) × 2 replicas
	// at the Environment's unit price is its whole 30 USD/day = 1050 THB/day:
	// 1050 × 30 days × 118/168 off = 22125.00.
	if r.MonthlySavings != "22125.00" || r.Currency != "THB" {
		t.Fatalf("savings %s %s", r.MonthlySavings, r.Currency)
	}
}

func TestK8sOffHoursNeverForProduction(t *testing.T) {
	w := k8sOffHoursWorld(t, "prod")
	res, recs := k8sOffHours(t, w)
	if len(recs) != 0 || res.Skipped["production"] != 1 {
		t.Fatalf("prod got %+v %+v", res, recs)
	}
}
