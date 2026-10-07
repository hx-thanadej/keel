package rightsize_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/rightsize"
)

// A VM costing 4 USD/day until it is resized on Sep 15, then 1 USD/day.
func savingsWorld(t *testing.T) (world, string) {
	w := k8sWorld(t)
	ctx := context.Background()
	var lines []cost.Line
	for d := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC); d.Before(time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)); d = d.AddDate(0, 0, 1) {
		amt := "4.00"
		if !d.Before(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)) {
			amt = "1.00"
		}
		lines = append(lines, cost.Line{SubAccountID: "prod-uin", BillingPeriodStart: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), ChargePeriodStart: d, ChargePeriodEnd: d.AddDate(0, 0, 1),
			ChargeCategory: "Usage", BilledCost: amt, BillingCurrency: "USD", ServiceName: "Cloud Virtual Machine", ResourceID: "ins-big", Tags: map[string]string{}, Vendor: map[string]string{}})
	}
	_, err := (&cost.Ingester{Store: w.s}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: "payer-sav", BillingPeriod: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Lines: lines})
	must(t, err)
	svc := rightsize.Service{Store: w.s}
	vm, _, err := svc.Upsert(ctx, w.tat, rightsize.Recommendation{Source: "engine:vm", Provider: "tencent", ResourceID: "ins-big", ResourceType: "vm", ProjectID: &w.project, EnvironmentID: &w.prod,
		Action: "resize", Recommended: map[string]any{"instance_type": "S5.MEDIUM4"}, MonthlySavings: "3150.00", Currency: "THB", Confidence: 0.9})
	must(t, err)
	must(t, svc.MarkApplied(rightsize.WithAppliedAt(ctx, time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)), w.tat, vm.ID, "resized", "", by))
	return w, vm.ID
}

func TestSavingsMeasuredForResourcesWithTheirOwnCost(t *testing.T) {
	w, id := savingsWorld(t)
	ctx := context.Background()
	tr := rightsize.Tracker{Service: rightsize.Service{Store: w.s}, Now: func() time.Time { return time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC) }}
	res, err := tr.Run(ctx)
	must(t, err)
	if res.Updated != 1 {
		t.Fatalf("result %+v", res)
	}
	r, err := tr.Service.Get(ctx, w.tat, id)
	must(t, err)
	// (4 − 1) USD/day × 30 × 35 THB/USD = 3150.00 measured.
	var realised, method string
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT realised_savings::text, realised_method FROM recommendations WHERE id = $1`, r.ID).Scan(&realised, &method)
	}))
	if realised != "3150.00" || method != "measured" {
		t.Fatalf("realised %s %s", realised, method)
	}
	sum, err := tr.Summary(ctx, w.tat, "")
	must(t, err)
	if sum.Applied != "3150.00" || sum.Realised != "3150.00" || sum.Currency != "THB" || len(sum.Items) != 1 {
		t.Fatalf("summary %+v", sum)
	}
}

func TestSavingsWaitForAWeekOfData(t *testing.T) {
	w, _ := savingsWorld(t)
	tr := rightsize.Tracker{Service: rightsize.Service{Store: w.s}, Now: func() time.Time { return time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC) }}
	res, err := tr.Run(context.Background())
	must(t, err)
	if res.Updated != 0 || res.Waiting != 1 {
		t.Fatalf("4 days after apply: %+v", res)
	}
}

func TestEstimatedForKubernetesAndRegressionFlagged(t *testing.T) {
	w := k8sWorld(t)
	ctx := context.Background()
	svc := rightsize.Service{Store: w.s}
	k, _, err := svc.Upsert(ctx, w.tat, rightsize.Recommendation{Source: "engine:k8s", Provider: "k8s", ResourceID: "tke/ns/api/app", ResourceType: "k8s_workload", ProjectID: &w.project, EnvironmentID: &w.prod,
		Action: "resize_requests", Recommended: map[string]any{"cpu": "410m"}, MonthlySavings: "21516.00", Currency: "THB", Confidence: 0.9})
	must(t, err)
	must(t, svc.MarkApplied(rightsize.WithAppliedAt(ctx, time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)), w.tat, k.ID, "merged", "https://github.com/hx/x/pull/1", by))
	// A week later the engine says the workload is now under-provisioned.
	_, _, err = svc.Upsert(ctx, w.tat, rightsize.Recommendation{Source: "engine:k8s", Provider: "k8s", ResourceID: "tke/ns/api/app", ResourceType: "k8s_workload", ProjectID: &w.project, EnvironmentID: &w.prod,
		Action: "resize_requests", Recommended: map[string]any{"cpu": "600m"}, MonthlySavings: "-3000.00", Currency: "THB", Confidence: 0.9,
		Risk: map[string]any{"under_provisioned": true}, ObservedAt: time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)})
	must(t, err)
	tr := rightsize.Tracker{Service: svc, Now: func() time.Time { return time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC) }}
	_, err = tr.Run(ctx)
	must(t, err)
	var realised, method, regression string
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT realised_savings::text, realised_method, coalesce(regression, '') FROM recommendations WHERE id = $1`, k.ID).Scan(&realised, &method, &regression)
	}))
	if realised != "21516.00" || method != "estimated" || regression == "" {
		t.Fatalf("realised %s %s regression %q", realised, method, regression)
	}
}
