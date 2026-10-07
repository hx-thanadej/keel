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

// A dev VM busy 09:00–18:00 Bangkok on weekdays (02:00–11:00 UTC), idle otherwise,
// costing 2.40 USD/day pay-as-you-go (0.10 USD/hour).
func offHoursWorld(t *testing.T, env string, weekends bool) (world, string) {
	w := k8sWorld(t)
	ctx := context.Background()
	var envID string
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		if env == "prod" {
			envID = w.prod
		} else if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, $3) RETURNING id::text`, w.tat, w.project, env).Scan(&envID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', $3, $3) ON CONFLICT DO NOTHING`, w.tat, envID, env+"-uin")
		return err
	}))
	var lines []cost.Line
	var sums []utilisation.Summary
	for i := 1; i <= 14; i++ {
		d := asOf.AddDate(0, 0, -i)
		lines = append(lines, cost.Line{SubAccountID: env + "-uin", BillingPeriodStart: time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC), ChargePeriodStart: d, ChargePeriodEnd: d.AddDate(0, 0, 1),
			ChargeCategory: "Usage", ChargeFrequency: "Usage-Based", BilledCost: "2.40", BillingCurrency: "USD", ServiceName: "Cloud Virtual Machine", ResourceID: "ins-dev", Tags: map[string]string{}, Vendor: map[string]string{}})
		hourly := make([]float64, 24)
		for h := range hourly {
			hourly[h] = 1.5
			weekday := d.Weekday() != time.Saturday && d.Weekday() != time.Sunday
			if h >= 2 && h < 11 && (weekday || weekends) {
				hourly[h] = 60
			}
		}
		s := utilisation.Summarize(hourly)
		s.Provider, s.ResourceID, s.ResourceType, s.Metric, s.Day, s.Hourly = "tencent", "ins-dev", "vm", "cpu_pct", d, hourly
		sums = append(sums, s)
	}
	_, err := (&cost.Ingester{Store: w.s}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: "payer-dev", BillingPeriod: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Lines: lines})
	must(t, err)
	project := w.project
	must(t, utilisation.Store{Store: w.s}.Save(ctx, w.tat, &project, &envID, sums))
	return w, envID
}

func offHours(t *testing.T, w world) (rightsize.OffHoursResult, []rightsize.Recommendation) {
	t.Helper()
	svc := rightsize.Service{Store: w.s}
	res, err := rightsize.OffHoursEngine{Service: svc, Now: func() time.Time { return asOf }}.Run(context.Background())
	must(t, err)
	recs, err := svc.List(context.Background(), w.tat, rightsize.Filter{State: "open"})
	must(t, err)
	var out []rightsize.Recommendation
	for _, r := range recs {
		if r.Action == "schedule" {
			out = append(out, r)
		}
	}
	return res, out
}

func TestOffHoursScheduleInTenantTimeZone(t *testing.T) {
	w, _ := offHoursWorld(t, "dev", false)
	_, recs := offHours(t, w)
	if len(recs) != 1 {
		t.Fatalf("recs %+v", recs)
	}
	r := recs[0]
	// Busy 09–18 local; start an hour early to warm up: on 08:00–18:00 Mon–Fri = 50 h/week, off 118 h.
	if r.Recommended["schedule"] != "Mon–Fri 08:00–18:00 Asia/Bangkok, off at weekends" || r.Evidence["off_hours_per_week"] != float64(118) {
		t.Fatalf("recommended %v evidence %v", r.Recommended, r.Evidence)
	}
	// 0.10 USD/h × 118 h/week × 30/7 × 35 THB/USD = 1770.00.
	if r.MonthlySavings != "1770.00" || r.Currency != "THB" {
		t.Fatalf("savings %s %s", r.MonthlySavings, r.Currency)
	}
}

func TestOffHoursWeekendsStayOnWhenBusy(t *testing.T) {
	w, _ := offHoursWorld(t, "staging", true)
	_, recs := offHours(t, w)
	if len(recs) != 1 || recs[0].Recommended["schedule"] != "Daily 08:00–18:00 Asia/Bangkok" {
		t.Fatalf("recs %+v", recs)
	}
}

func TestOffHoursNeverForProduction(t *testing.T) {
	w, _ := offHoursWorld(t, "prod", false)
	res, recs := offHours(t, w)
	if len(recs) != 0 || res.Skipped["production"] != 1 {
		t.Fatalf("prod got %+v %+v", res, recs)
	}
}

func TestOffHoursUsesTenantTimeZone(t *testing.T) {
	w, _ := offHoursWorld(t, "dev", false)
	must(t, w.s.InTenant(context.Background(), w.tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE tenants SET time_zone = 'Asia/Tokyo' WHERE id = $1`, w.tat)
		return err
	}))
	_, recs := offHours(t, w)
	if len(recs) != 1 || recs[0].Recommended["schedule"] != "Mon–Fri 10:00–20:00 Asia/Tokyo, off at weekends" {
		t.Fatalf("recs %+v", recs)
	}
}
