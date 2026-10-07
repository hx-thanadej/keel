package budget_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestPhasing(t *testing.T) {
	b := budget.Budget{Year: 2026, Amount: "365000"}
	if got := b.MonthAmount(time.September); got != "30000.00" {
		t.Errorf("Sep by days = %s, want 30000.00", got)
	}
	if got := b.DayAmount(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)); got != "1000.00" {
		t.Errorf("day = %s, want 1000.00", got)
	}
	w := budget.Budget{Year: 2026, Amount: "120000", MonthlyWeights: []string{"1", "1", "1", "1", "1", "1", "1", "1", "2", "1", "1", "1"}}
	if got := w.MonthAmount(time.September); got != "18461.54" { // 120000 * 2/13
		t.Errorf("weighted Sep = %s", got)
	}
	if got := w.DayAmount(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)); got != "615.38" { // 18461.538/30
		t.Errorf("weighted day = %s", got)
	}
}

type world struct {
	s                        *store.Store
	home, tat, project, prod string
}

func setup(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s}
	w.home, _ = s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	w.tat, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	var team, dev string
	must(t, s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.home).Scan(&team); err != nil {
			return err
		}
		// USD 1.10 and THB 38.50 per EUR → 1 USD = 35 THB.
		_, err := tx.Exec(ctx, `INSERT INTO fx_rates (tenant_id, day, currency, per_eur) VALUES ($1, '2026-08-31', 'USD', 1.10), ($1, '2026-08-31', 'THB', 38.50)`, w.home)
		return err
	}))
	must(t, s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE tenants SET currency = 'THB' WHERE id = $1`, w.tat); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tat, team).Scan(&w.project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, w.tat, w.project).Scan(&w.prod); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'dev') RETURNING id`, w.tat, w.project).Scan(&dev); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', '200048351622', 'prod'), ($1, $3, 'tencent', '200046202634', 'dev')`, w.tat, w.prod, dev); err != nil {
			return err
		}
		return nil
	}))
	raw, err := os.ReadFile("../cost/testdata/tencent-focus-2026-09.csv")
	must(t, err)
	lines, err := cost.ParseFOCUS(raw)
	must(t, err)
	_, err = (&cost.Ingester{Store: s}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: "200045645249", BillingPeriod: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Lines: lines})
	must(t, err)
	return w
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestStatusMonthSeriesInTenantCurrency(t *testing.T) {
	w := setup(t)
	svc := budget.Service{Store: w.s}
	b, err := svc.Create(context.Background(), w.tat, budget.Budget{ProjectID: w.project, EnvironmentID: &w.prod, Name: "prod 2026", Year: 2026, Amount: "365000"})
	must(t, err)
	if b.Currency != "THB" {
		t.Fatalf("budget currency = %s, want tenant currency THB", b.Currency)
	}
	st, err := svc.Status(context.Background(), w.tat, b.ID, budget.Month, time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
	must(t, err)
	if st.Budget != "30000.00" || st.Currency != "THB" {
		t.Fatalf("month budget %s %s", st.Budget, st.Currency)
	}
	// Effective prod per day: 4.80 CVM + 0.40 COS + 1.00 amortized MySQL = 6.20 USD = 217.00 THB.
	if st.Actual != "434.00" {
		t.Errorf("MTD actual = %s, want 434.00", st.Actual)
	}
	if len(st.Series) != 30 || st.Series[0].Actual != "217.00" || st.Series[1].Actual != "217.00" || st.Series[0].Budget != "1000.00" {
		t.Errorf("series %+v", st.Series[:2])
	}
	if st.Series[2].Actual != "" {
		t.Errorf("days after as-of must have no actual, got %q", st.Series[2].Actual)
	}
	if st.Forecast == "" || st.ForecastMethod != "run_rate" || st.Final {
		t.Errorf("forecast %s %s final=%v", st.Forecast, st.ForecastMethod, st.Final)
	}

	billed := budget.Budget{ProjectID: w.project, EnvironmentID: &w.prod, Name: "billed", Year: 2026, Amount: "365000", CostBasis: "billed", Provider: ptr("tencent")}
	bb, err := svc.Create(context.Background(), w.tat, billed)
	must(t, err)
	st, err = svc.Status(context.Background(), w.tat, bb.ID, budget.Day, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	must(t, err)
	if st.Actual != "1232.00" || st.Budget != "1000.00" { // 35.20 USD billed incl. the prepaid purchase
		t.Errorf("billed day-1 %s / %s", st.Actual, st.Budget)
	}

	yr, err := svc.Status(context.Background(), w.tat, b.ID, budget.Year, time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC))
	must(t, err)
	if yr.Budget != "365000.00" || len(yr.Series) != 12 || yr.Series[8].Actual != "434.00" || yr.Series[9].Actual != "" {
		t.Errorf("year status %s, series %+v", yr.Budget, yr.Series[8:10])
	}
}

func ptr(s string) *string { return &s }

func TestDuplicateScopeRejected(t *testing.T) {
	w := setup(t)
	svc := budget.Service{Store: w.s}
	_, err := svc.Create(context.Background(), w.tat, budget.Budget{ProjectID: w.project, Name: "a", Year: 2026, Amount: "1"})
	must(t, err)
	_, err = svc.Create(context.Background(), w.tat, budget.Budget{ProjectID: w.project, Name: "b", Year: 2026, Amount: "2"})
	if err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("duplicate scope err = %v", err)
	}
}

func TestEvaluateRaisesEachThresholdOnce(t *testing.T) {
	w := setup(t)
	svc := budget.Service{Store: w.s}
	b, err := svc.Create(context.Background(), w.tat, budget.Budget{ProjectID: w.project, EnvironmentID: &w.prod, Name: "tight", Year: 2026, Amount: "36500",
		Thresholds: []budget.Threshold{{Pct: 10, Basis: "actual"}, {Pct: 90, Basis: "actual"}, {Pct: 50, Basis: "forecast"}}})
	must(t, err)
	// Month budget 3000 THB; MTD 434 (14%) crosses 10% actual, not 90%; forecast crosses 50%.
	ev := budget.Evaluator{Service: svc, Now: func() time.Time { return time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC) }}
	alerts, err := ev.EvaluateAll(context.Background())
	must(t, err)
	got := map[string]bool{}
	for _, a := range alerts {
		got[a.Basis+"@"+a.Pct] = true
	}
	if !got["actual@10"] || got["actual@90"] || !got["forecast@50"] || len(alerts) != 2 {
		t.Fatalf("alerts %+v", alerts)
	}
	again, err := ev.EvaluateAll(context.Background())
	must(t, err)
	if len(again) != 0 {
		t.Fatalf("re-evaluation raised again: %+v", again)
	}
	var acts int
	must(t, w.s.InTenant(context.Background(), w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM activities WHERE type = 'keel.budget.threshold_crossed' AND subject = $1`, "budget/"+b.ID).Scan(&acts)
	}))
	if acts != 2 {
		t.Errorf("threshold activities = %d, want 2", acts)
	}
}
