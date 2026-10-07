package cost_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type world struct {
	s                       *store.Store
	home, tat               string
	project, devEnv, prdEnv string
}

func setup(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s}
	w.home, _ = s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	w.tat, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	var team string
	must(t, s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.home).Scan(&team)
	}))
	must(t, s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tat, team).Scan(&w.project); err != nil {
			return err
		}
		for env, dst := range map[string]*string{"dev": &w.devEnv, "prod": &w.prdEnv} {
			if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, $3) RETURNING id`, w.tat, w.project, env).Scan(dst); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', '200046202634', 'tat-crm-dev')`, w.tat, w.devEnv); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', '200048351622', 'tat-crm-prod')`, w.tat, w.prdEnv)
		return err
	}))
	return w
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) []byte {
	raw, err := os.ReadFile("testdata/tencent-focus-2026-09.csv")
	must(t, err)
	return raw
}

func ingest(t *testing.T, w world, final bool) cost.LoadResult {
	t.Helper()
	lines, err := cost.ParseFOCUS(fixture(t))
	must(t, err)
	res, err := (&cost.Ingester{Store: w.s}).Load(context.Background(), cost.Load{
		Provider: "tencent", BillingAccountID: "200045645249", BillingPeriod: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Source: "cos://bills/tencent-focus-2026-09.csv", Final: final, Lines: lines,
	})
	must(t, err)
	return res
}

func sum(t *testing.T, w world, tenant, where string, args ...any) string {
	t.Helper()
	var v string
	must(t, w.s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT coalesce(sum(billed_cost), 0)::text FROM cost_facts WHERE current AND `+where, args...).Scan(&v)
	}))
	return v
}

func TestLoadAllocatesByCloudAccount(t *testing.T) {
	w := setup(t)
	res := ingest(t, w, false)
	if res.Lines != 9 || res.Allocated != 7 || res.Unallocated != 2 {
		t.Fatalf("result %+v", res)
	}
	if got := sum(t, w, w.tat, "environment_id = $1", w.devEnv); got != "2.40" {
		t.Errorf("dev billed = %s, want 2.40", got)
	}
	if got := sum(t, w, w.tat, "environment_id = $1", w.prdEnv); got != "40.40" {
		t.Errorf("prod billed = %s, want 40.40", got)
	}
	if got := sum(t, w, w.tat, "project_id = $1", w.project); got != "42.80" {
		t.Errorf("project billed = %s, want 42.80", got)
	}
	// Unknown member account lands in the home Tenant, unallocated.
	if got := sum(t, w, w.home, "allocation_method = 'unallocated'"); got != "4.00" {
		t.Errorf("unallocated = %s, want 4.00", got)
	}
	// Tenants see only their own facts.
	if got := sum(t, w, w.tat, "sub_account_id = '200099999999'"); got != "0" {
		t.Errorf("TAT sees unallocated home rows: %s", got)
	}
}

func TestReloadSupersedesAndFinalFreezes(t *testing.T) {
	w := setup(t)
	ingest(t, w, false)
	ingest(t, w, false)
	if got := sum(t, w, w.tat, "true"); got != "42.80" {
		t.Fatalf("after reload billed = %s, want 42.80 (not doubled)", got)
	}
	var history int
	must(t, w.s.InTenant(context.Background(), w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM cost_facts WHERE NOT current`).Scan(&history)
	}))
	if history != 7 {
		t.Errorf("superseded rows kept = %d, want 7 (history is retained)", history)
	}
	ingest(t, w, true)
	lines, _ := cost.ParseFOCUS(fixture(t))
	_, err := (&cost.Ingester{Store: w.s}).Load(context.Background(), cost.Load{
		Provider: "tencent", BillingAccountID: "200045645249", BillingPeriod: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Lines: lines,
	})
	if !errors.Is(err, cost.ErrPeriodFinal) {
		t.Fatalf("load after final: err = %v, want ErrPeriodFinal", err)
	}
}

func TestDailyCostAndUnallocatedKPI(t *testing.T) {
	w := setup(t)
	ingest(t, w, false)
	q := cost.Queries{Store: w.s}
	from, to := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	rows, err := q.Daily(context.Background(), w.tat, cost.DailyFilter{From: from, To: to})
	must(t, err)
	// day 1: dev 1.20, prod 4.80+0.40+30.00 ; day 2: dev 1.20, prod 5.20
	got := map[string]string{}
	for _, r := range rows {
		got[r.Day.Format("02")+"/"+r.EnvironmentName] = r.Billed
	}
	want := map[string]string{"01/dev": "1.20", "01/prod": "35.20", "02/dev": "1.20", "02/prod": "5.20"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all %v)", k, got[k], v, got)
		}
	}
	kpi, err := q.Unallocated(context.Background(), w.home, from, to)
	must(t, err)
	if kpi.Unallocated != "4.00" || kpi.Total != "46.80" || kpi.Percent < 8.5 || kpi.Percent > 8.6 {
		t.Errorf("kpi %+v", kpi)
	}
}
