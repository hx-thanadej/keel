package anomaly_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/anomaly"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type world struct {
	s                        *store.Store
	home, tat, team, project string
	prod                     string
}

func setup(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s}
	w.home, _ = s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	w.tat, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	must(t, s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.home).Scan(&w.team); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO fx_rates (tenant_id, day, currency, per_eur) VALUES ($1, '2026-01-01', 'USD', 1)`, w.home)
		return err
	}))
	must(t, s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tat, w.team).Scan(&w.project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, w.tat, w.project).Scan(&w.prod); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', 'prod-uin', 'prod')`, w.tat, w.prod)
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

var start = storetest.Epoch

// load writes `days` days of spend: 2 CVM instances at 50 USD/day, plus
// NAT gateway at 10/day; spike adds NAT egress on given days.
func load(t *testing.T, w world, days int, spike map[int]string) {
	t.Helper()
	var lines []cost.Line
	line := func(d time.Time, svc, res, amt string) cost.Line {
		return cost.Line{SubAccountID: "prod-uin", BillingPeriodStart: time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC), ChargePeriodStart: d, ChargePeriodEnd: d.AddDate(0, 0, 1),
			ChargeCategory: "Usage", BilledCost: amt, BillingCurrency: "USD", ServiceName: svc, ResourceID: res, Tags: map[string]string{}, Vendor: map[string]string{}}
	}
	for i := 0; i < days; i++ {
		d := start.AddDate(0, 0, i)
		lines = append(lines, line(d, "Cloud Virtual Machine", "ins-a", "50"), line(d, "Cloud Virtual Machine", "ins-b", "50"), line(d, "NAT Gateway", "nat-1", "10"))
		if extra, ok := spike[i]; ok {
			lines = append(lines, line(d, "NAT Gateway", "nat-2", extra))
		}
	}
	byPeriod := map[time.Time][]cost.Line{}
	for _, l := range lines {
		byPeriod[l.BillingPeriodStart] = append(byPeriod[l.BillingPeriodStart], l)
	}
	for p, ls := range byPeriod {
		_, err := (&cost.Ingester{Store: w.s}).Load(context.Background(), cost.Load{Provider: "tencent", BillingAccountID: "payer", BillingPeriod: p, Lines: ls})
		must(t, err)
	}
}

func findings(t *testing.T, w world) []map[string]any {
	t.Helper()
	var out []map[string]any
	must(t, w.s.InTenant(context.Background(), w.tat, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT status, severity, title, detail, owner_team_id::text, environment_id::text FROM findings WHERE kind = 'cost_anomaly' ORDER BY first_seen_at`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var st, sev, title, team, env string
			var detail map[string]any
			if err := rows.Scan(&st, &sev, &title, &detail, &team, &env); err != nil {
				return err
			}
			out = append(out, map[string]any{"status": st, "severity": sev, "title": title, "detail": detail, "team": team, "env": env})
		}
		return rows.Err()
	}))
	return out
}

func TestSpikeRaisesFindingWithTopResources(t *testing.T) {
	w := setup(t)
	load(t, w, 41, map[int]string{40: "300"}) // day 40 = 2031-02-10: NAT 10 → 310
	r := anomaly.Runner{Store: w.s, Now: func() time.Time { return start.AddDate(0, 0, 41).Add(3 * time.Hour) }}
	raised, err := r.Run(context.Background())
	must(t, err)
	if raised.Raised != 1 {
		t.Fatalf("raised %+v", raised)
	}
	fs := findings(t, w)
	if len(fs) != 1 {
		t.Fatalf("findings %v", fs)
	}
	f := fs[0]
	d := f["detail"].(map[string]any)
	if f["status"] != "open" || f["severity"] != "critical" || f["team"] != w.team || f["env"] != w.prod ||
		d["service"] != "NAT Gateway" || d["day"] != "2031-02-10" || d["actual"] != "310.00" || d["expected"] != "10.00" {
		t.Fatalf("finding %+v", f)
	}
	top := d["top_resources"].([]any)
	if len(top) == 0 || top[0].(map[string]any)["resource_id"] != "nat-2" || top[0].(map[string]any)["delta"] != "300.00" {
		t.Fatalf("top resources %v", top)
	}
	// CVM did not change: no finding for it. Re-running does not duplicate.
	again, err := r.Run(context.Background())
	must(t, err)
	if again.Raised != 0 || len(findings(t, w)) != 1 {
		t.Fatalf("re-run raised again %+v", again)
	}
	var acts int
	must(t, w.s.InTenant(context.Background(), w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM activities WHERE type = 'keel.finding.raised'`).Scan(&acts)
	}))
	if acts != 1 {
		t.Errorf("raised activities %d", acts)
	}
}

func TestAutoResolveAfterThreeNormalDays(t *testing.T) {
	w := setup(t)
	load(t, w, 44, map[int]string{40: "300"})
	at := func(day int) func() time.Time {
		return func() time.Time { return start.AddDate(0, 0, day).Add(3 * time.Hour) }
	}
	r := anomaly.Runner{Store: w.s, Now: at(41)}
	_, err := r.Run(context.Background())
	must(t, err)
	r.Now = at(43) // only days 41,42 normal
	res, err := r.Run(context.Background())
	must(t, err)
	if res.Resolved != 0 {
		t.Fatalf("resolved too early %+v", res)
	}
	r.Now = at(44) // days 41..43 normal
	res, err = r.Run(context.Background())
	must(t, err)
	if res.Resolved != 1 || findings(t, w)[0]["status"] != "resolved" {
		t.Fatalf("not auto-resolved %+v %v", res, findings(t, w))
	}
	storetest.ClockedFindings(t, w.s, "cost_anomaly")
}

func TestSteadySpendRaisesNothing(t *testing.T) {
	w := setup(t)
	load(t, w, 45, nil)
	res, err := (&anomaly.Runner{Store: w.s, Now: func() time.Time { return start.AddDate(0, 0, 45) }}).Run(context.Background())
	must(t, err)
	if res.Raised != 0 {
		t.Fatalf("steady spend raised %+v", res)
	}
}
