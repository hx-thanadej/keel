package rightsize_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/rightsize"
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
		return tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.home).Scan(&w.team)
	}))
	must(t, s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE tenants SET currency = 'THB' WHERE id = $1`, w.tat); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tat, w.team).Scan(&w.project); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, w.tat, w.project).Scan(&w.prod)
	}))
	return w
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func rec(w world, target string, savings string) rightsize.Recommendation {
	return rightsize.Recommendation{
		Source: "engine:k8s", Provider: "tencent", AccountID: "200048351622", ResourceID: "tke-prod/tat-crm/deploy/api", ResourceType: "k8s_workload",
		ProjectID: &w.project, EnvironmentID: &w.prod, Action: "resize_requests",
		Current:        map[string]any{"cpu": "2000m", "memory": "4Gi"},
		Recommended:    map[string]any{"cpu": target, "memory": "1536Mi"},
		Evidence:       map[string]any{"lookback_days": 21, "samples": 30240, "cpu_p95": "410m", "mem_max": "1.3Gi", "method": "krr_simple"},
		MonthlySavings: savings, Currency: "THB", SavingsBasis: "effective", Confidence: 0.9,
		Risk: map[string]any{"performance": "low", "reversible": true},
	}
}

var by = activity.Actor{Type: activity.ActorHuman, UID: "user:lead@harmonyx.co"}

func TestUpsertCreatesRecommendationAndFinding(t *testing.T) {
	w := setup(t)
	svc := rightsize.Service{Store: w.s}
	ctx := context.Background()
	r, changed, err := svc.Upsert(ctx, w.tat, rec(w, "500m", "1200.00"))
	must(t, err)
	if !changed || r.State != "open" || r.FindingID == "" {
		t.Fatalf("rec %+v changed=%v", r, changed)
	}
	var kind, sev, status, team, title string
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT kind, severity, status, owner_team_id::text, title FROM findings WHERE id = $1`, r.FindingID).Scan(&kind, &sev, &status, &team, &title)
	}))
	if kind != "rightsizing" || sev != "high" || status != "open" || team != w.team || title == "" {
		t.Fatalf("finding %s %s %s %s %q", kind, sev, status, team, title)
	}
	// Same recommendation again: refreshed, not duplicated.
	r2, changed, err := svc.Upsert(ctx, w.tat, rec(w, "500m", "1180.00"))
	must(t, err)
	if changed || r2.ID != r.ID {
		t.Fatalf("re-upsert created a new record: %+v", r2)
	}
}

func TestChangedTargetSupersedes(t *testing.T) {
	w := setup(t)
	svc := rightsize.Service{Store: w.s}
	ctx := context.Background()
	r1, _, err := svc.Upsert(ctx, w.tat, rec(w, "500m", "1200.00"))
	must(t, err)
	r2, changed, err := svc.Upsert(ctx, w.tat, rec(w, "300m", "1500.00"))
	must(t, err)
	if !changed || r2.ID == r1.ID {
		t.Fatal("changed target must create a new recommendation")
	}
	open, err := svc.List(ctx, w.tat, rightsize.Filter{State: "open"})
	must(t, err)
	if len(open) != 1 || open[0].ID != r2.ID {
		t.Fatalf("open = %+v", open)
	}
	all, _ := svc.List(ctx, w.tat, rightsize.Filter{})
	if len(all) != 2 {
		t.Fatalf("history lost: %d", len(all))
	}
}

func TestDismissSticksUnlessEvidenceChangesMaterially(t *testing.T) {
	w := setup(t)
	svc := rightsize.Service{Store: w.s}
	ctx := context.Background()
	r, _, err := svc.Upsert(ctx, w.tat, rec(w, "500m", "1200.00"))
	must(t, err)
	if _, err := svc.Dismiss(ctx, w.tat, r.ID, "", by); err == nil {
		t.Fatal("dismiss without reason accepted")
	}
	_, err = svc.Dismiss(ctx, w.tat, r.ID, "batch peaks every quarter-end", by)
	must(t, err)
	var fstatus string
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, r.FindingID).Scan(&fstatus)
	}))
	if fstatus != "resolved" {
		t.Errorf("finding after dismiss = %s", fstatus)
	}
	// Same advice next run: stays dismissed.
	_, changed, err := svc.Upsert(ctx, w.tat, rec(w, "500m", "1250.00"))
	must(t, err)
	if changed {
		t.Fatal("dismissed recommendation came back with unchanged evidence")
	}
	// Savings up >20%: material change, raised again.
	_, changed, err = svc.Upsert(ctx, w.tat, rec(w, "500m", "1600.00"))
	must(t, err)
	if !changed {
		t.Fatal("materially different recommendation stayed dismissed")
	}
}

func TestAcceptRecordsActivity(t *testing.T) {
	w := setup(t)
	svc := rightsize.Service{Store: w.s}
	ctx := context.Background()
	r, _, err := svc.Upsert(ctx, w.tat, rec(w, "500m", "80.00"))
	must(t, err)
	a, err := svc.Accept(ctx, w.tat, r.ID, by)
	must(t, err)
	if a.State != "accepted" {
		t.Fatalf("state %s", a.State)
	}
	if _, err := svc.Accept(ctx, w.tat, r.ID, by); err == nil {
		t.Fatal("accepting twice should fail")
	}
	var n int
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM activities WHERE type IN ('keel.recommendation.raised', 'keel.recommendation.accepted')`).Scan(&n)
	}))
	if n != 2 {
		t.Errorf("activities %d", n)
	}
	var sev string
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT severity FROM findings WHERE id = $1`, r.FindingID).Scan(&sev)
	}))
	if sev != "low" {
		t.Errorf("80 THB/month severity %s, want low", sev)
	}
}
