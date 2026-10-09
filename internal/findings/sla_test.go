package findings_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/findings"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestDueDatesOverdueAndUnowned(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	clock := storetest.Clock()
	sla := findings.SLA{Store: s, Now: clock}
	home, _ := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var team, crit, stale, low, unowned string
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE tenants SET finding_sla = '{"critical": 3, "high": 14, "medium": 60, "low": 120}' WHERE id = $1`, tat); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tat).Scan(&team); err != nil {
			return err
		}
		ins := `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, owner_team_id, first_seen_at) VALUES ($1, 'vulnerability', $2, $3, $4, $5, $6) RETURNING id`
		if err := tx.QueryRow(ctx, ins, tat, "a", "critical", "CVE-1", team, clock().AddDate(0, 0, -5)).Scan(&crit); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, ins, tat, "b", "low", "lint", team, clock().AddDate(0, 0, -5)).Scan(&low); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, ins, tat, "d", "critical", "CVE-2", team, clock().AddDate(0, 0, -200)).Scan(&stale); err != nil {
			return err
		}
		return tx.QueryRow(ctx, ins, tat, "c", "high", "orphan", nil, clock()).Scan(&unowned)
	}); err != nil {
		t.Fatal(err)
	}
	due := func(id string) (time.Time, *time.Time) {
		var d time.Time
		var o *time.Time
		if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT due_at, overdue_at FROM findings WHERE id = $1`, id).Scan(&d, &o)
		}); err != nil {
			t.Fatal(err)
		}
		return d, o
	}
	if d, _ := due(crit); d.Sub(clock()) > -47*time.Hour || d.Sub(clock()) < -49*time.Hour {
		t.Fatalf("critical due %v (Tenant SLA 3 days from 5 days ago)", d)
	}
	res, err := sla.Run(ctx)
	if err != nil || res.Overdue != 2 || res.Unowned != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, o := due(crit); o == nil {
		t.Fatal("critical not flagged overdue")
	}
	if _, o := due(low); o != nil {
		t.Fatal("low flagged overdue")
	}
	storetest.ClockedFindings(t, s, "vulnerability")
	// Running again does not re-flag.
	if res, _ := sla.Run(ctx); res.Overdue != 0 {
		t.Fatalf("re-flagged %+v", res)
	}
	var title string
	if err := s.InTenant(ctx, home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT title FROM findings WHERE kind = 'unowned_findings' AND status = 'open'`).Scan(&title)
	}); err != nil || title != "1 Findings in Tenant tat have no owning Team" {
		t.Fatalf("unowned %q %v", title, err)
	}
	// Assign an owner; the platform Finding resolves.
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = 'routed' WHERE id = $1`, unowned, clock())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sla.Run(ctx); err != nil {
		t.Fatal(err)
	}
	var open int
	if err := s.InTenant(ctx, home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE kind = 'unowned_findings' AND status = 'open'`).Scan(&open)
	}); err != nil || open != 0 {
		t.Fatalf("still open %d %v", open, err)
	}
	storetest.ClockedFindings(t, s, "unowned_findings")
}

// Only the SLA run knows the clock, so it alone sets and clears overdue_at
// (#176): a severity change leaves the flag for the next run to judge.
func TestOverdueFlagFollowsTheSLARun(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	clock := storetest.Clock()
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var late, moved string
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE tenants SET finding_sla = '{"critical": 3, "high": 14, "medium": 60, "low": 120}' WHERE id = $1`, tat); err != nil {
			return err
		}
		ins := `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, first_seen_at) VALUES ($1, 'vulnerability', $2, 'critical', $2, $3) RETURNING id`
		if err := tx.QueryRow(ctx, ins, tat, "late", clock().AddDate(0, 0, -20)).Scan(&late); err != nil {
			return err
		}
		return tx.QueryRow(ctx, ins, tat, "moved", clock().AddDate(0, 0, -5)).Scan(&moved)
	}); err != nil {
		t.Fatal(err)
	}
	flag := func(id string) *time.Time {
		t.Helper()
		var o *time.Time
		if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT overdue_at FROM findings WHERE id = $1`, id).Scan(&o)
		}); err != nil {
			t.Fatal(err)
		}
		return o
	}
	run := func(sla findings.SLA, overdue int) {
		t.Helper()
		if res, err := sla.Run(ctx); err != nil || res.Overdue != overdue {
			t.Fatalf("%+v %v, want %d overdue", res, err, overdue)
		}
	}
	sla := findings.SLA{Store: s, Now: clock}
	// A run 16 days ago flags late (due 17 days ago); today's run flags moved (due 2 days ago).
	run(findings.SLA{Store: s, Now: func() time.Time { return clock().AddDate(0, 0, -16) }}, 1)
	run(sla, 1)
	flagged := flag(late)
	if flagged == nil || flag(moved) == nil {
		t.Fatal("not flagged")
	}
	// late's new due date (6 days ago) is after its flag but still past; moved's is 115 days ahead.
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE findings SET severity = 'high' WHERE id = $1`, late); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE findings SET severity = 'low' WHERE id = $1`, moved)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	run(sla, 0)
	run(sla, 0)
	if o := flag(late); o == nil || !o.Equal(*flagged) {
		t.Fatalf("late flag %v, want the original %v", o, flagged)
	}
	if o := flag(moved); o != nil {
		t.Fatalf("moved still flagged at %v though due in the future", o)
	}
	var alerts int
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM activities WHERE type = 'keel.finding.overdue' AND subject = $1`, "finding/"+late).Scan(&alerts)
	}); err != nil || alerts != 1 {
		t.Fatalf("%d keel.finding.overdue alerts for late, want 1 (%v)", alerts, err)
	}
	storetest.ClockedFindings(t, s, "vulnerability")
}
