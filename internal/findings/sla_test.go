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
	// Downgrading severity moves the due date and clears overdue, unless the
	// new due date had passed when the Finding was flagged.
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET severity = 'low' WHERE id = ANY ($1)`, []string{crit, stale})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, o := due(crit); o != nil {
		t.Fatal("overdue kept after the due date moved out")
	}
	if d, o := due(stale); o == nil {
		t.Fatalf("overdue cleared though the new due date %v had passed on the service clock", d)
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
