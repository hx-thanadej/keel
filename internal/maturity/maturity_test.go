package maturity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/dora"
	"github.com/hx-thanadej/keel/internal/maturity"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestQuestionnaireIsVersionedAndComplete(t *testing.T) {
	q, err := maturity.Load()
	if err != nil {
		t.Fatal(err)
	}
	if q.Version != "keel-maturity@1" || len(q.Aspects) != 5 || len(q.Levels) != 4 {
		t.Fatalf("%+v", q)
	}
}

func TestQuarters(t *testing.T) {
	if got := maturity.Quarter(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)); got != "2026-Q4" {
		t.Fatal(got)
	}
	s, err := maturity.QuarterStart("2026-Q2")
	if err != nil || !s.Equal(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal(s, err)
	}
	if _, err := maturity.QuarterStart("2026-Q5"); !errors.Is(err, maturity.ErrInvalid) {
		t.Fatal(err)
	}
}

func answers(level int) map[string]maturity.Answer {
	out := map[string]maturity.Answer{}
	for _, a := range []string{"investment", "adoption", "interfaces", "operations", "measurement"} {
		out[a] = maturity.Answer{Level: level}
	}
	return out
}

func TestAssessmentLifecycle(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project, env string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-p', 'P') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&env); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'dev')`, tenant, project); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO flows (tenant_id, kind, subject, state, created_by) VALUES ($1, 'vend_environment_tencent', $2, 'succeeded', 'u')`, tenant, "environment/"+env+"/tencent"); err != nil {
			return err
		}
		for i, tmpl := range []string{"go", "go", "go", ""} {
			if _, err := tx.Exec(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, template) VALUES ($1, $2, $3, $4, 'S', $5)`, tenant, project, team, "svc-"+string(rune('a'+i)), tmpl); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC) // day 72 of Q3
	svc := maturity.Service{Store: s, DORA: dora.Service{Store: s}, Now: func() time.Time { return now }}

	ind, err := svc.Measure(ctx, tenant, "2026-Q3")
	if err != nil {
		t.Fatal(err)
	}
	if *ind.TemplateAdoption != 0.75 || ind.Suggested["adoption"] != 3 || *ind.SelfServiceEnvs != 0.5 || ind.Suggested["interfaces"] != 3 {
		t.Fatalf("%+v", ind)
	}

	n, err := svc.Remind(ctx)
	if err != nil || n != 1 {
		t.Fatalf("remind %d %v", n, err)
	}
	if n, _ := svc.Remind(ctx); n != 0 {
		t.Fatalf("second remind opened %d", n)
	}

	by := activity.Actor{Type: activity.ActorHuman, UID: "user:lead@tat.or.th"}
	bad := answers(2)
	delete(bad, "operations")
	if _, err := svc.Submit(ctx, tenant, "2026-Q3", bad, by); !errors.Is(err, maturity.ErrInvalid) {
		t.Fatalf("missing aspect: %v", err)
	}
	if _, err := svc.Submit(ctx, tenant, "2026-Q4", answers(2), by); !errors.Is(err, maturity.ErrInvalid) {
		t.Fatalf("future quarter: %v", err)
	}
	if _, err := svc.Submit(ctx, tenant, "2026-Q2", answers(1), by); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Submit(ctx, tenant, "2026-Q3", answers(2), by); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Submit(ctx, tenant, "2026-Q3", answers(3), by); err != nil { // resubmit replaces
		t.Fatal(err)
	}
	trend, err := svc.List(ctx, tenant)
	if err != nil || len(trend) != 2 || trend[0].Quarter != "2026-Q2" || trend[1].Answers["adoption"].Level != 3 || trend[1].Version != "keel-maturity@1" {
		t.Fatalf("%+v %v", trend, err)
	}
	var open int
	_ = s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE kind = 'maturity_assessment_due' AND status = 'open'`).Scan(&open)
	})
	if open != 0 {
		t.Fatal("reminder not resolved by the submission")
	}
}
