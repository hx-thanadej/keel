package dora_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/dora"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestDORAFromDeployments(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	h := func(n float64) time.Time { return t0.Add(time.Duration(n * float64(time.Hour))) }
	var promos []string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project, svc, prod, dev string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'CRM API') RETURNING id`, tenant, project, team).Scan(&svc); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&prod); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'dev') RETURNING id`, tenant, project).Scan(&dev); err != nil {
			return err
		}
		// version, release built, requested, deployed, environment
		for i, d := range []struct {
			v               string
			built, req, dep float64
			env             string
		}{
			{"1", 0, 1, 2, prod},       // lead 2h
			{"2", 24, 26, 28, prod},    // lead 4h; fails at 29h
			{"3", 29, 29.5, 31, prod},  // rework (requested 0.5h after the failure); recovery 2h; lead 2h
			{"4", 100, 104, 106, prod}, // lead 6h
			{"5", 100, 101, 102, dev},  // not production
		} {
			var rel, p string
			if err := tx.QueryRow(ctx, `INSERT INTO releases (tenant_id, service_id, version, images, created_by, created_at) VALUES ($1, $2, $3, '[]', 'p', $4) RETURNING id`, tenant, svc, d.v, h(d.built)).Scan(&rel); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `INSERT INTO promotions (tenant_id, release_id, environment_id, state, requested_by, requested_at, deployed_at) VALUES ($1, $2, $3, 'deployed', 'u', $4, $5) RETURNING id`,
				tenant, rel, d.env, h(d.req), h(d.dep)).Scan(&p); err != nil {
				return err
			}
			promos = append(promos, p)
			_ = i
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	svc := dora.Service{Store: s}
	by := activity.Actor{Type: activity.ActorHuman, UID: "user:oncall"}
	if err := svc.MarkFailed(ctx, tenant, promos[1], "500s after deploy; rolled forward", h(29), by); err != nil {
		t.Fatal(err)
	}
	if err := svc.MarkFailed(ctx, tenant, promos[1], "again", h(29), by); !errors.Is(err, dora.ErrNotFound) {
		t.Fatalf("double mark: %v", err)
	}
	rep, err := svc.Compute(ctx, tenant, t0, t0.AddDate(0, 0, 10))
	if err != nil {
		t.Fatal(err)
	}
	m := rep.Tenant
	if m.Deployments != 4 || m.PerDay != 0.4 || *m.LeadTimeHours != 3 || *m.ChangeFailRate != 0.25 || *m.RecoveryHours != 2 || *m.ReworkRate != 0.25 || len(rep.Services) != 1 {
		t.Fatalf("%s / %+v", m, rep.Services)
	}
}
