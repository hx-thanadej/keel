package controls_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/controls"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestRegistryLoadsAndEveryCoverageQueryRuns(t *testing.T) {
	r, err := controls.Load()
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "keel-controls@1" || len(r.Controls) < 20 {
		t.Fatalf("%s %d", r.Version, len(r.Controls))
	}
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		var svc string
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'CRM API') RETURNING id`, tenant, project, team).Scan(&svc); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO scan_runs (tenant_id, service_id, tool, scope, results, raised, resolved, uploaded_by) VALUES ($1, $2, 'grype', 'full', 0, 0, 0, 'p')`, tenant, svc)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rep, err := controls.Service{Store: s, Registry: r}.Report(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]controls.ControlView{}
	for _, c := range rep.Controls {
		byID[c.ID] = c
	}
	if rep.Services != 1 || byID["PW.7.2"].Gap || !byID["SLSA-BUILD-L3"].Gap || !byID["PO.1.1"].Gap {
		t.Fatalf("services %d PW.7.2 %+v SLSA-L3 %+v PO.1.1 %+v", rep.Services, byID["PW.7.2"], byID["SLSA-BUILD-L3"], byID["PO.1.1"])
	}
}
