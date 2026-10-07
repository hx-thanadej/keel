package scorecard_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/scorecard"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestScorecards(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var good, bare string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project, env, rel string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&env); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository, repository_id, template) VALUES ($1, $2, $3, 'crm-api', 'API', 'https://github.com/acme/crm-api', 900, 'go-service') RETURNING id`, tenant, project, team).Scan(&good); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'legacy', 'Legacy') RETURNING id`, tenant, project, team).Scan(&bare); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO releases (tenant_id, service_id, version, images, created_by) VALUES ($1, $2, '1', '[{"name":"a","digest":"sha256:x"}]', 'p') RETURNING id`, tenant, good).Scan(&rel); err != nil {
			return err
		}
		for _, q := range []string{
			`INSERT INTO release_attestations (tenant_id, release_id, image_digest, passed, checks, bundle_sha256, vsa, submitted_by) VALUES ($1, $2, 'sha256:x', true, '[]', 'b', '{}', 'p')`,
			`INSERT INTO release_sboms (tenant_id, release_id, format, spec_version, components, submitted_by) VALUES ($1, $2, 'CycloneDX', '1.6', 1, 'p')`,
		} {
			if _, err := tx.Exec(ctx, q, tenant, rel); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scan_runs (tenant_id, service_id, tool, scope, results, raised, resolved, uploaded_by) VALUES ($1, $2, 'grype', 'full', 0, 0, 0, 'p')`, tenant, good); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO promotions (tenant_id, release_id, environment_id, state, requested_by, deployed_at) VALUES ($1, $2, $3, 'deployed', 'u', now())`, tenant, rel, env); err != nil {
			return err
		}
		// The legacy service has an overdue critical Finding.
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, service_id, first_seen_at) VALUES ($1, 'vulnerability', 'v', 'critical', 'CVE', $2, now() - interval '30 days')`, tenant, bare)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	svc := scorecard.Service{Store: s}
	rep, err := svc.Compute(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]scorecard.Card{}
	for _, c := range rep.Cards {
		byName[c.Service] = c
	}
	if byName["crm-api"].Score != 100 {
		t.Fatalf("crm-api %+v", byName["crm-api"])
	}
	failing := map[string]string{}
	for _, r := range byName["legacy"].Results {
		if !r.Pass {
			failing[r.Name] = r.Why
		}
	}
	if byName["legacy"].Score != 11 || failing["findings_sla"] != "has overdue Findings" || failing["critical_findings"] == "" || len(failing) != 8 {
		t.Fatalf("legacy %d %v", byName["legacy"].Score, failing)
	}
	if len(rep.Teams) != 1 || rep.Teams[0].Score != 55 || rep.Score != 55 {
		t.Fatalf("roll-up %+v %d", rep.Teams, rep.Score)
	}
	// Snapshots give a trend: 31 days ago the legacy service scored 0.
	svc.Now = func() time.Time { return time.Now().AddDate(0, 0, -31) }
	if n, err := svc.Snapshot(ctx); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	rep, _ = (scorecard.Service{Store: s}).Compute(ctx, tenant)
	for _, c := range rep.Cards {
		if c.Previous == nil {
			t.Fatalf("no previous score for %s", c.Service)
		}
	}
}
