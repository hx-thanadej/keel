package evidence_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/controls"
	"github.com/hx-thanadej/keel/internal/evidence"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func world(t *testing.T) (*store.Store, string, string) {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var svc string
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
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'API') RETURNING id`, tenant, project, team).Scan(&svc); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO releases (tenant_id, service_id, version, images, created_by) VALUES ($1, $2, '1.0', '[{"name":"a","digest":"sha256:aa"}]', 'p') RETURNING id`, tenant, svc).Scan(&rel); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO release_attestations (tenant_id, release_id, image_digest, passed, checks, bundle_sha256, vsa, submitted_by) VALUES ($1, $2, 'sha256:aa', true, '[]', 'b', '{"payloadType":"x"}', 'p')`, tenant, rel); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO promotions (tenant_id, release_id, environment_id, state, requested_by, deployed_at) VALUES ($1, $2, $3, 'deployed', 'u', now())`, tenant, rel, env); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, service_id, project_id, owner_team_id) VALUES ($1, 'vulnerability', $2, 'critical', 'Log4Shell', $3, $4, $5)`,
			tenant, "vuln:CVE-2021-44228:"+svc, svc, project, team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s, tenant, svc
}

func TestEvidenceBundleIsSignedAndTamperEvident(t *testing.T) {
	s, tenant, _ := world(t)
	ctx := context.Background()
	reg, _ := controls.Load()
	pub, key, _ := ed25519.GenerateKey(nil)
	e := evidence.Exporter{Store: s, Controls: controls.Service{Store: s, Registry: reg}, Key: key}
	from, to := time.Now().AddDate(0, 0, -30), time.Now().Add(time.Hour)
	b, err := e.Export(ctx, tenant, from, to, activity.Actor{Type: activity.ActorHuman, UID: "user:auditor"})
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range []string{"controls", "releases", "findings", "exceptions", "access_grants", "activity_chain"} {
		if _, ok := b.Manifest.Sections[sec]; !ok {
			t.Fatalf("missing section %s", sec)
		}
	}
	if !strings.Contains(string(b.Sections["releases"]), `"verified": true`) && !strings.Contains(string(b.Sections["releases"]), `"verified":true`) {
		t.Fatalf("releases %s", b.Sections["releases"])
	}
	// Round trip through JSON as an auditor would receive it.
	raw, _ := json.Marshal(b)
	var got evidence.Bundle
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if err := evidence.Verify(pub, got); err != nil {
		t.Fatalf("clean bundle: %v", err)
	}
	got.Sections["findings"] = json.RawMessage(`{"overdue": 0}`)
	if err := evidence.Verify(pub, got); err == nil {
		t.Fatal("altered section verified")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if err := evidence.Verify(other, b); err == nil {
		t.Fatal("wrong key verified")
	}
}

type kev map[string]bool

func (k kev) Exploited(context.Context) (map[string]bool, error) { return k, nil }

func TestCRAClockStartsOnceForExploitedDeployedVulnerabilities(t *testing.T) {
	s, tenant, _ := world(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	c := evidence.CRA{Store: s, KEV: kev{"CVE-2021-44228": true}, Now: func() time.Time { return now }}
	if n, err := c.Run(ctx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	now = now.Add(time.Hour)
	if n, _ := c.Run(ctx); n != 0 {
		t.Fatal("clock restarted")
	}
	var detail map[string]any
	var raw []byte
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT detail FROM findings WHERE kind = 'cra_report'`).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &detail)
	if detail["early_warning_by"] != "2026-10-08T09:00:00Z" || detail["final_report_by"] != "2026-10-21T09:00:00Z" {
		t.Fatalf("deadlines %v", detail)
	}
}
