package decisions_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/decisions"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestParseFormats(t *testing.T) {
	madr4 := "---\nstatus: accepted\ndate: 2026-10-06\ndeciders: platform\n---\n\n# Use Postgres row-level security for tenancy\n\n## Context\n..."
	r := decisions.Parse("docs/decisions/0003-rls.md", []byte(madr4))
	if r.Title != "Use Postgres row-level security for tenancy" || r.Status != "accepted" || r.Date != "2026-10-06" || r.Number == nil || *r.Number != 3 {
		t.Fatalf("madr4 %+v", r)
	}
	nygard := "# 2. Use Kafka\n\nDate: 2025-01-02\n\n## Status\n\nSuperseded by [ADR-0007](0007-use-ckafka.md)\n\n## Context\n"
	r = decisions.Parse("docs/decisions/0002-kafka.md", []byte(nygard))
	if r.Title != "Use Kafka" || r.Status != "superseded" || r.SupersededBy != "ADR-0007" || r.Date != "2025-01-02" {
		t.Fatalf("nygard %+v", r)
	}
}

type repo map[string]string

func (r repo) List(_ context.Context, _, _ string) ([]string, error) {
	var out []string
	for p := range r {
		out = append(out, p)
	}
	return out, nil
}
func (r repo) Read(_ context.Context, _, p string) ([]byte, error) { return []byte(r[p]), nil }

func TestIndexRecordsStatusChanges(t *testing.T) {
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
		_, err := tx.Exec(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository) VALUES ($1, $2, $3, 'crm-api', 'API', 'https://github.com/acme/crm-api')`, tenant, project, team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	src := repo{
		"docs/decisions/0001-record-architecture-decisions.md": "# 1. Record architecture decisions\n\n## Status\n\nAccepted\n",
		"docs/decisions/0002-cache.md":                         "---\nstatus: proposed\n---\n# Cache sessions in Redis\n",
		"docs/decisions/README.md":                             "# Decisions",
	}
	ix := decisions.Indexer{Store: s, Source: src}
	res, err := ix.Run(ctx)
	if err != nil || res.Records != 2 || res.Changed != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	src["docs/decisions/0002-cache.md"] = "---\nstatus: accepted\n---\n# Cache sessions in Redis\n"
	if res, _ := ix.Run(ctx); res.Changed != 1 {
		t.Fatalf("status change not recorded %+v", res)
	}
	var detail string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT event->'data'->>'status_detail' FROM activities WHERE type = 'keel.decision.status_changed'`).Scan(&detail)
	}); err != nil || detail != "Cache sessions in Redis: proposed → accepted" {
		t.Fatalf("%q %v", detail, err)
	}
	found, err := decisions.Search(ctx, s, tenant, "redis", "")
	if err != nil || len(found) != 1 || found[0].URL != "https://github.com/acme/crm-api/blob/HEAD/docs/decisions/0002-cache.md" {
		t.Fatalf("%+v %v", found, err)
	}
}
