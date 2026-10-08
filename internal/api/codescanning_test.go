package api_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// Switching a Service's code scanning source resolves the open code scanning
// Findings of the source it left, and nothing else.
func TestSwitchingCodeScanningSourceResolvesTheOtherSide(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az), Authz: az}))
	t.Cleanup(srv.Close)
	var team, svc string
	if err := s.InTenant(t.Context(), tat, func(tx pgx.Tx) error {
		var project string
		if err := tx.QueryRow(t.Context(), `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tat).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(t.Context(), `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tat, team).Scan(&project); err != nil {
			return err
		}
		return tx.QueryRow(t.Context(), `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository_id) VALUES ($1, $2, $3, 'crm-api', 'CRM API', 4242) RETURNING id`, tat, project, team).Scan(&svc)
	}); err != nil {
		t.Fatal(err)
	}
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[
		{"ruleId":"go/sql-injection","level":"error","message":{"text":"bad query"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.go"},"region":{"startLine":7}}}]},
		{"ruleId":"CVE-2026-1111","level":"error","message":{"text":"openssl"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"go.sum"},"region":{"startLine":1}}}]}]}]}`
	if _, err := (scans.Service{Store: s}).Ingest(t.Context(), tat, svc, scans.Upload{Scope: "full", SARIF: []byte(sarif)}, activity.Actor{Type: activity.ActorPipeline, UID: "pipeline:x"}); err != nil {
		t.Fatal(err)
	}
	status := func() map[string]string {
		out := map[string]string{}
		if err := s.InTenant(t.Context(), tat, func(tx pgx.Tx) error {
			rows, err := tx.Query(t.Context(), `SELECT split_part(fingerprint, ':', 2), status || ' ' || coalesce(resolution, '') FROM findings`)
			if err != nil {
				return err
			}
			var k, v string
			_, err = pgx.ForEachRow(rows, []any{&k, &v}, func() error { out[k] = strings.TrimSpace(v); return nil })
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	c := client{t: t, url: srv.URL}
	viewer := c.as(auth.Principal{Subject: "user:v@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	otherTeam := c.as(auth.Principal{Subject: "user:o@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleEngineer, TenantID: tat, TeamIDs: []string{"00000000-0000-0000-0000-000000000001"}}}})
	eng := c.as(auth.Principal{Subject: "user:e@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleEngineer, TenantID: tat, TeamIDs: []string{team}}}})
	path := "/v1/tenants/" + tat + "/services/" + svc

	st, body := viewer.do("PATCH", path, map[string]any{"code_scanning_source": "github"})
	mustStatus(t, st, 403, body)
	st, body = otherTeam.do("PATCH", path, map[string]any{"code_scanning_source": "github"})
	mustStatus(t, st, 403, body)
	st, body = eng.do("PATCH", path, map[string]any{"code_scanning_source": "both"})
	mustStatus(t, st, 400, body)
	if got := status(); got["codeql"] != "open" || got["CVE-2026-1111"] != "open" {
		t.Fatalf("a refused switch changed Findings: %v", got)
	}

	st, body = eng.do("PATCH", path, map[string]any{"code_scanning_source": "github", "why": "GitHub Advanced Security is our scanner"})
	mustStatus(t, st, 200, body)
	if body["code_scanning_source"] != "github" {
		t.Fatalf("%v", body)
	}
	if got := status(); got["codeql"] != "resolved code scanning source changed to github" || got["CVE-2026-1111"] != "open" {
		t.Fatalf("%v", got)
	}
	var detail string
	if err := s.InTenant(t.Context(), tat, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT event::text FROM activities WHERE operation = 'SetCodeScanningSource' ORDER BY seq DESC LIMIT 1`).Scan(&detail)
	}); err != nil || !strings.Contains(detail, "code scanning source github; 1 open code scanning Findings of the other source resolved") {
		t.Fatalf("activity %s %v", detail, err)
	}

	// A Finding the GitHub sync raised.
	if err := s.InTenant(t.Context(), tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, service_id)
			VALUES ($1, 'sast', 'scan:github:4242:5', 'high', 'sqli', '{"tools": ["github-code-scanning"]}', $2)`, tat, svc)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	st, body = eng.do("PATCH", path, map[string]any{"code_scanning_source": "keel"})
	mustStatus(t, st, 200, body)
	if got := status(); got["github"] != "resolved code scanning source changed to keel" || got["CVE-2026-1111"] != "open" {
		t.Fatalf("%v", got)
	}
}
