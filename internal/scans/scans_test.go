package scans_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// sarif builds a minimal SARIF 2.1 log.
func sarif(tool string, results ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": tool, "rules": []any{map[string]any{"id": "CVE-2026-1111", "shortDescription": map[string]any{"text": "openssl overflow"}, "properties": map[string]any{"security-severity": "9.8"}}}}},
		"results": results}}})
	return b
}

func res(rule, uri string, line int, extra map[string]any) map[string]any {
	r := map[string]any{"ruleId": rule, "level": "warning", "message": map[string]any{"text": rule + " found"},
		"locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": uri}, "region": map[string]any{"startLine": line}}}}}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

var ci = activity.Actor{Type: activity.ActorPipeline, UID: "pipeline:github:acme/crm-api@refs/heads/main#1"}

func open(t *testing.T, s *store.Store, tenant string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	if err := s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT fingerprint, severity, kind, owner_team_id::text, coalesce(detail->>'tools', '') FROM findings WHERE status = 'open'`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var fp, sev, kind, team, tools string
			if err := rows.Scan(&fp, &sev, &kind, &team, &tools); err != nil {
				return err
			}
			out[fp] = []string{sev, kind, team, tools}
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestScansDedupeAcrossToolsAndResolveOnFullScans(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var team, svc string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'CRM API') RETURNING id`, tenant, project, team).Scan(&svc)
	}); err != nil {
		t.Fatal(err)
	}
	ing := scans.Service{Store: s}
	cve := "vuln:CVE-2026-1111:" + svc

	// Trivy: the CVE in two lockfile places, plus a misconfiguration.
	run, err := ing.Ingest(ctx, tenant, svc, scans.Upload{Scope: "full", CommitSHA: "aaa", SARIF: sarif("Trivy",
		res("CVE-2026-1111", "go.sum", 10, nil), res("CVE-2026-1111", "web/package-lock.json", 99, nil),
		res("AVD-KSV-0014", "deploy/app.yaml", 3, map[string]any{"partialFingerprints": map[string]string{"primaryLocationLineHash": "abc"}}))}, ci)
	if err != nil || run.Results != 2 || run.Raised != 2 {
		t.Fatalf("%+v %v", run, err)
	}
	f := open(t, s, tenant)
	if f[cve][0] != "critical" || f[cve][1] != "vulnerability" || f[cve][2] != team {
		t.Fatalf("cve finding %v", f)
	}
	// Grype reports the same CVE: no duplicate, both tools recorded.
	if run, err := ing.Ingest(ctx, tenant, svc, scans.Upload{Scope: "full", SARIF: sarif("Grype", res("CVE-2026-1111", "go.sum", 10, nil))}, ci); err != nil || run.Raised != 0 {
		t.Fatalf("%+v %v", run, err)
	}
	if f := open(t, s, tenant); len(f) != 2 || f[cve][3] != `["grype", "trivy"]` {
		t.Fatalf("after grype %v", f)
	}
	// A diff scan never resolves anything.
	if run, _ := ing.Ingest(ctx, tenant, svc, scans.Upload{Scope: "diff", SARIF: sarif("Trivy")}, ci); run.Resolved != 0 {
		t.Fatalf("diff resolved %+v", run)
	}
	// Trivy no longer sees anything: the misconfig resolves; the CVE stays while Grype still reports it.
	if run, _ := ing.Ingest(ctx, tenant, svc, scans.Upload{Scope: "full", SARIF: sarif("Trivy")}, ci); run.Resolved != 1 {
		t.Fatalf("trivy full %+v", run)
	}
	if f := open(t, s, tenant); len(f) != 1 || f[cve] == nil {
		t.Fatalf("after trivy clean %v", f)
	}
	if run, _ := ing.Ingest(ctx, tenant, svc, scans.Upload{Scope: "full", SARIF: sarif("Grype")}, ci); run.Resolved != 1 {
		t.Fatalf("grype full %+v", run)
	}
	if f := open(t, s, tenant); len(f) != 0 {
		t.Fatalf("still open %v", f)
	}
	if _, err := ing.Ingest(ctx, tenant, svc, scans.Upload{Scope: "full", SARIF: []byte(`{"version":"1.0"}`)}, ci); err == nil {
		t.Fatal("bad SARIF accepted")
	}
}

func TestSeverityAndKinds(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "gitleaks"}},
		"results": []any{res("aws-access-token", "config.env", 2, map[string]any{"level": "error"}), res("generic", "x", 1, map[string]any{"level": "note"})}}}})
	_, rs, err := scans.ParseSARIF(raw, "svc")
	if err != nil || len(rs) != 2 || rs[0].Kind != "secret" || rs[0].Severity != "high" || rs[1].Severity != "low" {
		t.Fatalf("%+v %v", rs, err)
	}
}

// A code scanning fingerprint is rule, path and message: partial
// fingerprints, lines, path spelling and message whitespace do not change
// it, and the same result twice in one file is one Finding.
func TestCodeScanFingerprintIgnoresPartialFingerprintsAndLines(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "Semgrep"}},
		"results": []any{
			res("r1", "./db.go", 3, map[string]any{"partialFingerprints": map[string]string{"primaryLocationLineHash": "aa:1"}}),
			res("r1", "db.go", 9, map[string]any{"message": map[string]any{"text": "r1  found\n"}}),
			res("r1", "web.go", 3, nil),
		}}}})
	_, rs, err := scans.ParseSARIF(raw, "svc")
	if err != nil || len(rs) != 2 {
		t.Fatalf("%+v %v", rs, err)
	}
	if got := rs[0].Detail["locations"]; len(got.([]string)) != 2 || got.([]string)[0] != "db.go:3" || got.([]string)[1] != "db.go:9" {
		t.Fatalf("locations %v", got)
	}
}
