package ghalerts_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/ghalerts"
	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/scans"
)

// gitHub serves acme/crm-api's code scanning alerts.
type gitHub struct {
	t        *testing.T
	srv      *httptest.Server
	alerts   []map[string]any // most recently updated first, as GitHub sorts them
	requests []string
	// capClosed makes the dismissed and fixed lists end in a next link on
	// every page, as a repository with more closed alerts than Keel reads.
	capClosed bool
}

func newGitHub(t *testing.T) *gitHub {
	g := &gitHub{t: t}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/crm-api/code-scanning/alerts" {
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		state := r.URL.Query().Get("state")
		g.requests = append(g.requests, state)
		if state != "open" {
			if q := r.URL.Query(); q.Get("sort") != "updated" || q.Get("direction") != "desc" {
				t.Errorf("closed alerts not listed most recently updated first: %s", r.URL)
			}
			if g.capClosed {
				w.Header().Set("Link", "<"+g.srv.URL+r.URL.String()+">; rel=\"next\"")
				_, _ = w.Write([]byte(`[]`))
				return
			}
		}
		page := []map[string]any{}
		for _, a := range g.alerts {
			if a["state"] == state {
				page = append(page, a)
			}
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *gitHub) source() ghalerts.GitHub {
	return ghalerts.GitHub{Client: ghapi.Client{BaseURL: g.srv.URL}}
}

// alert opens CodeQL alert number on rule at path:line, or updates it.
func (g *gitHub) alert(number int, rule, path string, line int) {
	g.alerts = slices.DeleteFunc(g.alerts, func(a map[string]any) bool { return a["number"] == number })
	g.alerts = append([]map[string]any{{"number": number, "state": "open", "html_url": fmt.Sprintf("https://github.com/acme/crm-api/security/code-scanning/%d", number),
		"rule":                 map[string]any{"id": rule, "severity": "error", "security_severity_level": "high", "description": "Database query built from user-controlled sources"},
		"tool":                 map[string]any{"name": "CodeQL"},
		"most_recent_instance": map[string]any{"location": map[string]any{"path": path, "start_line": line}, "message": map[string]any{"text": "This query depends on a user-provided value."}},
	}}, g.alerts...)
}

// close moves alert number to state (dismissed or fixed).
func (g *gitHub) close(number int, state, reason string) {
	i := slices.IndexFunc(g.alerts, func(a map[string]any) bool { return a["number"] == number })
	a := g.alerts[i]
	a["state"], a["dismissed_reason"] = state, reason
	g.alerts = append([]map[string]any{a}, slices.Delete(g.alerts, i, i+1)...)
}

func (g *gitHub) reopen(number int) {
	i := slices.IndexFunc(g.alerts, func(a map[string]any) bool { return a["number"] == number })
	g.alerts[i]["state"], g.alerts[i]["dismissed_reason"] = "open", nil
}

func (e env) setSource(t *testing.T, source string) {
	t.Helper()
	ctx := context.Background()
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE services SET code_scanning_source = $2 WHERE id = $1`, e.svc, source)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// CodeQL results as CI's SARIF has them.
const (
	sqli = `{"ruleId":"go/sql-injection","level":"error","message":{"text":"bad query"},"partialFingerprints":{"primaryLocationLineHash":"9f3c1a2b:1"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.go"},"region":{"startLine":7}}}]}`
	xss = `{"ruleId":"go/reflected-xss","level":"warning","message":{"text":"xss"},"partialFingerprints":{"primaryLocationLineHash":"77aa:1"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"web.go"},"region":{"startLine":3}}}]}`
	cve = `{"ruleId":"CVE-2026-1111","level":"error","message":{"text":"openssl"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"go.sum"},"region":{"startLine":1}}}]}`
)

func sarifOf(tool string, results ...string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + tool + `"}},"results":[` + strings.Join(results, ",") + `]}]}`
}

var ci = activity.Actor{Type: activity.ActorPipeline, UID: "pipeline:x"}

func (e env) upload(t *testing.T, scope, sarif string) {
	t.Helper()
	if _, err := (scans.Service{Store: e.s}).Ingest(context.Background(), e.tenant, e.svc, scans.Upload{Scope: scope, CommitSHA: "ci", SARIF: []byte(sarif)}, ci); err != nil {
		t.Fatal(err)
	}
}

func (e env) run(t *testing.T, src ghalerts.Source) ghalerts.ServiceStatus {
	t.Helper()
	res, err := e.syncer(src).Run(context.Background())
	if err != nil || len(res.Statuses) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	return res.Statuses[0]
}

type finding struct {
	ID, Fingerprint, Status, Resolution string
	FirstSeen                           time.Time
}

// byPrefix lists the Findings whose fingerprint starts with prefix.
func (e env) byPrefix(t *testing.T, prefix string) []finding {
	t.Helper()
	var out []finding
	if err := e.s.InTenant(context.Background(), e.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT id::text, fingerprint, status, coalesce(resolution, ''), first_seen_at FROM findings
			WHERE starts_with(fingerprint, $1) ORDER BY first_seen_at, id`, prefix)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[finding])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// except approves an Exception for the Finding id.
func (e env) except(t *testing.T, id string) {
	t.Helper()
	ctx := context.Background()
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO exceptions (tenant_id, finding_ids, reason, state, requested_by, expires_at)
			VALUES ($1, ARRAY[$2::uuid], 'accepted until the ORM migration', 'approved', 'a', now() + interval '30 days')`, e.tenant, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// coveredOpen reports whether an approved Exception names an open Finding
// with the given fingerprint by its id.
func (e env) coveredOpen(t *testing.T, fp string) bool {
	t.Helper()
	ctx := context.Background()
	var covered bool
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM findings f JOIN exceptions x ON f.id = ANY (x.finding_ids)
			WHERE f.fingerprint = $1 AND f.status = 'open' AND x.state = 'approved')`, fp).Scan(&covered)
	}); err != nil {
		t.Fatal(err)
	}
	return covered
}

func (e env) lastSyncActivity(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	var detail string
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT event::text FROM activities WHERE operation = 'SyncGitHubAlerts' ORDER BY seq DESC LIMIT 1`).Scan(&detail)
	}); err != nil {
		t.Fatal(err)
	}
	return detail
}

// By default a Service takes code scanning from CI: GitHub's code scanning
// is not read at all.
func TestDefaultSourceKeelIgnoresGitHubCodeScanning(t *testing.T) {
	e := setup(t, "acme/crm-api")
	gh := newGitHub(t)
	gh.alert(1, "go/sql-injection", "db.go", 7)
	e.upload(t, "full", sarifOf("CodeQL", sqli))
	st := e.run(t, &fake{code: gh.source()})
	if st.CodeScanning != ghalerts.StatusKeel || len(gh.requests) != 0 {
		t.Fatalf("status %q after %v", st.CodeScanning, gh.requests)
	}
	if got := e.byPrefix(t, "scan:"); len(got) != 1 || !strings.HasPrefix(got[0].Fingerprint, "scan:codeql:") || got[0].Status != "open" {
		t.Fatalf("%+v", got)
	}
	if d := e.lastSyncActivity(t); !strings.Contains(d, "code scanning keel,") {
		t.Fatalf("activity %s", d)
	}
}

// With GitHub as the source, each alert number is one Finding for its whole
// life: it survives the code moving, keeps its Exception, and resolves with
// GitHub's reason when GitHub fixes or dismisses it.
func TestGitHubSourceOneFindingPerAlert(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.setSource(t, scans.SourceGitHub)
	gh := newGitHub(t)
	src := &fake{code: gh.source()}
	gh.alert(5, "go/sql-injection", "db.go", 7)
	gh.alert(6, "go/sql-injection", "db.go", 50)
	if st := e.run(t, src); st.CodeScanning != ghalerts.StatusOK {
		t.Fatalf("%+v", st)
	}
	f := e.findings(t)
	five := f["scan:github:4242:5"]
	if len(f) != 2 || five.status != "open" || five.kind != "sast" || five.severity != "high" ||
		five.title != "go/sql-injection in crm-api: Database query built from user-controlled sources" {
		t.Fatalf("%+v", f)
	}
	for _, want := range []string{`"tools": ["github-code-scanning"]`, `"tool": "codeql"`, `"rule_id": "go/sql-injection"`, `"locations": ["db.go:7"]`,
		`"alert_url": "https://github.com/acme/crm-api/security/code-scanning/5"`} {
		if !strings.Contains(five.detail, want) {
			t.Fatalf("detail %s lacks %s", five.detail, want)
		}
	}
	first := e.byPrefix(t, "scan:github:4242:5")[0]
	e.except(t, first.ID)

	gh.alert(5, "go/sql-injection", "db.go", 30) // a line added above it
	e.run(t, src)
	if got := e.byPrefix(t, "scan:github:4242:5"); len(got) != 1 || got[0] != first || !e.coveredOpen(t, "scan:github:4242:5") {
		t.Fatalf("after the alert moved: %+v, want %+v covered", got, first)
	}
	if d := e.findings(t)["scan:github:4242:5"].detail; !strings.Contains(d, `"locations": ["db.go:30"]`) {
		t.Fatalf("location not refreshed: %s", d)
	}

	gh.close(5, "fixed", "")
	gh.close(6, "dismissed", "false positive")
	e.run(t, src)
	if got := e.byPrefix(t, "scan:github:4242:5"); len(got) != 1 || got[0].Status != "resolved" || got[0].Resolution != "fixed on GitHub" {
		t.Fatalf("%+v", got)
	}
	if got := e.byPrefix(t, "scan:github:4242:6"); len(got) != 1 || got[0].Status != "resolved" || got[0].Resolution != "dismissed on GitHub: false positive" {
		t.Fatalf("%+v", got)
	}
	// Closed alerts stay closed: a sync with nothing open changes nothing.
	gh.requests = nil
	e.run(t, src)
	if got := e.byPrefix(t, "scan:github:"); len(open(got)) != 0 || !slices.Equal(gh.requests, []string{"open"}) {
		t.Fatalf("%+v after %v", got, gh.requests)
	}
	// Only GitHub reopening an alert raises it again, as a new Finding.
	gh.reopen(6)
	e.run(t, src)
	if got := e.byPrefix(t, "scan:github:4242:6"); len(got) != 2 || got[0].Status != "resolved" || got[1].Status != "open" {
		t.Fatalf("%+v", got)
	}
}

// An open Finding whose alert is in no list resolves only when the closed
// lists were read to the end; a capped read keeps it open.
func TestGitHubSourceMissingAlertNeedsCompleteLists(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.setSource(t, scans.SourceGitHub)
	gh := newGitHub(t)
	src := &fake{code: gh.source()}
	gh.alert(7, "go/sql-injection", "db.go", 7)
	e.run(t, src)
	gh.alerts = nil // the analysis that raised it was deleted on GitHub
	gh.capClosed = true
	e.run(t, src)
	if got := e.byPrefix(t, "scan:github:4242:7"); len(got) != 1 || got[0].Status != "open" {
		t.Fatalf("resolved on a capped read: %+v", got)
	}
	gh.capClosed = false
	e.run(t, src)
	if got := e.byPrefix(t, "scan:github:4242:7"); len(got) != 1 || got[0].Resolution != "no longer on GitHub" {
		t.Fatalf("%+v", got)
	}
}

func TestGitHubSourceWithoutRepositoryIDSyncsNoCodeScanning(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.setSource(t, scans.SourceGitHub)
	if err := e.s.InTenant(context.Background(), e.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE services SET repository_id = NULL WHERE id = $1`, e.svc)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	gh := newGitHub(t)
	gh.alert(1, "go/sql-injection", "db.go", 7)
	if st := e.run(t, &fake{code: gh.source()}); st.CodeScanning != ghalerts.StatusNoRepositoryID || len(gh.requests) != 0 {
		t.Fatalf("%+v after %v", st, gh.requests)
	}
	if f := e.findings(t); len(f) != 0 {
		t.Fatalf("%v", f)
	}
}

// With GitHub as the source, CI's SARIF neither raises nor resolves code
// scanning Findings, and still raises and resolves vulnerabilities.
func TestCISARIFForGitHubSourceOnlyReportsVulnerabilities(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.upload(t, "full", sarifOf("CodeQL", sqli))
	e.setSource(t, scans.SourceGitHub) // bypasses the switch, so CI's Finding stays open
	gh := newGitHub(t)
	gh.alert(5, "go/sql-injection", "db.go", 7)
	e.run(t, &fake{code: gh.source()})
	before := e.byPrefix(t, "scan:codeql:")

	e.upload(t, "full", sarifOf("CodeQL", sqli, xss, cve))
	vuln := "vuln:CVE-2026-1111:" + e.svc
	if got := e.byPrefix(t, vuln); len(got) != 1 || got[0].Status != "open" {
		t.Fatalf("%+v", got)
	}
	e.upload(t, "full", sarifOf("CodeQL"))
	if got := e.byPrefix(t, vuln); len(got) != 1 || got[0].Status != "resolved" {
		t.Fatalf("%+v", got)
	}
	if got := e.byPrefix(t, "scan:codeql:"); len(before) != 1 || !slices.Equal(got, before) {
		t.Fatalf("CI changed code scanning Findings: %+v, was %+v", got, before)
	}
	if got := e.byPrefix(t, "scan:github:4242:5"); len(got) != 1 || got[0].Status != "open" {
		t.Fatalf("CI resolved GitHub's Finding: %+v", got)
	}
}

func open(fs []finding) []finding {
	var out []finding
	for _, f := range fs {
		if f.Status == "open" {
			out = append(out, f)
		}
	}
	return out
}
