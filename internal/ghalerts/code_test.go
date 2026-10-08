package ghalerts_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/ghalerts"
	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// gitHub serves acme/crm-api's code scanning analyses, their SARIF and its
// dismissed alerts.
type gitHub struct {
	t         *testing.T
	srv       *httptest.Server
	analyses  []map[string]any // newest first, as GitHub lists them
	sarif     map[int64]string
	dismissed []map[string]any
	downloads []int64
	failSARIF bool
	// capped makes the analyses list end in a next link on every page, as
	// a repository with more analyses than Keel reads does.
	capped bool
}

func newGitHub(t *testing.T) *gitHub {
	g := &gitHub{t: t, sarif: map[int64]string{}}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const repo = "/repos/acme/crm-api"
		switch p := r.URL.Path; {
		case p == repo:
			_, _ = w.Write([]byte(`{"default_branch": "main"}`))
		case p == repo+"/code-scanning/analyses":
			if r.URL.Query().Get("ref") != "refs/heads/main" {
				t.Errorf("analyses not filtered to the default branch: %s", r.URL)
			}
			if g.capped {
				w.Header().Set("Link", "<"+g.srv.URL+r.URL.String()+">; rel=\"next\"")
			}
			_ = json.NewEncoder(w).Encode(g.analyses)
		case strings.HasPrefix(p, repo+"/code-scanning/analyses/"):
			if a := r.Header.Get("Accept"); a != "application/sarif+json" {
				t.Errorf("SARIF download with Accept %q", a)
			}
			id, _ := strconv.ParseInt(strings.TrimPrefix(p, repo+"/code-scanning/analyses/"), 10, 64)
			g.downloads = append(g.downloads, id)
			if g.failSARIF {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(`{"message": "upstream"}`))
				return
			}
			_, _ = w.Write([]byte(g.sarif[id]))
		case p == repo+"/code-scanning/alerts":
			if r.URL.Query().Get("state") != "dismissed" {
				t.Errorf("code scanning alerts listed without state=dismissed: %s", r.URL)
			}
			_ = json.NewEncoder(w).Encode(g.dismissed)
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *gitHub) source() ghalerts.GitHub {
	return ghalerts.GitHub{Client: ghapi.Client{BaseURL: g.srv.URL}}
}

// analysis adds a new, newest analysis of tool and category on main.
func (g *gitHub) analysis(tool, category, sarif string) int64 {
	id := int64(len(g.analyses) + 1)
	g.analyses = append([]map[string]any{{"id": id, "ref": "refs/heads/main", "commit_sha": fmt.Sprintf("c%d", id), "category": category,
		"created_at": time.Date(2026, 9, 1, 0, 0, int(id), 0, time.UTC), "tool": map[string]any{"name": tool}, "error": ""}}, g.analyses...)
	g.sarif[id] = sarif
	return id
}

func (g *gitHub) dismiss(rule, path string, line int, reason string) {
	g.dismissed = append(g.dismissed, map[string]any{"number": len(g.dismissed) + 1, "state": "dismissed", "dismissed_reason": reason,
		"rule": map[string]any{"id": rule}, "tool": map[string]any{"name": "CodeQL"},
		"most_recent_instance": map[string]any{"location": map[string]any{"path": path, "start_line": line}}})
}

// CodeQL results carry partial fingerprints, as CodeQL writes them.
const (
	sqli = `{"ruleId":"go/sql-injection","level":"error","message":{"text":"bad query"},"partialFingerprints":{"primaryLocationLineHash":"9f3c1a2b:1"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.go"},"region":{"startLine":7}}}]}`
	xss = `{"ruleId":"go/reflected-xss","level":"warning","message":{"text":"xss"},"partialFingerprints":{"primaryLocationLineHash":"77aa:1"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"web.go"},"region":{"startLine":3}}}]}`
	jsXSS = `{"ruleId":"js/xss","level":"error","message":{"text":"dom xss"},"partialFingerprints":{"primaryLocationLineHash":"1234:1"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"web/app.js"},"region":{"startLine":9}}}]}`
)

func codeql(results ...string) string {
	return sarifOf("CodeQL", results...)
}

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

func (e env) covered(t *testing.T, id string) bool {
	t.Helper()
	ctx := context.Background()
	var covered bool
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM exceptions WHERE $1::uuid = ANY (finding_ids) AND state = 'approved')`, id).Scan(&covered)
	}); err != nil {
		t.Fatal(err)
	}
	return covered
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

// GitHub's stored SARIF fingerprints exactly as CI's upload of the same
// results, so every source and order keeps one Finding per alert: same id,
// same first_seen_at, and an Exception by id keeps covering it. Other tools
// and the shared vulnerability Finding are never touched.
func TestCodeScanningLifecycleKeepsOneFindingPerAlert(t *testing.T) {
	ctx := context.Background()
	e := setup(t, "acme/crm-api")
	gh := newGitHub(t)
	e.upload(t, "full", sarifOf("Semgrep", `{"ruleId":"go.lang.xss","level":"warning","message":{"text":"xss"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"web.go"},"region":{"startLine":3}}}]}`))
	e.upload(t, "full", sarifOf("Trivy", `{"ruleId":"CVE-2026-1111","level":"error","message":{"text":"openssl"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"go.sum"},"region":{"startLine":1}}}]}`))
	src := &fake{code: gh.source(), deps: []ghalerts.DependabotAlert{{Number: 1, GHSA: "GHSA-aaaa-bbbb-cccc", CVE: "CVE-2026-1111", Severity: "high", Summary: "s"}}}

	gh.analysis("CodeQL", "/language:go", codeql(sqli))
	e.run(t, src)
	codeqlPrefix := "scan:codeql:go/sql-injection:" + e.svc + ":"
	alert := e.byPrefix(t, codeqlPrefix)
	others := append(e.byPrefix(t, "scan:semgrep:"), e.byPrefix(t, "vuln:")...)
	if len(alert) != 1 || alert[0].Status != "open" || len(others) != 2 {
		t.Fatalf("after the first GitHub analysis: %v %v", alert, others)
	}
	e.except(t, alert[0].ID)
	check := func(step string) {
		t.Helper()
		got := e.byPrefix(t, codeqlPrefix)
		if len(got) != 1 || got[0] != alert[0] {
			t.Fatalf("%s: CodeQL Findings %v, want only %v", step, got, alert[0])
		}
		if now := append(e.byPrefix(t, "scan:semgrep:"), e.byPrefix(t, "vuln:")...); fmt.Sprint(now) != fmt.Sprint(others) {
			t.Fatalf("%s: other Findings changed: %v, was %v", step, now, others)
		}
		if !e.covered(t, alert[0].ID) {
			t.Fatalf("%s: Exception no longer covers the Finding", step)
		}
	}
	check("GitHub analysis")
	e.upload(t, "diff", codeql(sqli))
	check("CI diff upload")
	e.run(t, src)
	check("sync after the diff upload")
	e.upload(t, "full", codeql(sqli))
	check("CI full upload")
	e.run(t, src)
	check("sync after the full upload")
	if _, err := storetest.Superuser(t, e.s).Exec(ctx, `UPDATE scan_runs SET created_at = now() - interval '31 days'`); err != nil {
		t.Fatal(err)
	}
	gh.analysis("CodeQL", "/language:go", codeql(sqli))
	e.run(t, src)
	check("new GitHub analysis after 31 days without CI")
	gh.analysis("CodeQL", "/language:go", codeql(sqli))
	e.run(t, src)
	check("second new GitHub analysis")

	gh.analysis("CodeQL", "/language:go", codeql())
	e.run(t, src)
	got := e.byPrefix(t, codeqlPrefix)
	if len(got) != 1 || got[0].ID != alert[0].ID || got[0].Status != "resolved" || got[0].Resolution != "no longer reported by a full scan" {
		t.Fatalf("fixed on GitHub: %v", got)
	}
	if now := append(e.byPrefix(t, "scan:semgrep:"), e.byPrefix(t, "vuln:")...); fmt.Sprint(now) != fmt.Sprint(others) {
		t.Fatalf("fixed on GitHub: other Findings changed: %v, was %v", now, others)
	}
}

// A dismissal on GitHub resolves the Finding with GitHub's reason, and the
// next analysis, which still reports the result, does not raise it again.
func TestDismissedAlertResolvesItsFinding(t *testing.T) {
	e := setup(t, "acme/crm-api")
	gh := newGitHub(t)
	src := &fake{code: gh.source()}
	gh.analysis("CodeQL", "", codeql(sqli, xss))
	e.run(t, src)
	gh.dismiss("go/sql-injection", "db.go", 7, "false positive")
	e.run(t, src)
	dismissed := e.byPrefix(t, "scan:codeql:go/sql-injection:")
	if len(dismissed) != 1 || dismissed[0].Status != "resolved" || dismissed[0].Resolution != "dismissed on GitHub: false positive" {
		t.Fatalf("dismissed alert: %v", dismissed)
	}
	if kept := open(e.byPrefix(t, "scan:codeql:go/reflected-xss:")); len(kept) != 1 {
		t.Fatalf("the other alert: %v", kept)
	}
	gh.analysis("CodeQL", "", codeql(sqli, xss))
	e.run(t, src)
	if got := e.byPrefix(t, "scan:codeql:go/sql-injection:"); len(got) != 1 || got[0] != dismissed[0] {
		t.Fatalf("new analysis raised the dismissed alert again: %v", got)
	}
	// A CI upload, which knows nothing of dismissals, raises it; the next sync resolves it.
	e.upload(t, "full", codeql(sqli, xss))
	e.run(t, src)
	if got := open(e.byPrefix(t, "scan:codeql:go/sql-injection:")); len(got) != 0 {
		t.Fatalf("CI's copy of a dismissed alert still open: %v", got)
	}
}

// An analysis Keel already ingested is not downloaded or ingested again; a
// failed download or a failed analysis changes nothing.
func TestIngestedAnalysisIsSkippedAndFailuresKeepFindings(t *testing.T) {
	ctx := context.Background()
	e := setup(t, "acme/crm-api")
	gh := newGitHub(t)
	src := &fake{code: gh.source()}
	first := gh.analysis("CodeQL", "", codeql(sqli))
	e.run(t, src)
	e.run(t, src)
	if len(gh.downloads) != 1 || gh.downloads[0] != first {
		t.Fatalf("downloads %v, want only analysis %d once", gh.downloads, first)
	}
	var runs int
	var ids string
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), string_agg(github_analysis_ids::text, ' ') FROM scan_runs WHERE uploaded_by = 'keel:ghalerts'`).Scan(&runs, &ids)
	}); err != nil || runs != 1 || ids != "{1}" {
		t.Fatalf("scan runs %d %q %v", runs, ids, err)
	}
	if d := e.lastSyncDetail(t); !strings.Contains(d, "code scanning ok (unchanged codeql; 0 dismissed on GitHub)") {
		t.Fatalf("activity %q", d)
	}

	gh.analysis("CodeQL", "", codeql())
	gh.failSARIF = true
	if st := e.run(t, src); st.CodeScanning != ghalerts.StatusError {
		t.Fatalf("code scanning %q after a failed download", st.CodeScanning)
	}
	if got := open(e.byPrefix(t, "scan:codeql:")); len(got) != 1 {
		t.Fatalf("a failed download resolved %v", got)
	}

	gh.failSARIF = false
	gh.analyses[0]["error"] = "CodeQL could not build the database"
	n := len(gh.downloads)
	if st := e.run(t, src); st.CodeScanning != ghalerts.StatusOK || len(gh.downloads) != n {
		t.Fatalf("failed analysis: status %q, downloads %v", st.CodeScanning, gh.downloads[n:])
	}
	if got := open(e.byPrefix(t, "scan:codeql:")); len(got) != 1 {
		t.Fatalf("a failed analysis resolved %v", got)
	}
}

// The newest analysis of every category is ingested as one full scan, so a
// new Go analysis does not resolve the JavaScript results.
func TestCategoriesOfOneToolIngestTogether(t *testing.T) {
	e := setup(t, "acme/crm-api")
	gh := newGitHub(t)
	src := &fake{code: gh.source()}
	gh.analysis("CodeQL", "/language:go", codeql(sqli))
	gh.analysis("CodeQL", "/language:javascript", codeql(jsXSS))
	e.run(t, src)
	gh.analysis("CodeQL", "/language:go", codeql())
	e.run(t, src)
	if got := open(e.byPrefix(t, "scan:codeql:")); len(got) != 1 || !strings.HasPrefix(got[0].Fingerprint, "scan:codeql:js/xss:") {
		t.Fatalf("open %v, want only the JavaScript result", got)
	}
}

func (e env) lastSyncDetail(t *testing.T) string {
	t.Helper()
	var detail string
	if err := e.s.InTenant(context.Background(), e.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT event->'data'->>'status_detail' FROM activities WHERE operation = 'SyncGitHubAlerts' ORDER BY seq DESC LIMIT 1`).Scan(&detail)
	}); err != nil {
		t.Fatal(err)
	}
	return detail
}

// GitHub's copy of an uploaded SARIF is not CI's copy: GitHub adds
// primaryLocationLineHash to a third-party tool's results, may drop CodeQL's,
// and writes the path against %SRCROOT%. Each pairing, through CI, sync, CI,
// sync, keeps one open Finding with the same id and first_seen_at, still
// covered by its Exception.
func TestCIAndGitHubCopiesOfAResultAreOneFinding(t *testing.T) {
	copyOf := func(tool string, hash bool, location string) string {
		r := `{"ruleId":"r1","level":"error","message":{"text":"tainted input reaches sink"},"locations":[{"physicalLocation":{` + location + `,"region":{"startLine":7}}}]`
		if hash {
			r += `,"partialFingerprints":{"primaryLocationLineHash":"9f3c1a2b:1"}`
		}
		return sarifOf(tool, r+"}")
	}
	for _, c := range []struct {
		tool           string
		ciHash, ghHash bool
	}{
		{"Semgrep", false, true},
		{"CodeQL", true, false},
		{"CodeQL", false, true},
	} {
		t.Run(fmt.Sprintf("%s CI hash %v GitHub hash %v", c.tool, c.ciHash, c.ghHash), func(t *testing.T) {
			e := setup(t, "acme/crm-api")
			gh := newGitHub(t)
			src := &fake{code: gh.source()}
			ci := copyOf(c.tool, c.ciHash, `"artifactLocation":{"uri":"db.go"}`)
			fromGitHub := copyOf(c.tool, c.ghHash, `"artifactLocation":{"uri":"db.go","uriBaseId":"%SRCROOT%"}`)
			prefix := "scan:" + strings.ToLower(c.tool) + ":r1:" + e.svc + ":"

			e.upload(t, "full", ci)
			first := e.byPrefix(t, prefix)
			if len(first) != 1 || first[0].Status != "open" {
				t.Fatalf("CI upload: %v", first)
			}
			e.except(t, first[0].ID)
			for i, step := range []string{"sync", "CI", "sync"} {
				if step == "CI" {
					e.upload(t, "full", ci)
				} else {
					gh.analysis(c.tool, "", fromGitHub)
					e.run(t, src)
				}
				if got := e.byPrefix(t, prefix); len(got) != 1 || got[0] != first[0] {
					t.Fatalf("step %d (%s): Findings %v, want only %v", i+1, step, got, first[0])
				}
				if !e.covered(t, first[0].ID) {
					t.Fatalf("step %d (%s): Exception no longer covers the Finding", i+1, step)
				}
			}
		})
	}
}

// A dismissal names the path GitHub shows; the SARIF may write the same file
// as ./db.go, as a file URI under %SRCROOT%, or without a region. Each form
// resolves with GitHub's reason, and the next analysis does not raise it again.
func TestDismissalMatchesEveryLocationForm(t *testing.T) {
	const base = `"originalUriBaseIds":{"%SRCROOT%":{"uri":"file:///home/runner/work/crm-api/crm-api/"}},`
	for _, c := range []struct {
		name, location string
		alertLine      int
	}{
		{"dot slash", `"artifactLocation":{"uri":"./db.go"},"region":{"startLine":7}`, 7},
		{"file URI", `"artifactLocation":{"uri":"file:///home/runner/work/crm-api/crm-api/db.go"},"region":{"startLine":7}`, 7},
		{"uriBaseId", `"artifactLocation":{"uri":"db.go","uriBaseId":"%SRCROOT%"},"region":{"startLine":7}`, 7},
		{"no region", `"artifactLocation":{"uri":"db.go"}`, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t, "acme/crm-api")
			gh := newGitHub(t)
			src := &fake{code: gh.source()}
			result := `{"ruleId":"go/sql-injection","level":"error","message":{"text":"bad query"},"locations":[{"physicalLocation":{` + c.location + `}}]}`
			analysis := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},` + base + `"results":[` + result + `,` + xss + `]}]}`
			gh.analysis("CodeQL", "", analysis)
			e.run(t, src)
			gh.dismiss("go/sql-injection", "db.go", c.alertLine, "false positive")
			gh.analysis("CodeQL", "", analysis)
			e.run(t, src)
			got := e.byPrefix(t, "scan:codeql:go/sql-injection:")
			if len(got) != 1 || got[0].Status != "resolved" || got[0].Resolution != "dismissed on GitHub: false positive" {
				t.Fatalf("dismissed alert: %v", got)
			}
			if kept := open(e.byPrefix(t, "scan:codeql:go/reflected-xss:")); len(kept) != 1 {
				t.Fatalf("the other alert: %v", kept)
			}
		})
	}
}

// When the analyses list ends at the page cap, a category missing from the
// window may still exist on GitHub: the categories seen resolve as usual,
// and the Findings of the others stay open.
func TestCategoryOutsideTheAnalysisWindowStaysOpen(t *testing.T) {
	e := setup(t, "acme/crm-api")
	gh := newGitHub(t)
	src := &fake{code: gh.source()}
	gh.analysis("CodeQL", "/language:go", codeql(sqli))
	gh.analysis("CodeQL", "/language:javascript", codeql(jsXSS))
	e.run(t, src)
	gh.analysis("CodeQL", "/language:go", codeql())
	var window []map[string]any
	for _, a := range gh.analyses {
		if a["category"] != "/language:javascript" {
			window = append(window, a)
		}
	}
	gh.analyses, gh.capped = window, true
	if st := e.run(t, src); st.CodeScanning != ghalerts.StatusOK {
		t.Fatalf("code scanning %q", st.CodeScanning)
	}
	if got := e.byPrefix(t, "scan:codeql:go/sql-injection:"); len(got) != 1 || got[0].Status != "resolved" {
		t.Fatalf("Go result fixed in a seen category: %v", got)
	}
	if got := open(e.byPrefix(t, "scan:codeql:js/xss:")); len(got) != 1 {
		t.Fatalf("JavaScript result outside the window: %v, want it open", got)
	}
}
