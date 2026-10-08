package ghalerts_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/ghalerts"
	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// fake is a Source with canned alerts and per-type errors.
type fake struct {
	code             []ghalerts.CodeAlert
	deps             []ghalerts.DependabotAlert
	secrets          []ghalerts.SecretAlert
	codeErr, depsErr error
	secretsErr       error
	repos            []string
}

func (f *fake) CodeScanning(_ context.Context, repo string) ([]ghalerts.CodeAlert, error) {
	f.repos = append(f.repos, repo)
	return f.code, f.codeErr
}
func (f *fake) Dependabot(context.Context, string) ([]ghalerts.DependabotAlert, error) {
	return f.deps, f.depsErr
}
func (f *fake) SecretScanning(context.Context, string) ([]ghalerts.SecretAlert, error) {
	return f.secrets, f.secretsErr
}

type env struct {
	s      *store.Store
	tenant string
	svc    string
	team   string
}

func setup(t *testing.T, repo string) env {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	e := env{s: s, tenant: tenant}
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&e.team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, e.team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository, repository_id) VALUES ($1, $2, $3, 'crm-api', 'CRM API', $4, 4242) RETURNING id`,
			tenant, project, e.team, repo).Scan(&e.svc); err != nil {
			return err
		}
		// An archived Service and one without a repository are never synced.
		_, err := tx.Exec(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository, archived_at) VALUES ($1, $2, $3, 'old-api', 'Old', 'acme/old', now()),
			($1, $2, $3, 'no-repo', 'No repo', '', NULL)`, tenant, project, e.team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

type row struct {
	status, kind, severity, title, detail string
	team                                  string
}

func (e env) findings(t *testing.T) map[string]row {
	t.Helper()
	out := map[string]row{}
	if err := e.s.InTenant(context.Background(), e.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT fingerprint, status, kind, severity, title, detail::text, owner_team_id::text FROM findings`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var fp string
			var r row
			if err := rows.Scan(&fp, &r.status, &r.kind, &r.severity, &r.title, &r.detail, &r.team); err != nil {
				return err
			}
			out[fp] = r
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e env) tools(t *testing.T, fp string) []string {
	t.Helper()
	var d struct {
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal([]byte(e.findings(t)[fp].detail), &d); err != nil {
		t.Fatal(err)
	}
	return d.Tools
}

func (e env) syncer(src ghalerts.Source) ghalerts.Syncer {
	return ghalerts.Syncer{Store: e.s, Source: src}
}

var sqli = ghalerts.CodeAlert{Number: 1, Tool: "codeql", RuleID: "go/sql-injection", Severity: "high", Description: "SQL injection", Path: "db.go", Line: 7, Message: "bad query"}

func TestCodeScanningAlertUsesSARIFFingerprintAndResolves(t *testing.T) {
	ctx := context.Background()
	e := setup(t, "https://github.com/acme/crm-api.git")
	src := &fake{code: []ghalerts.CodeAlert{sqli}}
	res, err := e.syncer(src).Run(ctx)
	if err != nil || res.Services != 1 || res.Raised != 1 || res.Statuses[0].CodeScanning != "ok" || res.Statuses[0].Repository != "acme/crm-api" {
		t.Fatalf("%+v %v", res, err)
	}
	if len(src.repos) != 1 || src.repos[0] != "acme/crm-api" {
		t.Fatalf("synced %v", src.repos)
	}
	// The fingerprint a SARIF upload of the same alert would get.
	_, rs, err := scans.ParseSARIF([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"ruleId":"go/sql-injection","message":{"text":"bad query"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.go"},"region":{"startLine":7}}}]}]}]}`), e.svc)
	if err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
	f := e.findings(t)
	got, ok := f[rs[0].Fingerprint]
	if !ok || len(f) != 1 || got.kind != "sast" || got.severity != "high" || got.team != e.team || !strings.HasPrefix(rs[0].Fingerprint, "scan:codeql:go/sql-injection:"+e.svc+":") {
		t.Fatalf("finding %v want %s", f, rs[0].Fingerprint)
	}
	if got.title != "go/sql-injection in crm-api: SQL injection" {
		t.Fatalf("title %q", got.title)
	}
	// Syncing again changes nothing.
	if res, err := e.syncer(src).Run(ctx); err != nil || res.Raised != 0 || res.Resolved != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	// The alert is dismissed on GitHub: the Finding resolves, though no tool is named in the empty fetch.
	src.code = nil
	if res, err := e.syncer(src).Run(ctx); err != nil || res.Resolved != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if f := e.findings(t); f[rs[0].Fingerprint].status != "resolved" {
		t.Fatalf("%v", f)
	}
}

func TestDependabotCVEMergesWithTrivyFinding(t *testing.T) {
	ctx := context.Background()
	e := setup(t, "acme/crm-api")
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[{"ruleId":"CVE-2026-1111","level":"error","message":{"text":"openssl"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"go.sum"},"region":{"startLine":1}}}]}]}]}`
	if _, err := (scans.Service{Store: e.s}).Ingest(ctx, e.tenant, e.svc, scans.Upload{Scope: "full", SARIF: []byte(sarif)}, activity.Actor{Type: activity.ActorPipeline, UID: "pipeline:x"}); err != nil {
		t.Fatal(err)
	}
	cve := "vuln:CVE-2026-1111:" + e.svc
	src := &fake{deps: []ghalerts.DependabotAlert{
		{Number: 1, GHSA: "GHSA-aaaa-bbbb-cccc", CVE: "CVE-2026-1111", Summary: "openssl overflow", Severity: "critical", Ecosystem: "gomod", Package: "openssl", ManifestPath: "go.sum"},
		{Number: 2, GHSA: "GHSA-aaaa-bbbb-cccc", CVE: "CVE-2026-1111", Severity: "high", Ecosystem: "npm", Package: "openssl-js", ManifestPath: "web/package-lock.json"},
		{Number: 3, GHSA: "GHSA-xxxx-yyyy-zzzz", Summary: "no cve", Severity: "low", Ecosystem: "npm", Package: "x", ManifestPath: "package-lock.json"}}}
	res, err := e.syncer(src).Run(ctx)
	if err != nil || res.Raised != 1 { // the CVE merged; only the GHSA-only advisory is new
		t.Fatalf("%+v %v", res, err)
	}
	f := e.findings(t)
	ghsa := "vuln:GHSA-xxxx-yyyy-zzzz:" + e.svc
	if len(f) != 2 || f[cve].severity != "critical" || f[ghsa].severity != "low" {
		t.Fatalf("%v", f)
	}
	if tools := strings.Join(e.tools(t, cve), ","); tools != "dependabot,trivy" {
		t.Fatalf("tools %s", tools)
	}
	// Dependabot stops reporting the CVE: only its own tool is removed.
	src.deps = src.deps[2:]
	if res, err := e.syncer(src).Run(ctx); err != nil || res.Resolved != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if f := e.findings(t); f[cve].status != "open" || strings.Join(e.tools(t, cve), ",") != "trivy" {
		t.Fatalf("%v", f[cve])
	}
	// Likewise a GitHub-only Finding resolves once gone.
	src.deps = nil
	if res, err := e.syncer(src).Run(ctx); err != nil || res.Resolved != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if f := e.findings(t); f[ghsa].status != "resolved" || f[cve].status != "open" {
		t.Fatalf("%v", f)
	}
}

func TestSecretAlertIsCriticalAndCarriesNoSecret(t *testing.T) {
	ctx := context.Background()
	e := setup(t, "acme/crm-api")
	src := &fake{secrets: []ghalerts.SecretAlert{{Number: 9, Type: "aws_access_key_id", DisplayName: "AWS Access Key ID", URL: "https://github.com/acme/crm-api/security/secret-scanning/9"}}}
	if res, err := e.syncer(src).Run(ctx); err != nil || res.Raised != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	f := e.findings(t)
	got, ok := f["secret:github:4242:9"]
	if !ok || len(f) != 1 || got.kind != "secret" || got.severity != "critical" || got.status != "open" {
		t.Fatalf("%v", f)
	}
	if strings.Contains(got.title+got.detail, "AKIA") || !strings.Contains(got.detail, `"github-secret-scanning"`) {
		t.Fatalf("title/detail %q %s", got.title, got.detail)
	}
	src.secrets = nil
	if res, err := e.syncer(src).Run(ctx); err != nil || res.Resolved != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestUnavailableAlertTypeIsReportedNotResolved(t *testing.T) {
	ctx := context.Background()
	e := setup(t, "acme/crm-api")
	src := &fake{code: []ghalerts.CodeAlert{sqli}, deps: []ghalerts.DependabotAlert{{Number: 1, GHSA: "GHSA-aaaa-bbbb-cccc", Severity: "high", Summary: "s"}},
		secrets: []ghalerts.SecretAlert{{Number: 1, Type: "t"}}}
	if res, err := e.syncer(src).Run(ctx); err != nil || res.Raised != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	// Plan limitations on the next sync: every fetch fails differently.
	src.code, src.deps, src.secrets = nil, nil, nil
	src.codeErr = ghalerts.ErrNotEnabled
	src.depsErr = ghalerts.ErrForbidden
	src.secretsErr = &ghapi.Error{Method: "GET", Path: "/x", Status: 502, Body: `{"message": "` + strings.Repeat("a", 150) + `", "documentation_url": "https://docs.github.com"}`}
	res, err := e.syncer(src).Run(ctx)
	if err != nil || res.Resolved != 0 || res.Raised != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	st := res.Statuses[0]
	if st.CodeScanning != "not_enabled" || st.Dependabot != "forbidden" || st.SecretScanning != "error" {
		t.Fatalf("%+v", st)
	}
	for fp, r := range e.findings(t) {
		if r.status != "open" {
			t.Fatalf("%s resolved by a failed fetch", fp)
		}
	}
	var detail string
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT event::text FROM activities WHERE operation = 'SyncGitHubAlerts' ORDER BY seq DESC LIMIT 1`).Scan(&detail)
	}); err != nil || !strings.Contains(detail, "code scanning not_enabled") || !strings.Contains(detail, "dependabot forbidden") || !strings.Contains(detail, "secret scanning error (HTTP 502: "+strings.Repeat("a", 110)+")") ||
		strings.Contains(detail, "documentation_url") {
		t.Fatalf("activity %q %v", detail, err)
	}
}

func TestVEXSuppressedVulnerabilityIsSkipped(t *testing.T) {
	ctx := context.Background()
	e := setup(t, "acme/crm-api")
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO vex_statements (tenant_id, vulnerability, service_id, status, justification, author) VALUES ($1, 'CVE-2026-7', $2, 'not_affected', 'component_not_present', 'a')`, e.tenant, e.svc)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	src := &fake{deps: []ghalerts.DependabotAlert{{Number: 1, GHSA: "GHSA-aaaa-bbbb-cccc", CVE: "CVE-2026-7", Severity: "high", Summary: "s"}}}
	if res, err := e.syncer(src).Run(ctx); err != nil || res.Raised != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if f := e.findings(t); len(f) != 0 {
		t.Fatalf("suppressed vulnerability raised %v", f)
	}
}

// CodeQL SARIF carries partial fingerprints and GitHub's alert list does
// not, so the two copies of one alert get different fingerprints. Recent
// CodeQL uploads make CI the only source for CodeQL: one open Finding, and
// its SLA clock never restarts.
func TestRecentSARIFUploadMakesCIOnlySourceForTool(t *testing.T) {
	ctx := context.Background()
	e := setup(t, "acme/crm-api")
	sarif := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"ruleId":"go/sql-injection","level":"error","message":{"text":"bad query"},
		"partialFingerprints":{"primaryLocationLineHash":"9f3c1a2b:1"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.go"},"region":{"startLine":7}}}]}]}]}`)
	ingest := func() {
		t.Helper()
		if _, err := (scans.Service{Store: e.s}).Ingest(ctx, e.tenant, e.svc, scans.Upload{Scope: "full", SARIF: sarif}, activity.Actor{Type: activity.ActorPipeline, UID: "pipeline:x"}); err != nil {
			t.Fatal(err)
		}
	}
	type open struct {
		Fingerprint string
		FirstSeen   time.Time
	}
	openFindings := func() []open {
		t.Helper()
		var out []open
		if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT fingerprint, first_seen_at FROM findings WHERE status = 'open'`)
			if err != nil {
				return err
			}
			out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[open])
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	sync := func() ghalerts.ServiceStatus {
		t.Helper()
		res, err := e.syncer(&fake{code: []ghalerts.CodeAlert{sqli}}).Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return res.Statuses[0]
	}

	ingest()
	before := openFindings()
	if len(before) != 1 {
		t.Fatalf("after CI upload: %v", before)
	}
	sync()
	ingest()
	st := sync()
	after := openFindings()
	if len(after) != 1 || after[0] != before[0] {
		t.Fatalf("CI, sync, CI, sync: open Findings %v, want only %v", after, before)
	}
	if st.CodeScanning != ghalerts.StatusSARIF {
		t.Fatalf("code scanning status %q, want %q", st.CodeScanning, ghalerts.StatusSARIF)
	}
}

// codeqlSARIF is the CI copy of sqli. CodeQL SARIF carries partial
// fingerprints, so its Finding never shares a fingerprint with GitHub's copy.
var codeqlSARIF = []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[{"ruleId":"go/sql-injection","level":"error","message":{"text":"bad query"},
	"partialFingerprints":{"primaryLocationLineHash":"9f3c1a2b:1"},
	"locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.go"},"region":{"startLine":7}}}]}]}]}`)

var semgrep = ghalerts.CodeAlert{Number: 2, Tool: "semgrep", RuleID: "go.lang.security.audit.xss", Severity: "medium", Description: "XSS", Path: "web.go", Line: 3, Message: "xss"}

func (e env) ingest(t *testing.T, scope string) {
	t.Helper()
	if _, err := (scans.Service{Store: e.s}).Ingest(context.Background(), e.tenant, e.svc, scans.Upload{Scope: scope, SARIF: codeqlSARIF},
		activity.Actor{Type: activity.ActorPipeline, UID: "pipeline:x"}); err != nil {
		t.Fatal(err)
	}
}

func (e env) sync(t *testing.T, code ...ghalerts.CodeAlert) ghalerts.ServiceStatus {
	t.Helper()
	res, err := e.syncer(&fake{code: code}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res.Statuses[0]
}

type state struct {
	Fingerprint, Status, Resolution, Source string
}

func (e env) states(t *testing.T) []state {
	t.Helper()
	var out []state
	if err := e.s.InTenant(context.Background(), e.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT fingerprint, status, coalesce(resolution, ''), coalesce(detail->>'source', 'ci') FROM findings ORDER BY first_seen_at, fingerprint`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[state])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e env) open(t *testing.T) []state {
	t.Helper()
	var out []state
	for _, s := range e.states(t) {
		if s.Status == "open" {
			out = append(out, s)
		}
	}
	return out
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

// A diff upload says nothing about code it did not scan, so it never makes
// CI the source: GitHub keeps resolving its own Findings.
func TestDiffUploadKeepsGitHubAsSource(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.sync(t, sqli)
	gh := e.open(t)
	if len(gh) != 1 || gh[0].Source != "github" {
		t.Fatalf("after sync: %v", gh)
	}
	e.ingest(t, "diff")
	if st := e.sync(t, sqli); st.CodeScanning != ghalerts.StatusOK {
		t.Fatalf("after a diff upload code scanning is %q, want ok", st.CodeScanning)
	}
	e.sync(t) // fixed on GitHub
	for _, s := range e.states(t) {
		if s.Fingerprint == gh[0].Fingerprint && s.Status != "resolved" {
			t.Fatalf("GitHub Finding still open after the alert was fixed: %v", e.states(t))
		}
	}
}

// A full CI upload takes the tool over: GitHub's copy resolves as handed
// over, and only CI's copy stays open. Other tools are not touched.
func TestFullUploadHandsToolOverToCI(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.sync(t, sqli, semgrep)
	e.ingest(t, "full")
	if st := e.sync(t, sqli, semgrep); st.CodeScanning != ghalerts.StatusSARIF {
		t.Fatalf("code scanning %q, want sarif", st.CodeScanning)
	}
	var codeqlOpen, semgrepOpen int
	for _, s := range e.states(t) {
		switch {
		case s.Source == "github" && strings.HasPrefix(s.Fingerprint, "scan:codeql:"):
			if s.Status != "resolved" || s.Resolution != "source handed over to CI uploads" {
				t.Fatalf("GitHub CodeQL Finding %+v, want resolved as handed over to CI", s)
			}
		case strings.HasPrefix(s.Fingerprint, "scan:codeql:") && s.Status == "open":
			codeqlOpen++
		case strings.HasPrefix(s.Fingerprint, "scan:semgrep:") && s.Status == "open":
			semgrepOpen++
		}
	}
	if codeqlOpen != 1 || semgrepOpen != 1 || len(e.open(t)) != 2 {
		t.Fatalf("want one open Finding per alert: %v", e.states(t))
	}
}

// CI stops uploading: after 30 days GitHub takes the tool back, CI's copy
// resolves as handed over, and GitHub's copy is the only open one.
func TestSilentCIHandsToolBackToGitHub(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.ingest(t, "full")
	e.sync(t, sqli)
	if _, err := storetest.Superuser(t, e.s).Exec(context.Background(), `UPDATE scan_runs SET created_at = now() - interval '31 days'`); err != nil {
		t.Fatal(err)
	}
	if st := e.sync(t, sqli); st.CodeScanning != ghalerts.StatusOK {
		t.Fatalf("code scanning %q, want ok", st.CodeScanning)
	}
	for _, s := range e.states(t) {
		if s.Source == "ci" && (s.Status != "resolved" || s.Resolution != "source handed over to GitHub code scanning") {
			t.Fatalf("CI Finding %+v, want resolved as handed over to GitHub", s)
		}
	}
	if open := e.open(t); len(open) != 1 || open[0].Source != "github" {
		t.Fatalf("want only GitHub's copy open: %v", e.states(t))
	}
	if d := e.lastSyncDetail(t); !strings.Contains(d, "codeql handed over from CI to GitHub (1)") {
		t.Fatalf("activity %q", d)
	}
	e.sync(t) // fixed on GitHub
	if open := e.open(t); len(open) != 0 {
		t.Fatalf("still open after the fix on GitHub: %v", open)
	}
}
