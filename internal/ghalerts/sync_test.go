package ghalerts_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/ghalerts"
	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// fake is a Source with canned Dependabot and secret scanning alerts. Code
// scanning goes to code (a GitHub client on a test server) when set, and
// lists no analyses otherwise.
type fake struct {
	code             ghalerts.Source
	deps             []ghalerts.DependabotAlert
	secrets          []ghalerts.SecretAlert
	codeErr, depsErr error
	secretsErr       error
	repos            []string
}

func (f *fake) Analyses(ctx context.Context, repo string) ([]ghalerts.Analysis, error) {
	f.repos = append(f.repos, repo)
	if f.code == nil || f.codeErr != nil {
		return nil, f.codeErr
	}
	return f.code.Analyses(ctx, repo)
}
func (f *fake) SARIF(ctx context.Context, repo string, id int64) ([]byte, error) {
	return f.code.SARIF(ctx, repo, id)
}
func (f *fake) DismissedCodeAlerts(ctx context.Context, repo string) ([]ghalerts.DismissedAlert, error) {
	if f.code == nil {
		return nil, nil
	}
	return f.code.DismissedCodeAlerts(ctx, repo)
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
	gh := newGitHub(t)
	gh.analysis("codeql", "", codeql(sqli))
	src := &fake{code: gh.source(), deps: []ghalerts.DependabotAlert{{Number: 1, GHSA: "GHSA-aaaa-bbbb-cccc", Severity: "high", Summary: "s"}},
		secrets: []ghalerts.SecretAlert{{Number: 1, Type: "t"}}}
	if res, err := e.syncer(src).Run(ctx); err != nil || res.Raised != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	// Plan limitations on the next sync: every fetch fails differently.
	gh.analysis("codeql", "", codeql())
	src.deps, src.secrets = nil, nil
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
