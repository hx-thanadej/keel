package ghalerts_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// Results of the scanners CI keeps running under a github source.
const (
	leak = `{"ruleId":"aws-access-token","level":"error","message":{"text":"key"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":".env"},"region":{"startLine":2}}}]}`
	iac  = `{"ruleId":"CKV_AWS_20","level":"error","message":{"text":"public bucket"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.tf"},"region":{"startLine":4}}}]}`
	wf   = `{"ruleId":"artipacked","level":"warning","message":{"text":"persisted credentials"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":".github/workflows/ci.yml"},"region":{"startLine":9}}}]}`
)

func (e env) openCount(t *testing.T, prefix string) int {
	t.Helper()
	return len(open(e.byPrefix(t, prefix)))
}

// unexceptedOpen counts the open Findings the promotion gate would count.
func (e env) unexceptedOpen(t *testing.T) int {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE status = 'open' AND NOT finding_excepted(findings, $1)`, e.now()).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// switchTo is the store half of SetCodeScanningSource.
func (e env) switchTo(t *testing.T, source string, hold time.Duration) int {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := e.s.InTenant(ctx, e.tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE services SET code_scanning_source = $2 WHERE id = $1`, e.svc, source); err != nil {
			return err
		}
		time.Sleep(hold)
		var err error
		n, err = scans.ResolveOtherCodeScanning(ctx, tx, e.svc, source, e.now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// A CVE-rule alert is not a code scanning alert: under github the CVE stays
// the single Finding CI raised, so its Exception still clears the gate.
func TestGitHubSourceSkipsCVERuleAlerts(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.upload(t, "full", sarifOf("Trivy", cve))
	vuln := "vuln:CVE-2026-1111:" + e.svc
	got := e.byPrefix(t, vuln)
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	e.except(t, got[0].ID)
	e.switchTo(t, scans.SourceGitHub, 0)

	gh := newGitHub(t)
	gh.alert(9, "CVE-2026-1111", "go.sum", 1)
	gh.alert(10, "go/sql-injection", "db.go", 7)
	e.run(t, &fake{code: gh.source()})

	if got := e.byPrefix(t, "scan:github:4242:9"); len(got) != 0 {
		t.Fatalf("the CVE alert raised a second Finding: %+v", got)
	}
	if got := e.byPrefix(t, "scan:github:4242:10"); len(got) != 1 {
		t.Fatalf("the code scanning alert was skipped: %+v", got)
	}
	if got := e.byPrefix(t, vuln); len(got) != 1 || got[0].Status != "open" || !e.coveredOpen(t, vuln) {
		t.Fatalf("%+v", got)
	}
	if n := e.unexceptedOpen(t); n != 1 { // the SQL injection alone
		t.Fatalf("gate sees %d unexcepted open Findings, want 1", n)
	}
}

// The source covers code scanning kinds only: secrets, IaC and workflow
// results keep their Findings across a switch, and CI keeps resolving them.
func TestSwitchToGitHubLeavesSecretIaCAndWorkflowFindings(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.upload(t, "full", sarifOf("CodeQL", sqli))
	e.upload(t, "full", sarifOf("Gitleaks", leak))
	e.upload(t, "full", sarifOf("Checkov", iac))
	e.upload(t, "full", sarifOf("Zizmor", wf))

	if n := e.switchTo(t, scans.SourceGitHub, 0); n != 1 {
		t.Fatalf("resolved %d, want only the CodeQL Finding", n)
	}
	for _, p := range []string{"scan:gitleaks:", "scan:checkov:", "scan:zizmor:"} {
		if e.openCount(t, p) != 1 {
			t.Fatalf("%s Finding closed by the switch: %+v", p, e.byPrefix(t, p))
		}
	}
	if e.openCount(t, "scan:codeql:") != 0 {
		t.Fatal("CodeQL Finding stayed open")
	}
	storetest.ClockedFindings(t, e.s, "sast")

	e.upload(t, "full", sarifOf("Gitleaks", leak))
	if e.openCount(t, "scan:gitleaks:") != 1 {
		t.Fatalf("CI stopped reporting the secret: %+v", e.byPrefix(t, "scan:gitleaks:"))
	}
	for _, tool := range []string{"Gitleaks", "Checkov", "Zizmor"} {
		e.upload(t, "full", sarifOf(tool))
	}
	for _, p := range []string{"scan:gitleaks:", "scan:checkov:", "scan:zizmor:"} {
		if got := e.byPrefix(t, p); len(got) != 1 || got[0].Status != "resolved" {
			t.Fatalf("CI full upload did not resolve %s: %+v", p, got)
		}
	}
}

// Under github a diff upload raises nothing for code scanning kinds, and
// still raises what the source does not cover.
func TestDiffUploadUnderGitHubRaisesNoCodeScanningFindings(t *testing.T) {
	e := setup(t, "acme/crm-api")
	e.switchTo(t, scans.SourceGitHub, 0)
	run, err := e.scans().Ingest(context.Background(), e.tenant, e.svc,
		scans.Upload{Scope: "diff", CommitSHA: "ci", SARIF: []byte(sarifOf("CodeQL", sqli, xss))}, ci)
	if err != nil || run.Raised != 0 {
		t.Fatalf("raised %d, %v", run.Raised, err)
	}
	run, err = e.scans().Ingest(context.Background(), e.tenant, e.svc,
		scans.Upload{Scope: "diff", CommitSHA: "ci", SARIF: []byte(sarifOf("Gitleaks", leak))}, ci)
	if err != nil || run.Raised != 1 {
		t.Fatalf("secret raised %d, %v", run.Raised, err)
	}
	if n := e.openCount(t, "scan:codeql:"); n != 0 {
		t.Fatalf("%d CodeQL Findings", n)
	}
}

// A switch and a CI ingest race on the Service row: whichever order they
// serialise in, CI's code scanning Finding is not left open under github,
// and the secret CI reports still is.
func TestSourceSwitchRacingCIIngestNeverLeavesBothSidesOpen(t *testing.T) {
	e := setup(t, "acme/crm-api")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		e.switchTo(t, scans.SourceGitHub, 400*time.Millisecond)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond) // the switch holds the row by now
		e.upload(t, "full", sarifOf("CodeQL", sqli))
		e.upload(t, "full", sarifOf("Gitleaks", leak))
	}()
	wg.Wait()
	if n := e.openCount(t, "scan:codeql:"); n != 0 {
		t.Fatalf("%d CI code scanning Findings open under github", n)
	}
	if n := e.openCount(t, "scan:gitleaks:"); n != 1 {
		t.Fatalf("%d secret Findings open, want 1", n)
	}
	gh := newGitHub(t)
	gh.alert(5, "go/sql-injection", "db.go", 7)
	e.run(t, &fake{code: gh.source()})
	if n := e.openCount(t, "scan:"); n != 2 {
		t.Fatalf("%+v", e.byPrefix(t, "scan:"))
	}
}
