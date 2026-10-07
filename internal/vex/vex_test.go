package vex_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/store/storetest"
	"github.com/hx-thanadej/keel/internal/vex"
)

func p(s string) *string { return &s }

func TestVEXSuppressesAndExports(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var svc, rel string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'CRM API') RETURNING id`, tenant, project, team).Scan(&svc); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO releases (tenant_id, service_id, version, images, created_by) VALUES ($1, $2, '1.0.0', '[{"name":"acme.tencentcloudcr.com/tat/crm-api","digest":"sha256:aa"}]', 'p') RETURNING id`, tenant, svc).Scan(&rel)
	}); err != nil {
		t.Fatal(err)
	}
	sarif := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"grype","rules":[{"id":"CVE-2026-2222","properties":{"security-severity":"9.1"}}]}},"results":[{"ruleId":"CVE-2026-2222","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"go.sum"}}}]}]}]}`)
	ing := scans.Service{Store: s}
	ci := activity.Actor{Type: activity.ActorPipeline, UID: "pipeline:x"}
	if run, err := ing.Ingest(ctx, tenant, svc, scans.Upload{Scope: "full", SARIF: sarif}, ci); err != nil || run.Raised != 1 {
		t.Fatalf("%+v %v", run, err)
	}
	v := vex.Service{Store: s}
	dev := activity.Actor{Type: activity.ActorHuman, UID: "user:dev"}
	if _, err := v.Record(ctx, tenant, vex.Statement{Vulnerability: "CVE-2026-2222", ServiceID: svc, Status: "not_affected"}, dev); !errors.Is(err, vex.ErrInvalid) {
		t.Fatalf("not_affected without justification: %v", err)
	}
	if _, err := v.Record(ctx, tenant, vex.Statement{Vulnerability: "CVE-2026-2222", ServiceID: svc, Status: "not_affected", Justification: p("because")}, dev); !errors.Is(err, vex.ErrInvalid) {
		t.Fatalf("unknown justification: %v", err)
	}
	if _, err := v.Record(ctx, tenant, vex.Statement{Vulnerability: "CVE-2026-2222", ServiceID: svc, Status: "not_affected", Justification: p("vulnerable_code_not_in_execute_path")}, dev); err != nil {
		t.Fatal(err)
	}
	open := func() int {
		var n int
		if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE status = 'open'`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if open() != 0 {
		t.Fatal("Finding not resolved by VEX")
	}
	// The next scan does not raise it again.
	if run, _ := ing.Ingest(ctx, tenant, svc, scans.Upload{Scope: "full", SARIF: sarif}, ci); run.Raised != 0 || open() != 0 {
		t.Fatalf("re-raised after VEX: %+v", run)
	}
	// Later evidence: affected (needs an action). It counts again on the next scan.
	if _, err := v.Record(ctx, tenant, vex.Statement{Vulnerability: "CVE-2026-2222", ServiceID: svc, Status: "affected", ActionStatement: p("upgrade to 1.2.3")}, dev); err != nil {
		t.Fatal(err)
	}
	if run, _ := ing.Ingest(ctx, tenant, svc, scans.Upload{Scope: "full", SARIF: sarif}, ci); run.Raised != 1 {
		t.Fatalf("affected not re-raised: %+v", run)
	}
	doc, err := v.Document(ctx, tenant, rel, "keel")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Context    string `json:"@context"`
		Statements []struct {
			Vulnerability struct{ Name string } `json:"vulnerability"`
			Status        string                `json:"status"`
			Products      []map[string]string   `json:"products"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(doc, &d); err != nil || d.Context != "https://openvex.dev/ns/v0.2.0" || len(d.Statements) != 1 || d.Statements[0].Status != "affected" ||
		d.Statements[0].Products[0]["@id"] != "pkg:oci/acme.tencentcloudcr.com/tat/crm-api@sha256:aa" {
		t.Fatalf("doc %s %v", doc, err)
	}
}
