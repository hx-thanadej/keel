package controls_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/controls"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// ids expands each clause family and how many clauses it has, as published:
// ISO/IEC 27001:2022 Annex A themes 5 to 8, and the AICPA Trust Services
// Criteria CC1 to CC9, A1 and C1.
func ids(series []struct {
	prefix string
	n      int
}) []string {
	var out []string
	for _, s := range series {
		for i := 1; i <= s.n; i++ {
			out = append(out, fmt.Sprintf("%s%d", s.prefix, i))
		}
	}
	return out
}

var (
	annexA = ids([]struct {
		prefix string
		n      int
	}{{"5.", 37}, {"6.", 8}, {"7.", 14}, {"8.", 34}})
	tsc = ids([]struct {
		prefix string
		n      int
	}{{"CC1.", 5}, {"CC2.", 3}, {"CC3.", 4}, {"CC4.", 2}, {"CC5.", 3}, {"CC6.", 8}, {"CC7.", 5}, {"CC8.", 1}, {"CC9.", 2}, {"A1.", 3}, {"C1.", 2}})
)

func TestRegistryListsEveryAnnexAControlAndTrustServicesCriterion(t *testing.T) {
	r, err := controls.Load()
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "keel-controls@2" {
		t.Fatalf("version %s", r.Version)
	}
	got := map[string][]string{}
	for _, c := range r.Controls {
		got[c.Framework] = append(got[c.Framework], c.ID)
	}
	for fw, want := range map[string][]string{"ISO27001": annexA, "SOC2": tsc} {
		if strings.Join(got[fw], ",") != strings.Join(want, ",") {
			t.Errorf("%s: got %d controls %v, want %d %v", fw, len(got[fw]), got[fw], len(want), want)
		}
	}
	if len(annexA) != 93 || len(tsc) != 38 {
		t.Fatalf("expected lists: %d Annex A, %d TSC", len(annexA), len(tsc))
	}
}

func TestRegistryRejectsBadMappings(t *testing.T) {
	head := "version: keel-controls@2\nframeworks: [{id: ISO27001, name: ISO}]\npolicies: [{name: keel-authz@1, point: api, description: d}]\ncontrols:\n"
	for name, tc := range map[string]struct{ controls, want string }{
		"unknown policy":    {`  - {framework: ISO27001, id: "5.15", title: t, covered_by: [keel-nope@1]}`, "unknown policy keel-nope@1"},
		"duplicate clause":  {"  - {framework: ISO27001, id: \"5.15\", title: t, covered_by: [keel-authz@1]}\n  - {framework: ISO27001, id: \"5.15\", title: t, covered_by: [keel-authz@1]}", "listed twice"},
		"unknown framework": {`  - {framework: SOC3, id: "CC6.1", title: t, covered_by: [keel-authz@1]}`, "unknown framework"},
		"silent gap":        {`  - {framework: ISO27001, id: "6.1", title: t, covered_by: []}`, "gap_reason"},
		"covered with gap":  {`  - {framework: ISO27001, id: "5.15", title: t, covered_by: [keel-authz@1], gap_reason: r}`, "gap_reason"},
		"@1 field name":     {`  - {framework: ISO27001, id: "5.15", title: t, policies: [keel-authz@1]}`, "policies"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := controls.Parse([]byte(head + tc.controls)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := controls.Parse([]byte(head + `  - {framework: ISO27001, id: "5.15", title: t, covered_by: [keel-authz@1]}`)); err != nil {
		t.Fatalf("valid registry: %v", err)
	}
}

func TestReportCountsCoveredAndGapsPerFramework(t *testing.T) {
	r, err := controls.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	// One Service with a scan: keel-scans@1 reaches it, as do the Policies
	// that apply to every Service (authz, findings, activity). Nothing else.
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		var svc string
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'CRM API') RETURNING id`, tenant, project, team).Scan(&svc); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO scan_runs (tenant_id, service_id, tool, scope, results, raised, resolved, uploaded_by) VALUES ($1, $2, 'grype', 'full', 0, 0, 0, 'p')`, tenant, svc)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rep, err := controls.Service{Store: s, Registry: r}.Report(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]controls.ControlView{}
	for _, c := range rep.Controls {
		byID[c.Framework+" "+c.ID] = c
	}
	if rep.Services != 1 || byID["SSDF PW.7.2"].Gap || !byID["SLSA SLSA-BUILD-L3"].Gap || !byID["SSDF PO.1.1"].Gap {
		t.Fatalf("services %d PW.7.2 %+v SLSA-L3 %+v PO.1.1 %+v", rep.Services, byID["SSDF PW.7.2"], byID["SLSA SLSA-BUILD-L3"], byID["SSDF PO.1.1"])
	}
	if c := byID["ISO27001 8.8"]; c.Gap || len(c.Coverage) != 4 {
		t.Fatalf("8.8 %+v", c)
	}
	if c := byID["ISO27001 6.1"]; !c.Gap || c.GapReason == "" || len(c.Coverage) != 0 {
		t.Fatalf("6.1 %+v", c)
	}
	if c := byID["ISO27001 8.2"]; !c.Gap || len(c.Coverage) != 2 {
		t.Fatalf("8.2 is mapped but reaches no Service: %+v", c)
	}
	counts := map[string]controls.FrameworkCoverage{}
	for _, f := range rep.Frameworks {
		counts[f.ID] = f
	}
	for fw, want := range map[string][4]int{
		// controls, mapped, covered, gaps
		"ISO27001": {93, 22, 14, 79},
		"SOC2":     {38, 7, 5, 33},
		"SSDF":     {11, 10, 4, 7},
	} {
		f := counts[fw]
		if got := [4]int{f.Controls, f.Mapped, f.Covered, f.Gaps}; got != want {
			t.Errorf("%s: got %v, want %v", fw, got, want)
		}
	}

	soc2, ok := rep.Only("SOC2")
	if !ok || len(soc2.Frameworks) != 1 || soc2.Frameworks[0] != counts["SOC2"] || len(soc2.Controls) != 38 {
		t.Fatalf("only SOC2: %v %+v %d", ok, soc2.Frameworks, len(soc2.Controls))
	}
	for _, c := range soc2.Controls {
		if c.Framework != "SOC2" {
			t.Fatalf("SOC2 report holds %s %s", c.Framework, c.ID)
		}
	}
	if _, ok := rep.Only("SOC3"); ok {
		t.Fatal("unknown framework accepted")
	}
}
