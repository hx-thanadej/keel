package sbom_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/sbom"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

const complete = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"timestamp":"2026-10-01T00:00:00Z","authors":[{"name":"keel-build"}],"lifecycles":[{"phase":"build"}],"tools":{"components":[{"name":"syft","version":"1.33.0"}]}},
 "signature":{"algorithm":"ES256","value":"x"},
 "components":[
  {"name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1","supplier":{"name":"Apache"},"hashes":[{"alg":"SHA-256","content":"a"}],"licenses":[{"license":{"id":"Apache-2.0"}}]},
  {"name":"x/net","version":"0.1.0","purl":"pkg:golang/golang.org/x/net@0.1.0","supplier":{"name":"Go"},"hashes":[{"alg":"SHA-256","content":"b"}],"licenses":[{"license":{"id":"BSD-3-Clause"}}]}],
 "dependencies":[{"ref":"root","dependsOn":[]}]}`

func TestMinimumElements(t *testing.T) {
	d, err := sbom.Parse([]byte(complete))
	if err != nil || len(d.Gaps) != 0 || len(d.Components) != 2 || d.Tool != "syft 1.33.0" || d.Components[1].Ecosystem != "golang" {
		t.Fatalf("%+v %v", d, err)
	}
	bare := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"a","purl":"pkg:npm/a@1"},{"name":"b"}]}`
	d, _ = sbom.Parse([]byte(bare))
	joined := strings.Join(d.Gaps, "|")
	for _, want := range []string{"SBOM Author", "SBOM Timestamp", "SBOM Tool Name", "Component Identifiers missing on 1 of 2", "Component Hash missing on 2 of 2", "Component Dependency Relationship"} {
		if !strings.Contains(joined, want) {
			t.Errorf("gaps lack %q: %v", want, d.Gaps)
		}
	}
	if _, err := sbom.Parse([]byte(`{"hello":"world"}`)); err == nil {
		t.Fatal("non-SBOM accepted")
	}
}

func fakeOSV(t *testing.T, vulnerable map[string][]string, details map[string]map[string]any) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Queries []struct {
				Package struct{ Purl string } `json:"package"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		var results []any
		for _, q := range in.Queries {
			var vs []any
			for _, id := range vulnerable[q.Package.Purl] {
				vs = append(vs, map[string]string{"id": id})
			}
			results = append(results, map[string]any{"vulns": vs})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(details[r.PathValue("id")])
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestSubmitWhereAndOSVMatching(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var rel, svc string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project, env string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'CRM API') RETURNING id`, tenant, project, team).Scan(&svc); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&env); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO releases (tenant_id, service_id, version, images, created_by) VALUES ($1, $2, '1.0.0', '[]', 'p') RETURNING id`, tenant, svc).Scan(&rel); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO promotions (tenant_id, release_id, environment_id, state, requested_by, deployed_at) VALUES ($1, $2, $3, 'deployed', 'u', now())`, tenant, rel, env)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	by := activity.Actor{Type: activity.ActorPipeline, UID: "pipeline:x"}
	sum, err := (sbom.Service{Store: s}).Submit(ctx, tenant, rel, []byte(complete), by)
	if err != nil || sum.Components != 2 || len(sum.Gaps) != 0 {
		t.Fatalf("%+v %v", sum, err)
	}
	where, err := (sbom.Service{Store: s}).Where(ctx, tenant, "log4j-core")
	if err != nil || len(where) != 1 || where[0].Service != "crm-api" || len(where[0].Environments) != 1 || where[0].Environments[0] != "prod" {
		t.Fatalf("where %+v %v", where, err)
	}

	log4j := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	osv := fakeOSV(t, map[string][]string{log4j: {"GHSA-jfh8-c2jp-5v3q"}},
		map[string]map[string]any{"GHSA-jfh8-c2jp-5v3q": {"id": "GHSA-jfh8-c2jp-5v3q", "summary": "Log4Shell", "aliases": []string{"CVE-2021-44228"}, "database_specific": map[string]string{"severity": "CRITICAL"}}})
	tenants := func(context.Context) ([]string, error) { return []string{tenant}, nil }
	m := sbom.Matcher{Store: s, Tenants: tenants, OSV: sbom.OSVClient{BaseURL: osv.URL}, Now: storetest.Clock()}
	res, err := m.Run(ctx)
	if err != nil || res.Components != 2 || res.Raised != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	var sev, title string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT severity, title FROM findings WHERE fingerprint = $1 AND status = 'open'`, "vuln:CVE-2021-44228:"+svc).Scan(&sev, &title)
	}); err != nil || sev != "critical" || !strings.Contains(title, "Log4Shell") {
		t.Fatalf("finding %s %s %v", sev, title, err)
	}
	// The advisory is withdrawn / the component fixed: the Finding resolves.
	m.OSV = sbom.OSVClient{BaseURL: fakeOSV(t, nil, nil).URL}
	if res, err := m.Run(ctx); err != nil || res.Resolved != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	storetest.ClockedFindings(t, s, "vulnerability")
}
