package catalogsync_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/catalogsync"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

const crmDescriptor = `apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: crm-api
  title: CRM API
  annotations:
    keel.dev/tenant: tat
spec:
  type: service
  lifecycle: production
  owner: group:crm
  system: tat-crm
---
apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: crm-worker
  annotations:
    keel.dev/tenant: tat
spec:
  type: service
  lifecycle: experimental
  owner: crm
  system: tat-crm
`

func TestParse(t *testing.T) {
	cs, err := catalogsync.Parse([]byte(crmDescriptor))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 {
		t.Fatalf("components = %d", len(cs))
	}
	c := cs[0]
	if c.Name != "crm-api" || c.Title != "CRM API" || c.Tenant != "tat" || c.Owner != "crm" || c.System != "tat-crm" || c.Lifecycle != "production" || c.Type != "service" {
		t.Errorf("parsed %+v", c)
	}
	if cs[1].Owner != "crm" {
		t.Errorf("owner without group: prefix = %q", cs[1].Owner)
	}
	if _, err := catalogsync.Parse([]byte("kind: [unclosed")); err == nil {
		t.Error("want error for invalid yaml")
	}
}

// fakeGitHub serves the two REST endpoints the sync uses.
func fakeGitHub(t *testing.T, files map[string]string, token string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{owner}/repos", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("page") != "" && r.URL.Query().Get("page") != "1" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		var repos []map[string]any
		for _, name := range []string{"crm", "no-descriptor", "orphan", "bad-yaml"} {
			repos = append(repos, map[string]any{"name": name, "full_name": r.PathValue("owner") + "/" + name, "archived": false, "html_url": "https://github.com/" + r.PathValue("owner") + "/" + name})
		}
		repos = append(repos, map[string]any{"name": "old", "full_name": r.PathValue("owner") + "/old", "archived": true})
		_ = json.NewEncoder(w).Encode(repos)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/contents/{path}", func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.PathValue("repo")]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(body))})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func seed(t *testing.T, s *store.Store) (home, tat string) {
	t.Helper()
	ctx := context.Background()
	home, _ = s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	tat, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	var team string
	if err := s.InTenant(ctx, home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, home).Scan(&team)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM')`, tat, team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return home, tat
}

func TestSyncCreatesServicesAndReportsProblems(t *testing.T) {
	s := storetest.New(t)
	home, tat := seed(t, s)
	gh := fakeGitHub(t, map[string]string{
		"crm":      crmDescriptor,
		"orphan":   "apiVersion: backstage.io/v1alpha1\nkind: Component\nmetadata:\n  name: orphan\n  annotations:\n    keel.dev/tenant: tat\nspec:\n  system: tat-crm\n",
		"bad-yaml": "kind: [",
	}, "tok")
	syncer := &catalogsync.Syncer{Store: s, Source: &catalogsync.GitHub{BaseURL: gh.URL, Owner: "hx", Token: "tok", Client: gh.Client()}}

	rep, err := syncer.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Repos != 4 || rep.Upserted != 2 {
		t.Fatalf("report %+v, want 4 repos (archived skipped), 2 services", rep)
	}
	want := map[string]string{"hx/no-descriptor": "no catalog-info.yaml", "hx/orphan": "no owner", "hx/bad-yaml": "invalid"}
	for repo, msg := range want {
		found := false
		for _, p := range rep.Problems {
			if p.Repo == repo && strings.Contains(p.Problem, msg) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing problem for %s containing %q in %+v", repo, msg, rep.Problems)
		}
	}

	var n int
	var lifecycle, repoURL string
	err = s.InTenant(context.Background(), tat, func(tx pgx.Tx) error {
		if err := tx.QueryRow(context.Background(), `SELECT count(*) FROM services`).Scan(&n); err != nil {
			return err
		}
		return tx.QueryRow(context.Background(), `SELECT lifecycle, repository FROM services WHERE slug = 'crm-api'`).Scan(&lifecycle, &repoURL)
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || lifecycle != "production" || repoURL != "https://github.com/hx/crm" {
		t.Errorf("services=%d lifecycle=%q repo=%q", n, lifecycle, repoURL)
	}

	// Second run updates in place, no duplicates; activity per change only.
	rep, err = syncer.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Upserted != 0 || rep.Unchanged != 2 {
		t.Errorf("second run %+v, want 0 upserted, 2 unchanged", rep)
	}
	var acts int
	_ = s.InTenant(context.Background(), tat, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM activities WHERE type = 'keel.service.synced'`).Scan(&acts)
	})
	if acts != 2 {
		t.Errorf("sync activities = %d, want 2", acts)
	}

	// The last run's report is stored in the home Tenant.
	var problems int
	_ = s.InTenant(context.Background(), home, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT jsonb_array_length(report->'problems') FROM catalog_sync_runs ORDER BY started_at DESC LIMIT 1`).Scan(&problems)
	})
	if problems != 3 {
		t.Errorf("stored problems = %d, want 3", problems)
	}
}

func TestUnknownTenantOrProjectReported(t *testing.T) {
	s := storetest.New(t)
	seed(t, s)
	gh := fakeGitHub(t, map[string]string{
		"crm":    strings.ReplaceAll(crmDescriptor, "system: tat-crm", "system: nope"),
		"orphan": strings.ReplaceAll(crmDescriptor, "keel.dev/tenant: tat", "keel.dev/tenant: ghost"),
	}, "tok")
	syncer := &catalogsync.Syncer{Store: s, Source: &catalogsync.GitHub{BaseURL: gh.URL, Owner: "hx", Token: "tok", Client: gh.Client()}}
	rep, err := syncer.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, p := range rep.Problems {
		all += p.Repo + ": " + p.Problem + "\n"
	}
	if !strings.Contains(all, `unknown project "nope"`) || !strings.Contains(all, `unknown tenant "ghost"`) {
		t.Errorf("problems:\n%s", all)
	}
	if rep.Upserted != 0 {
		t.Errorf("upserted %d, want 0", rep.Upserted)
	}
}
