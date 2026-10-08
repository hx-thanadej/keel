package apply_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/apply"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// fakeGitHub keeps one repo "hx/tat-crm" in memory.
type fakeGitHub struct {
	mu       sync.Mutex
	files    map[string]string // path → content on main
	branches map[string]map[string]string
	prs      []map[string]any
}

func (f *fakeGitHub) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/hx/tat-crm", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
	})
	mux.HandleFunc("GET /repos/hx/tat-crm/git/trees/main", func(w http.ResponseWriter, _ *http.Request) {
		var tree []map[string]string
		for p := range f.files {
			tree = append(tree, map[string]string{"path": p, "type": "blob"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tree": tree})
	})
	mux.HandleFunc("GET /repos/hx/tat-crm/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		c, ok := f.files[r.PathValue("path")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"content": base64.StdEncoding.EncodeToString([]byte(c)), "encoding": "base64", "sha": "sha-" + r.PathValue("path")})
	})
	mux.HandleFunc("GET /repos/hx/tat-crm/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": "main-sha"}})
	})
	mux.HandleFunc("POST /repos/hx/tat-crm/git/refs", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.branches[strings.TrimPrefix(in["ref"], "refs/heads/")] = map[string]string{}
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("PUT /repos/hx/tat-crm/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		b, _ := base64.StdEncoding.DecodeString(in["content"])
		_, onMain := f.files[r.PathValue("path")]
		if in["sha"] != "sha-"+r.PathValue("path") && (onMain || in["sha"] != "") { // no sha creates a file
			http.Error(w, "sha mismatch", http.StatusConflict)
			return
		}
		f.mu.Lock()
		f.branches[in["branch"]][r.PathValue("path")] = string(b)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /repos/hx/tat-crm/pulls", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &in)
		f.mu.Lock()
		in["number"] = len(f.prs) + 1
		in["html_url"] = "https://github.com/hx/tat-crm/pull/" + string(rune('0'+len(f.prs)+1))
		in["state"], in["merged"] = "open", false
		f.prs = append(f.prs, in)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(in)
	})
	mux.HandleFunc("GET /repos/hx/tat-crm/pulls/{n}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.prs[0])
	})
	return mux
}

const deploy = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: app
          image: api
          resources:
            requests:
              cpu: 2000m
              memory: 4096Mi
`

func setup(t *testing.T, files map[string]string, repo string) (apply.Applier, *fakeGitHub, string, string) {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	home, _ := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var team, project string
	_ = s.InTenant(ctx, home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, home).Scan(&team)
	})
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tat, team).Scan(&project); err != nil {
			return err
		}
		if repo == "" {
			return nil
		}
		_, err := tx.Exec(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository) VALUES ($1, $2, $3, 'api', 'API', $4)`, tat, project, team, repo)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	gh := &fakeGitHub{files: files, branches: map[string]map[string]string{}}
	srv := httptest.NewServer(gh.handler(t))
	t.Cleanup(srv.Close)
	recs := rightsize.Service{Store: s}
	r, _, err := recs.Upsert(ctx, tat, rightsize.Recommendation{Source: "engine:k8s", Provider: "k8s", ResourceID: "tke/tat-crm-prod/api/app", ResourceType: "k8s_workload",
		ProjectID: &project, Action: "resize_requests", Current: map[string]any{"cpu": "2000m", "memory": "4096Mi"}, Recommended: map[string]any{"cpu": "410m", "memory": "1531Mi"},
		Evidence: map[string]any{"workload": "api", "container": "app", "lookback_days": 21, "replicas": 2}, MonthlySavings: "21516.00", Currency: "THB", Confidence: 0.9})
	if err != nil {
		t.Fatal(err)
	}
	return apply.Applier{Recs: recs, Git: apply.GitHub{BaseURL: srv.URL, Token: "t", Client: srv.Client()}}, gh, tat, r.ID
}

var by = activity.Actor{Type: activity.ActorHuman, UID: "user:lead@harmonyx.co"}

func TestApplyOpensPullRequestThenTracksMerge(t *testing.T) {
	a, gh, tat, id := setup(t, map[string]string{"k8s/prod/api.yaml": deploy, "README.md": "x", "k8s/prod/other.yaml": "kind: ConfigMap\n"}, "https://github.com/hx/tat-crm")
	ctx := context.Background()
	url, err := a.Apply(ctx, tat, id, by)
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://github.com/hx/tat-crm/pull/1" || len(gh.prs) != 1 {
		t.Fatalf("url %s prs %d", url, len(gh.prs))
	}
	branch := "keel/rightsize-" + id[len(id)-8:]
	got := gh.branches[branch]["k8s/prod/api.yaml"]
	if !strings.Contains(got, "cpu: 410m") || !strings.Contains(got, "memory: 1531Mi") {
		t.Fatalf("committed file:\n%s", got)
	}
	if body := gh.prs[0]["body"].(string); !strings.Contains(body, "21516.00 THB/month") || gh.prs[0]["base"] != "main" || gh.prs[0]["head"] != branch {
		t.Fatalf("pr %+v", gh.prs[0])
	}
	// Applying again returns the same PR.
	if again, _ := a.Apply(ctx, tat, id, by); again != url || len(gh.prs) != 1 {
		t.Fatal("re-apply opened another PR")
	}
	r, _ := a.Recs.Get(ctx, tat, id)
	if r.State != "accepted" || r.PRURL == nil {
		t.Fatalf("state %s pr %v", r.State, r.PRURL)
	}
	// Merge → applied.
	gh.prs[0]["merged"], gh.prs[0]["state"] = true, "closed"
	res, err := a.Sync(ctx)
	if err != nil || res.Applied != 1 {
		t.Fatalf("sync %+v %v", res, err)
	}
	r, _ = a.Recs.Get(ctx, tat, id)
	if r.State != "applied" {
		t.Fatalf("state after merge %s", r.State)
	}
}

func TestClosedPullRequestReopens(t *testing.T) {
	a, gh, tat, id := setup(t, map[string]string{"api.yaml": deploy}, "https://github.com/hx/tat-crm")
	ctx := context.Background()
	if _, err := a.Apply(ctx, tat, id, by); err != nil {
		t.Fatal(err)
	}
	gh.prs[0]["state"] = "closed"
	res, err := a.Sync(ctx)
	if err != nil || res.Reopened != 1 {
		t.Fatalf("sync %+v %v", res, err)
	}
	if r, _ := a.Recs.Get(ctx, tat, id); r.State != "open" || r.PRURL != nil {
		t.Fatalf("after close: %s %v", r.State, r.PRURL)
	}
}

func TestUnsupportedLayoutsSayApplyManually(t *testing.T) {
	ctx := context.Background()
	a, _, tat, id := setup(t, map[string]string{"api.yaml": deploy}, "")
	if _, err := a.Apply(ctx, tat, id, by); !errors.Is(err, apply.ErrUnsupported) || !strings.Contains(err.Error(), "catalog-info.yaml") {
		t.Fatalf("no service repo: %v", err)
	}
	helm := "replicaCount: 2\nresources:\n  requests:\n    cpu: {{ .Values.cpu }}\n"
	a, _, tat, id = setup(t, map[string]string{"chart/templates/deployment.yaml": "kind: Deployment\nmetadata:\n  name: {{ include \"api\" . }}\n", "values.yaml": helm}, "https://github.com/hx/tat-crm")
	if _, err := a.Apply(ctx, tat, id, by); !errors.Is(err, apply.ErrUnsupported) || !strings.Contains(err.Error(), "Helm") {
		t.Fatalf("helm repo: %v", err)
	}
}

func TestApplyScheduleAddsScaledObjectBesideDeployment(t *testing.T) {
	ctx := context.Background()
	dev := strings.Replace(deploy, "  name: api\n", "  name: api\n  namespace: tat-crm\n", 1)
	a, gh, tat, resize := setup(t, map[string]string{"k8s/dev/api.yaml": dev, "k8s/dev/other.yaml": "kind: ConfigMap\n"}, "https://github.com/hx/tat-crm")
	project := mustGet(t, a, tat, resize).ProjectID
	r, _, err := a.Recs.Upsert(ctx, tat, rightsize.Recommendation{Source: "engine:k8s-offhours", Provider: "k8s", ResourceID: "dev-tke/tat-crm/api", ResourceType: "k8s_workload",
		ProjectID: project, Action: "schedule", Current: map[string]any{"replicas": 2},
		Recommended:    map[string]any{"schedule": map[string]any{"text": "Mon–Fri 08:00–18:00 Asia/Bangkok, off at weekends", "start": "08:00", "stop": "18:00", "days": "Mon–Fri", "weekends_off": true, "timezone": "Asia/Bangkok"}},
		Evidence:       map[string]any{"workload": "api", "lookback_days": 14, "off_hours_per_week": 118, "replicas": 2, "conditional_on": "cluster autoscaler removes idle nodes"},
		MonthlySavings: "22125.00", Currency: "THB", Confidence: 1})
	if err != nil {
		t.Fatal(err)
	}
	url, err := a.Apply(ctx, tat, r.ID, by)
	if err != nil {
		t.Fatal(err)
	}
	branch := gh.branches["keel/offhours-"+r.ID[len(r.ID)-8:]]
	if url == "" || len(branch) != 1 {
		t.Fatalf("url %q branch files %v", url, branch)
	}
	if _, touched := branch["k8s/dev/api.yaml"]; touched {
		t.Fatal("the Deployment manifest was changed")
	}
	want := `apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: api-offhours
  namespace: tat-crm
spec:
  scaleTargetRef:
    name: api
  minReplicaCount: 0
  triggers:
    - type: cron
      metadata:
        timezone: Asia/Bangkok
        start: 0 8 * * 1-5
        end: 0 18 * * 1-5
        desiredReplicas: "2"
`
	if got := branch["k8s/dev/keda-offhours-api.yaml"]; got != want {
		t.Fatalf("ScaledObject:\n%s", got)
	}
	body := gh.prs[0]["body"].(string)
	if !strings.Contains(body, "KEDA installed in the cluster") || !strings.Contains(body, "only if node autoscaling") || !strings.Contains(body, "22125.00 THB/month") {
		t.Fatalf("pr body:\n%s", body)
	}
	if got, _ := a.Recs.Get(ctx, tat, r.ID); got.State != "accepted" || got.PRURL == nil || *got.PRURL != url {
		t.Fatalf("state %s pr %v", got.State, got.PRURL)
	}
}

func TestScaledObjectRunsToMidnight(t *testing.T) {
	out, err := apply.ScaledObject(apply.Schedule{Workload: "worker", Kind: "StatefulSet", TimeZone: "Asia/Bangkok", Days: "Daily", Start: 7, Stop: 24, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"start: 0 7 * * *", "end: 59 23 * * *", "kind: StatefulSet", "desiredReplicas: \"1\""} {
		if !strings.Contains(string(out), s) {
			t.Fatalf("missing %q in:\n%s", s, out)
		}
	}
}

func mustGet(t *testing.T, a apply.Applier, tenant, id string) rightsize.Recommendation {
	t.Helper()
	r, err := a.Recs.Get(context.Background(), tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
