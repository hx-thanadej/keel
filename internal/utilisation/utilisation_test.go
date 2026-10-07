package utilisation_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store/storetest"
	"github.com/hx-thanadej/keel/internal/utilisation"
)

var day = time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

func TestSummarize(t *testing.T) {
	var xs []float64
	for i := 1; i <= 100; i++ {
		xs = append(xs, float64(i))
	}
	s := utilisation.Summarize(xs)
	if s.Samples != 100 || s.Max != 100 || s.P50 != 50 || s.P95 != 95 || s.P99 != 99 {
		t.Fatalf("summary %+v", s)
	}
	if e := utilisation.Summarize(nil); e.Samples != 0 {
		t.Fatal("empty summary")
	}
}

func TestWorkloadFromPod(t *testing.T) {
	cases := map[string]string{
		"api-7d9f8c6b5d-x2k4p":    "api",        // Deployment
		"crm-web-65b8d9c7f-9qz7x": "crm-web",    // Deployment, 9-char hash
		"postgres-0":              "postgres",   // StatefulSet
		"node-agent-x2k4p":        "node-agent", // DaemonSet
		"one-off":                 "one-off",
	}
	for pod, want := range cases {
		if got := utilisation.WorkloadFromPod(pod); got != want {
			t.Errorf("%s → %s, want %s", pod, got, want)
		}
	}
}

// fakeProm answers query_range with two replicas of api/app and one of db/postgres.
func fakeProm(t *testing.T) *httptest.Server {
	t.Helper()
	series := func(metric map[string]string, f func(i int) float64) map[string]any {
		var vals [][2]any
		for i := 0; i < 1440; i++ { // one day at 1m
			ts := float64(day.Unix() + int64(i)*60)
			vals = append(vals, [2]any{ts, fmt.Sprintf("%g", f(i))})
		}
		return map[string]any{"metric": metric, "values": vals}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if r.URL.Path != "/api/v1/query_range" || r.URL.Query().Get("step") != "60" {
			http.Error(w, "bad request "+r.URL.String(), 400)
			return
		}
		var result []map[string]any
		switch {
		case contains(q, "container_cpu_usage_seconds_total"):
			result = []map[string]any{
				series(map[string]string{"namespace": "tat-crm-prod", "pod": "api-7d9f8c6b5d-aaaaa", "container": "app"}, func(i int) float64 { return 0.2 + 0.2*float64(i%100)/100 }),
				series(map[string]string{"namespace": "tat-crm-prod", "pod": "api-7d9f8c6b5d-bbbbb", "container": "app"}, func(i int) float64 { return 0.3 }),
				series(map[string]string{"namespace": "tat-crm-prod", "pod": "postgres-0", "container": "postgres"}, func(i int) float64 { return 1.0 }),
			}
		case contains(q, "container_memory_working_set_bytes"):
			result = []map[string]any{
				series(map[string]string{"namespace": "tat-crm-prod", "pod": "api-7d9f8c6b5d-aaaaa", "container": "app"}, func(i int) float64 { return 500e6 }),
				series(map[string]string{"namespace": "tat-crm-prod", "pod": "api-7d9f8c6b5d-bbbbb", "container": "app"}, func(i int) float64 { return 700e6 }),
			}
		case contains(q, "kube_pod_container_resource_requests"):
			result = []map[string]any{
				series(map[string]string{"namespace": "tat-crm-prod", "pod": "api-7d9f8c6b5d-aaaaa", "container": "app", "resource": "cpu"}, func(int) float64 { return 2 }),
				series(map[string]string{"namespace": "tat-crm-prod", "pod": "api-7d9f8c6b5d-aaaaa", "container": "app", "resource": "memory"}, func(int) float64 { return 4 << 30 }),
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": result}})
	}))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestPrometheusCollector(t *testing.T) {
	srv := fakeProm(t)
	defer srv.Close()
	c := utilisation.Prometheus{Cluster: "shared-tke", URL: srv.URL}
	sums, err := c.Day(context.Background(), day)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]utilisation.Summary{}
	for _, s := range sums {
		byKey[s.ResourceID+"#"+s.Metric] = s
	}
	cpu := byKey["shared-tke/tat-crm-prod/api/app#cpu_cores"]
	// 2 replicas × 1440 samples; replica b is flat 0.3, replica a spans 0.2..0.398.
	if cpu.Samples != 2880 || math.Abs(cpu.Max-0.398) > 1e-9 || cpu.Namespace != "tat-crm-prod" || cpu.Workload != "api" || cpu.Container != "app" {
		t.Fatalf("cpu %+v", cpu)
	}
	if cpu.Request == nil || *cpu.Request != 2 {
		t.Fatalf("cpu request %v", cpu.Request)
	}
	mem := byKey["shared-tke/tat-crm-prod/api/app#memory_bytes"]
	if mem.Max != 700e6 || mem.Request == nil || *mem.Request != float64(4<<30) {
		t.Fatalf("mem %+v", mem)
	}
	if _, ok := byKey["shared-tke/tat-crm-prod/postgres/postgres#cpu_cores"]; !ok {
		t.Fatal("statefulset workload missing")
	}
}

func TestSaveAndWindow(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	st := utilisation.Store{Store: s}
	sum := utilisation.Summary{Provider: "k8s", ResourceID: "c/ns/api/app", ResourceType: "k8s_container", Metric: "cpu_cores", Day: day, P50: 0.3, P95: 0.39, P99: 0.398, Max: 0.4, Samples: 2880}
	if err := st.Save(ctx, tat, nil, nil, []utilisation.Summary{sum}); err != nil {
		t.Fatal(err)
	}
	sum.Max = 0.5 // re-collection replaces the day
	if err := st.Save(ctx, tat, nil, nil, []utilisation.Summary{sum}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Window(ctx, tat, "c/ns/api/app", "cpu_cores", day.AddDate(0, 0, -1), day.AddDate(0, 0, 1))
	if err != nil || len(got) != 1 || got[0].Max != 0.5 {
		t.Fatalf("window %+v %v", got, err)
	}
	var n int
	_ = s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM utilisation_daily`).Scan(&n)
	})
	if n != 1 {
		t.Fatalf("rows %d", n)
	}
}

func TestJobAttributesNamespacesToTenants(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	home, _ := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var team, project, env string
	_ = s.InTenant(ctx, home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, home).Scan(&team)
	})
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tat, team).Scan(&project); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tat, project).Scan(&env)
	}); err != nil {
		t.Fatal(err)
	}
	srv := fakeProm(t)
	defer srv.Close()
	job := utilisation.Job{Store: utilisation.Store{Store: s}, Clusters: []utilisation.Cluster{{Prometheus: utilisation.Prometheus{Cluster: "tat-crm-prod-tke", URL: srv.URL}, DefaultScope: "tat/tat-crm/prod"}}}
	if err := job.Run(ctx, day.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var n int
	var gotEnv string
	_ = s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), max(environment_id::text) FROM utilisation_daily`).Scan(&n, &gotEnv)
	})
	if n != 3 || gotEnv != env { // api cpu, api memory, postgres cpu
		t.Fatalf("TAT rows %d env %s", n, gotEnv)
	}
}
