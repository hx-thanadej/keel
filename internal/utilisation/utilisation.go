// Package utilisation collects and stores daily usage summaries per
// resource: the evidence behind every Rightsizing Recommendation (#68).
package utilisation

import (
	"context"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
)

// Summary is one resource's usage of one metric over one UTC day.
type Summary struct {
	Provider     string    `json:"provider"`
	ResourceID   string    `json:"resource_id"`
	ResourceType string    `json:"resource_type"`
	Metric       string    `json:"metric"` // cpu_cores | memory_bytes | cpu_pct | memory_pct
	Day          time.Time `json:"day"`
	P50          float64   `json:"p50"`
	P95          float64   `json:"p95"`
	P99          float64   `json:"p99"`
	Max          float64   `json:"max"`
	Samples      int       `json:"samples"`
	Request      *float64  `json:"request,omitempty"`  // k8s: current request
	Capacity     *float64  `json:"capacity,omitempty"` // vm: provisioned capacity
	// Hourly is the maximum in each UTC hour of Day (24 entries; -1 where
	// there was no sample), the input to off-hours scheduling (#73).
	Hourly []float64 `json:"hourly,omitempty"`
	// Kubernetes identity (for allocation and pull requests).
	Cluster   string `json:"cluster,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Workload  string `json:"workload,omitempty"`
	Container string `json:"container,omitempty"`
}

// Summarize computes nearest-rank quantiles.
func Summarize(xs []float64) Summary {
	if len(xs) == 0 {
		return Summary{}
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	q := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		return s[max(0, min(i, len(s)-1))]
	}
	return Summary{P50: q(0.50), P95: q(0.95), P99: q(0.99), Max: s[len(s)-1], Samples: len(s)}
}

// HourlyMax buckets samples taken at unix-second timestamps into the 24
// UTC hours of day, keeping each hour's maximum.
func HourlyMax(day time.Time, unix, xs []float64) []float64 {
	out := make([]float64, 24)
	for i := range out {
		out[i] = -1
	}
	start := day.UTC().Unix()
	for i, x := range xs {
		if i >= len(unix) || x != x {
			continue
		}
		h := int((int64(unix[i]) - start) / 3600)
		if h >= 0 && h < 24 && x > out[h] {
			out[h] = x
		}
	}
	return out
}

// mergeHourly keeps the per-hour maximum of two hourly series.
func mergeHourly(a, b []float64) []float64 {
	if a == nil {
		return b
	}
	for i := range a {
		if i < len(b) && b[i] > a[i] {
			a[i] = b[i]
		}
	}
	return a
}

var (
	deployPod = regexp.MustCompile(`^(.*)-[a-z0-9]{6,10}-[a-z0-9]{5}$`)
	dsPod     = regexp.MustCompile(`^(.*)-[a-z0-9]{5}$`)
	stsPod    = regexp.MustCompile(`^(.*)-\d+$`)
)

// WorkloadFromPod strips the controller's suffix from a pod name
// (Deployment hash, DaemonSet suffix, StatefulSet ordinal).
func WorkloadFromPod(pod string) string {
	for _, re := range []*regexp.Regexp{deployPod, stsPod, dsPod} {
		if m := re.FindStringSubmatch(pod); m != nil {
			return m[1]
		}
	}
	return pod
}

// Store persists summaries.
type Store struct {
	Store *store.Store
}

// Save upserts summaries for one Tenant (re-collecting a day replaces it).
func (s Store) Save(ctx context.Context, tenant string, project, env *string, sums []Summary) error {
	return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, x := range sums {
			labels, _ := json.Marshal(map[string]string{"cluster": x.Cluster, "namespace": x.Namespace, "workload": x.Workload, "container": x.Container})
			b.Queue(`INSERT INTO utilisation_daily (tenant_id, provider, resource_id, resource_type, metric, day, p50, p95, p99, max, samples, request, capacity, project_id, environment_id, labels, hourly_max)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
				ON CONFLICT (tenant_id, provider, resource_id, metric, day) DO UPDATE SET p50 = excluded.p50, p95 = excluded.p95, p99 = excluded.p99,
				    max = excluded.max, samples = excluded.samples, request = excluded.request, capacity = excluded.capacity,
				    project_id = excluded.project_id, environment_id = excluded.environment_id, labels = excluded.labels, hourly_max = excluded.hourly_max, collected_at = now()`,
				tenant, x.Provider, x.ResourceID, x.ResourceType, x.Metric, x.Day, x.P50, x.P95, x.P99, x.Max, x.Samples, x.Request, x.Capacity, project, env, labels, x.Hourly)
		}
		return tx.SendBatch(ctx, b).Close()
	})
}

// Window returns a resource's daily summaries for one metric in [from, to).
func (s Store) Window(ctx context.Context, tenant, resource, metric string, from, to time.Time) ([]Summary, error) {
	var out []Summary
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT provider, resource_id, resource_type, metric, day, p50, p95, p99, max, samples, request, capacity, labels
			FROM utilisation_daily WHERE resource_id = $1 AND metric = $2 AND day >= $3 AND day < $4 ORDER BY day`, resource, metric, from, to)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, scanSummary)
		return err
	})
	return out, err
}

func scanSummary(r pgx.CollectableRow) (Summary, error) {
	var x Summary
	var labels map[string]string
	err := r.Scan(&x.Provider, &x.ResourceID, &x.ResourceType, &x.Metric, &x.Day, &x.P50, &x.P95, &x.P99, &x.Max, &x.Samples, &x.Request, &x.Capacity, &labels)
	x.Cluster, x.Namespace, x.Workload, x.Container = labels["cluster"], labels["namespace"], labels["workload"], labels["container"]
	return x, err
}

// Resources lists resources with summaries since `since`, one row per
// resource and metric, for the engines to iterate.
func (s Store) Resources(ctx context.Context, tenant, resourceType string, since time.Time) ([]Summary, error) {
	var out []Summary
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (resource_id, metric) provider, resource_id, resource_type, metric, day, p50, p95, p99, max, samples, request, capacity, labels
			FROM utilisation_daily WHERE resource_type = $1 AND day >= $2 ORDER BY resource_id, metric, day DESC`, resourceType, since)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, scanSummary)
		return err
	})
	return out, err
}
