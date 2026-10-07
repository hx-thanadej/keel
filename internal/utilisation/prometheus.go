package utilisation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Prometheus collects per-container usage from a cluster's Prometheus
// (cAdvisor + kube-state-metrics), one day at 1-minute resolution. Each
// replica's samples count separately, because requests apply per replica.
type Prometheus struct {
	Cluster string
	URL     string
	Client  *http.Client
}

const (
	cpuQuery = `sum by (namespace, pod, container) (rate(container_cpu_usage_seconds_total{container!="", container!="POD"}[5m]))`
	memQuery = `max by (namespace, pod, container) (container_memory_working_set_bytes{container!="", container!="POD"})`
	reqQuery = `max by (namespace, pod, container, resource) (kube_pod_container_resource_requests{resource=~"cpu|memory"})`
)

type series struct {
	Metric map[string]string `json:"metric"`
	Values [][2]any          `json:"values"`
}

func (p Prometheus) rangeQuery(ctx context.Context, q string, day time.Time) ([]series, error) {
	v := url.Values{"query": {q}, "start": {strconv.FormatInt(day.Unix(), 10)}, "end": {strconv.FormatInt(day.Add(24*time.Hour-time.Minute).Unix(), 10)}, "step": {"60"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(p.URL, "/")+"/api/v1/query_range?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}
	c := p.Client
	if c == nil {
		c = &http.Client{Timeout: 2 * time.Minute}
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 512<<20))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus: HTTP %d: %.200s", res.StatusCode, body)
	}
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Result []series `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Status != "success" {
		return nil, fmt.Errorf("prometheus: bad response: %v", err)
	}
	return out.Data.Result, nil
}

func values(s series) []float64 {
	out, _ := timedValues(s)
	return out
}

// timedValues returns samples with their unix-second timestamps.
func timedValues(s series) (xs, ts []float64) {
	for _, v := range s.Values {
		t, okT := v[0].(float64)
		if str, ok := v[1].(string); ok && okT {
			if f, err := strconv.ParseFloat(str, 64); err == nil && !isNaN(f) {
				xs, ts = append(xs, f), append(ts, t)
			}
		}
	}
	return xs, ts
}

func isNaN(f float64) bool { return f != f }

// Day returns one Summary per workload container and metric for the UTC day.
func (p Prometheus) Day(ctx context.Context, day time.Time) ([]Summary, error) {
	type key struct{ ns, wl, ctr string }
	samples := map[string]map[key][]float64{"cpu_cores": {}, "memory_bytes": {}}
	hourly := map[string]map[key][]float64{"cpu_cores": {}, "memory_bytes": {}}
	for metric, q := range map[string]string{"cpu_cores": cpuQuery, "memory_bytes": memQuery} {
		ss, err := p.rangeQuery(ctx, q, day)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", metric, err)
		}
		for _, s := range ss {
			k := key{s.Metric["namespace"], WorkloadFromPod(s.Metric["pod"]), s.Metric["container"]}
			xs, ts := timedValues(s)
			samples[metric][k] = append(samples[metric][k], xs...)
			hourly[metric][k] = mergeHourly(hourly[metric][k], HourlyMax(day, ts, xs))
		}
	}
	requests := map[string]map[key]float64{"cpu_cores": {}, "memory_bytes": {}}
	reqs, err := p.rangeQuery(ctx, reqQuery, day)
	if err != nil {
		return nil, fmt.Errorf("requests: %w", err)
	}
	for _, s := range reqs {
		metric := map[string]string{"cpu": "cpu_cores", "memory": "memory_bytes"}[s.Metric["resource"]]
		vs := values(s)
		if metric == "" || len(vs) == 0 {
			continue
		}
		k := key{s.Metric["namespace"], WorkloadFromPod(s.Metric["pod"]), s.Metric["container"]}
		requests[metric][k] = vs[len(vs)-1] // the request in force at the end of the day
	}
	var out []Summary
	for metric, byKey := range samples {
		for k, xs := range byKey {
			s := Summarize(xs)
			s.Provider, s.ResourceType, s.Metric, s.Day = "k8s", "k8s_container", metric, day
			s.Cluster, s.Namespace, s.Workload, s.Container = p.Cluster, k.ns, k.wl, k.ctr
			s.ResourceID = strings.Join([]string{p.Cluster, k.ns, k.wl, k.ctr}, "/")
			s.Hourly = hourly[metric][k]
			if r, ok := requests[metric][k]; ok {
				r := r
				s.Request = &r
			}
			out = append(out, s)
		}
	}
	return out, nil
}
