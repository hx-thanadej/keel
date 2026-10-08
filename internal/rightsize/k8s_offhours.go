package rightsize

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
)

// K8sOffHoursEngine recommends scaling non-production Kubernetes workloads
// to zero outside the hours they are used (#85). A workload's hour is busy
// when any of its containers reached offHoursIdleCPU percent of its CPU
// request; the working window comes from the same helper as the VM
// engine. Savings are the workload's requested cores and GiB at the
// Environment's unit price for the hours it would be off, and only
// materialise when the cluster autoscaler removes the freed nodes.
type K8sOffHoursEngine struct {
	Service Service
	Now     func() time.Time
}

const k8sOffHoursCondition = "cluster autoscaler removes idle nodes"

type workloadUse struct {
	cluster, ns, name string
	project, env      *string
	prod              bool
	containers        []*container
	days              map[time.Time]bool
	busy              [7][24]bool
}

// Run evaluates every Tenant.
func (e K8sOffHoursEngine) Run(ctx context.Context) (OffHoursResult, error) {
	res := OffHoursResult{Skipped: map[string]int{}}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	rows, err := e.Service.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	asOf := now().UTC().Truncate(24 * time.Hour)
	for _, tenant := range tenants {
		if err := e.tenant(ctx, tenant, asOf, &res); err != nil {
			return res, fmt.Errorf("tenant %s: %w", tenant, err)
		}
	}
	return res, nil
}

type cpuHours struct {
	day    time.Time
	hourly []float64
}

func (e K8sOffHoursEngine) tenant(ctx context.Context, tenant string, asOf time.Time, res *OffHoursResult) error {
	from := asOf.AddDate(0, 0, -offHoursLookback)
	var currency, zone string
	cs := map[string]*container{}
	prod := map[string]bool{}
	hours := map[string][]cpuHours{} // container → days of per-hour CPU maxima (cores)
	var loc *time.Location
	err := e.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT currency, time_zone FROM tenants WHERE id = $1`, tenant).Scan(&currency, &zone); err != nil {
			return err
		}
		var err error
		if loc, err = time.LoadLocation(zone); err != nil {
			return fmt.Errorf("tenant time zone %q: %w", zone, err)
		}
		rows, err := tx.Query(ctx, `SELECT u.resource_id, u.metric, u.day, u.samples, u.request, u.project_id::text, u.environment_id::text,
				coalesce(e.name IN ('prod', 'production', 'prd'), false), u.labels, u.hourly_max
			FROM utilisation_daily u LEFT JOIN environments e ON e.id = u.environment_id
			WHERE u.resource_type = 'k8s_container' AND u.day >= $1 AND u.day < $2 ORDER BY u.day`, from, asOf)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, metric string
			var day time.Time
			var samples int
			var req *float64
			var project, env *string
			var isProd bool
			var labels map[string]string
			var hourly []float64
			if err := rows.Scan(&id, &metric, &day, &samples, &req, &project, &env, &isProd, &labels, &hourly); err != nil {
				return err
			}
			c := cs[id]
			if c == nil {
				c = &container{id: id, cluster: labels["cluster"], ns: labels["namespace"], workload: labels["workload"], ctr: labels["container"], days: map[time.Time]bool{}}
				cs[id] = c
			}
			c.project, c.env = project, env
			prod[id] = isProd
			c.days[day] = true
			switch metric {
			case "cpu_cores":
				c.samples += samples
				if req != nil {
					c.cpuReq = *req // latest (rows ordered by day)
				}
				if hourly != nil {
					hours[id] = append(hours[id], cpuHours{day: day, hourly: hourly})
				}
			case "memory_bytes":
				if req != nil {
					c.memReq = *req
				}
			}
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}

	ws := map[string]*workloadUse{}
	for id, c := range cs {
		key := c.cluster + "/" + c.ns + "/" + c.workload
		w := ws[key]
		if w == nil {
			w = &workloadUse{cluster: c.cluster, ns: c.ns, name: c.workload, days: map[time.Time]bool{}}
			ws[key] = w
		}
		w.project, w.env, w.prod = c.project, c.env, w.prod || prod[id]
		w.containers = append(w.containers, c)
		for _, h := range hours[id] {
			w.days[h.day] = true
			if c.cpuReq == 0 {
				continue // no request to measure idleness against
			}
			markBusy(&w.busy, h.day, h.hourly, loc, c.cpuReq*offHoursIdleCPU/100)
		}
	}

	prices, err := K8sEngine{Service: e.Service}.unitPrices(ctx, tenant, currency, cs, from, asOf)
	if err != nil {
		return err
	}
	for key, w := range ws {
		switch {
		case w.env == nil:
			res.Skipped["unowned"]++
			continue
		case w.prod:
			res.Skipped["production"]++
			continue
		case len(w.days) < offHoursMinDays:
			res.Skipped["short_history"]++
			continue
		}
		var cores, gib, replicas float64
		for _, c := range w.containers {
			if c.cpuReq == 0 {
				continue
			}
			r := math.Max(1, math.Round(float64(c.samples)/float64(max(len(c.days), 1)*1440)*10)/10)
			cores += c.cpuReq * r
			gib += c.memReq / (1 << 30) * r
			replicas = math.Max(replicas, r)
		}
		if replicas == 0 {
			res.Skipped["no_request"]++
			continue
		}
		p, ok := prices[*w.env]
		if !ok {
			res.Skipped["no_unit_price"]++
			continue
		}
		s, ok := quietWindow(&w.busy)
		if !ok {
			res.Skipped["no_quiet_hours"]++
			continue
		}
		offFraction := float64(s.offPerWeek) / 168
		monthly := (cores*p.perCore + gib*p.perGiB) * offFraction * 30
		text := fmt.Sprintf("%s %02d:00–%02d:00 %s", s.days, s.start, s.stop, zone)
		if s.weekendsOff {
			text += ", off at weekends"
		}
		r := Recommendation{Source: "engine:k8s-offhours", Provider: "k8s", ResourceID: key, ResourceType: "k8s_workload", ProjectID: w.project, EnvironmentID: w.env,
			Action: "schedule", Current: map[string]any{"replicas": int(math.Round(replicas))},
			Recommended: map[string]any{"schedule": map[string]any{"text": text, "start": fmt.Sprintf("%02d:00", s.start), "stop": fmt.Sprintf("%02d:00", s.stop),
				"days": s.days, "weekends_off": s.weekendsOff, "timezone": zone}},
			Evidence: map[string]any{"lookback_days": len(w.days), "off_hours_per_week": s.offPerWeek, "replicas": replicas, "idle_below_request_pct": offHoursIdleCPU,
				"cluster": w.cluster, "namespace": w.ns, "workload": w.name, "conditional_on": k8sOffHoursCondition,
				"price_per_core_month": fmt.Sprintf("%.2f", p.perCore*30), "price_per_gib_month": fmt.Sprintf("%.2f", p.perGiB*30),
				"method": "hours whose CPU maximum stayed below 5% of the request on every observed day are off; savings = requested cores and GiB × unit price × replicas × off fraction of the week"},
			MonthlySavings: new(big.Rat).SetFloat64(monthly).FloatString(2), Currency: currency, SavingsBasis: "effective",
			Confidence: min(1, float64(len(w.days))/offHoursLookback),
			Risk: map[string]any{"requires": "KEDA installed in the cluster", "conditional_on": k8sOffHoursCondition,
				"note": "the workload scales to zero outside the window; jobs and requests then will not be served"},
			ObservedAt: asOf}
		_, raised, err := e.Service.Upsert(ctx, tenant, r)
		if err != nil {
			return err
		}
		if raised {
			res.Raised++
		} else {
			res.Kept++
		}
	}
	return nil
}
