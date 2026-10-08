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
	noRequest         bool // a container with CPU data has no CPU request
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

func (e K8sOffHoursEngine) tenant(ctx context.Context, tenant string, asOf time.Time, res *OffHoursResult) error {
	from := asOf.AddDate(0, 0, -offHoursLookback)
	var currency, zone string
	var cs map[string]*container
	var loc *time.Location
	err := e.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT currency, time_zone FROM tenants WHERE id = $1`, tenant).Scan(&currency, &zone); err != nil {
			return err
		}
		var err error
		if loc, err = time.LoadLocation(zone); err != nil {
			return fmt.Errorf("tenant time zone %q: %w", zone, err)
		}
		cs, err = loadContainers(ctx, tx, from, asOf)
		return err
	})
	if err != nil {
		return err
	}

	ws := map[string]*workloadUse{}
	for _, c := range cs {
		key := c.cluster + "/" + c.ns + "/" + c.workload
		w := ws[key]
		if w == nil {
			w = &workloadUse{cluster: c.cluster, ns: c.ns, name: c.workload, days: map[time.Time]bool{}}
			ws[key] = w
		}
		w.project, w.env, w.prod = c.project, c.env, w.prod || c.prod
		w.containers = append(w.containers, c)
		if len(c.cpuHourly) > 0 && c.cpuReq == 0 {
			w.noRequest = true // idleness can't be judged for this container
		}
		for _, h := range c.cpuHourly {
			w.days[h.day] = true
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
		case w.noRequest:
			res.Skipped["no_request"]++
			continue
		}
		var cores, gib, pods float64
		for _, c := range w.containers {
			r := replicas(c)
			cores += c.cpuReq * r
			gib += c.memReq / (1 << 30) * r
			pods = math.Max(pods, r)
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
			Action: "schedule", Current: map[string]any{"replicas": int(math.Round(pods))},
			Recommended: map[string]any{"schedule": map[string]any{"text": text, "start": fmt.Sprintf("%02d:00", s.start), "stop": fmt.Sprintf("%02d:00", s.stop),
				"days": s.days, "weekends_off": s.weekendsOff, "timezone": zone}},
			Evidence: map[string]any{"lookback_days": len(w.days), "off_hours_per_week": s.offPerWeek, "replicas": math.Round(pods*10) / 10, "idle_below_request_pct": offHoursIdleCPU,
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
