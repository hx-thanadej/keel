package rightsize

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/utilisation"
)

// K8sEngine recommends container requests from observed usage (#69,
// ADR-0013), KRR-style: CPU = the highest daily p95 over the lookback,
// memory = the highest daily max + 15%.
type K8sEngine struct {
	Service     Service
	Utilisation utilisation.Store
	Now         func() time.Time
}

// Tunables (ADR-0013 defaults).
const (
	lookbackDays    = 30   // window searched for evidence
	minHistory      = 14   // days required at all
	prodHistory     = 21   // days required in production
	prodConfidence  = 0.8  // confidence required in production
	memHeadroom     = 1.15 // memory = max × 1.15
	minReduction    = 0.2  // only recommend cuts of at least 20%
	gibPerCorePrice = 0.134
	minCPU          = 0.01 // 10m
	minMemMiB       = 32
)

// K8sResult counts what a run did.
type K8sResult struct {
	Raised  int            `json:"raised"`
	Kept    int            `json:"kept"`
	Skipped map[string]int `json:"skipped"`
}

type container struct {
	id, cluster, ns, workload, ctr string
	project, env                   *string
	days                           map[time.Time]bool
	cpuP95, memMax                 float64
	cpuReq, memReq                 float64
	samples                        int
}

// Run evaluates every Tenant.
func (e K8sEngine) Run(ctx context.Context) (K8sResult, error) {
	res := K8sResult{Skipped: map[string]int{}}
	rows, err := e.Service.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, t := range tenants {
		if err := e.tenant(ctx, t, &res); err != nil {
			return res, fmt.Errorf("tenant %s: %w", t, err)
		}
	}
	return res, nil
}

func (e K8sEngine) tenant(ctx context.Context, tenant string, res *K8sResult) error {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	n := now().UTC()
	asOf := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
	from := asOf.AddDate(0, 0, -lookbackDays)

	cs := map[string]*container{}
	var currency string
	prodEnv := map[string]bool{}
	err := e.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT currency FROM tenants WHERE id = $1`, tenant).Scan(&currency); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text FROM environments WHERE name IN ('prod', 'production', 'prd')`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			prodEnv[id] = true
		}
		rows.Close()
		rows, err = tx.Query(ctx, `SELECT resource_id, metric, day, p95, max, samples, request, project_id::text, environment_id::text, labels
			FROM utilisation_daily WHERE resource_type = 'k8s_container' AND day >= $1 AND day < $2 ORDER BY day`, from, asOf)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, metric string
			var day time.Time
			var p95, mx float64
			var samples int
			var req *float64
			var project, env *string
			var labels map[string]string
			if err := rows.Scan(&id, &metric, &day, &p95, &mx, &samples, &req, &project, &env, &labels); err != nil {
				return err
			}
			c := cs[id]
			if c == nil {
				c = &container{id: id, cluster: labels["cluster"], ns: labels["namespace"], workload: labels["workload"], ctr: labels["container"], days: map[time.Time]bool{}}
				cs[id] = c
			}
			c.project, c.env = project, env
			c.days[day] = true
			switch metric {
			case "cpu_cores":
				c.cpuP95 = math.Max(c.cpuP95, p95)
				c.samples += samples
				if req != nil {
					c.cpuReq = *req // latest (rows ordered by day)
				}
			case "memory_bytes":
				c.memMax = math.Max(c.memMax, mx)
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

	prices, err := e.unitPrices(ctx, tenant, currency, cs, from, asOf)
	if err != nil {
		return err
	}
	for _, c := range cs {
		days := len(c.days)
		if days < minHistory {
			res.Skipped["insufficient_history"]++
			continue
		}
		if c.cpuReq == 0 || c.memReq == 0 {
			res.Skipped["no_request"]++
			continue
		}
		var first time.Time
		for d := range c.days {
			if first.IsZero() || d.Before(first) {
				first = d
			}
		}
		span := int(asOf.Sub(first).Hours() / 24)
		confidence := math.Min(1, float64(days)/prodHistory) * float64(days) / float64(max(span, 1))
		if c.env != nil && prodEnv[*c.env] && (days < prodHistory || confidence < prodConfidence) {
			res.Skipped["low_confidence_prod"]++
			continue
		}
		recCPU := math.Max(minCPU, math.Ceil(c.cpuP95*100)/100)
		recMemMiB := math.Max(minMemMiB, math.Ceil(c.memMax*memHeadroom/(1<<20)))
		reqMemMiB := c.memReq / (1 << 20)
		under := c.cpuP95 > c.cpuReq || c.memMax > c.memReq
		reduce := recCPU <= c.cpuReq*(1-minReduction) || recMemMiB <= reqMemMiB*(1-minReduction)
		if !under && !reduce {
			res.Skipped["no_change"]++
			continue
		}
		replicas := float64(c.samples) / float64(days*1440)
		replicas = math.Max(1, math.Round(replicas*10)/10)
		p := prices[deref(c.env)]
		saving := ((c.cpuReq-recCPU)*p.perCore + (reqMemMiB-recMemMiB)/1024*p.perGiB) * replicas * 30
		risk := map[string]any{"performance": "low", "reversible": true, "restart": "rolling (or in-place resize on Kubernetes ≥1.35)"}
		if under {
			risk["under_provisioned"] = true
			risk["performance"] = "high"
		}
		r := Recommendation{
			Source: "engine:k8s", Provider: "k8s", ResourceID: c.id, ResourceType: "k8s_workload",
			ProjectID: c.project, EnvironmentID: c.env, Action: "resize_requests",
			Current:     map[string]any{"cpu": milli(c.cpuReq), "memory": fmt.Sprintf("%.0fMi", reqMemMiB)},
			Recommended: map[string]any{"cpu": milli(recCPU), "memory": fmt.Sprintf("%.0fMi", recMemMiB)},
			Evidence: map[string]any{"lookback_days": days, "replicas": replicas, "cpu_p95_max": milli(c.cpuP95), "memory_max": fmt.Sprintf("%.0fMi", c.memMax/(1<<20)),
				"method": "max daily p95 CPU; max memory × 1.15", "cluster": c.cluster, "namespace": c.ns, "workload": c.workload, "container": c.ctr,
				"price_per_core_month": fmt.Sprintf("%.2f", p.perCore*30), "price_per_gib_month": fmt.Sprintf("%.2f", p.perGiB*30)},
			MonthlySavings: new(big.Rat).SetFloat64(saving).FloatString(2), Currency: currency, SavingsBasis: "effective",
			Confidence: math.Round(confidence*100) / 100, Risk: risk,
		}
		_, changed, err := e.Service.Upsert(ctx, tenant, r)
		if err != nil {
			return err
		}
		if changed {
			res.Raised++
		} else {
			res.Kept++
		}
	}
	return nil
}

type price struct{ perCore, perGiB float64 } // per day, Tenant currency

// unitPrices derives each Environment's cost per requested core and GiB per
// day: its compute spend (CVM/TKE effective cost over the window, in the
// Tenant's currency) divided by everything requested in it, with memory
// weighted at gibPerCorePrice of a core.
func (e K8sEngine) unitPrices(ctx context.Context, tenant, currency string, cs map[string]*container, from, to time.Time) (map[string]price, error) {
	requested := map[string]float64{} // env → core-equivalents requested
	for _, c := range cs {
		days := float64(max(len(c.days), 1))
		replicas := math.Max(1, float64(c.samples)/(days*1440))
		requested[deref(c.env)] += (c.cpuReq + c.memReq/(1<<30)*gibPerCorePrice) * replicas
	}
	out := map[string]price{}
	err := e.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		for env, units := range requested {
			if env == "" || units == 0 {
				continue
			}
			var daily *float64
			if err := tx.QueryRow(ctx, `SELECT sum(fx_convert(coalesce(effective_cost, billed_cost), billing_currency, $4, (charge_period_start AT TIME ZONE 'UTC')::date))::float8
					/ greatest(1, ($3::date - $2::date))
				FROM cost_facts WHERE current AND environment_id = $1 AND charge_period_start >= $2 AND charge_period_start < $3
				  AND service_name IN ('Cloud Virtual Machine', 'Tencent Kubernetes Engine', 'Elastic Kubernetes Service', 'Amazon Elastic Compute Cloud')`,
				env, from, to, currency).Scan(&daily); err != nil {
				return err
			}
			if daily == nil {
				continue
			}
			perCore := *daily / units
			out[env] = price{perCore: perCore, perGiB: perCore * gibPerCorePrice}
		}
		return nil
	})
	return out, err
}

func milli(cores float64) string { return fmt.Sprintf("%dm", int(math.Round(cores*1000))) }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
