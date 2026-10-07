package rightsize

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// InstanceType is one size in a provider's catalogue.
type InstanceType struct {
	Name        string
	Family      string
	CPU         float64
	MemoryGiB   float64
	HourlyPrice float64 // list price; used only as a ratio between sizes
}

// Catalog lists instance types available in a region.
type Catalog interface {
	Types(ctx context.Context, region string) ([]InstanceType, error)
}

// Inventory reports each instance's current type in one account.
type Inventory interface {
	InstanceTypes(ctx context.Context, region string, ids []string) (map[string]string, error)
}

// VMEngine recommends instance sizes for Tencent CVM, which has no native
// size recommender (#70, ADR-0013).
type VMEngine struct {
	Service   Service
	Catalog   Catalog
	Inventory func(account string) Inventory
	Region    string
	Now       func() time.Time
}

const (
	vmLookback       = 35
	vmProdHistory    = 32
	vmTargetCPU      = 0.7 // size so that p95 CPU lands at ≤70%
	vmMinPriceSaving = 0.2 // recommend only if the new type costs ≤80%
)

// VMResult counts what a run did.
type VMResult struct {
	Raised  int            `json:"raised"`
	Kept    int            `json:"kept"`
	Skipped map[string]int `json:"skipped"`
}

type vmUse struct {
	id, account      string
	project, env     *string
	days             map[time.Time]bool
	cpuP95, memMax   float64
	memMeasured      bool
	monthlyEffective float64 // Tenant currency
}

// Run evaluates every Tenant.
func (e VMEngine) Run(ctx context.Context) (VMResult, error) {
	res := VMResult{Skipped: map[string]int{}}
	types, err := e.Catalog.Types(ctx, e.Region)
	if err != nil {
		return res, fmt.Errorf("instance catalogue: %w", err)
	}
	rows, err := e.Service.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, t := range tenants {
		if err := e.tenant(ctx, t, types, &res); err != nil {
			return res, fmt.Errorf("tenant %s: %w", t, err)
		}
	}
	return res, nil
}

func (e VMEngine) tenant(ctx context.Context, tenant string, types []InstanceType, res *VMResult) error {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	n := now().UTC()
	asOf := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
	from := asOf.AddDate(0, 0, -vmLookback)
	uses := map[string]*vmUse{}
	var currency string
	prod := map[string]bool{}
	err := e.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT currency FROM tenants WHERE id = $1`, tenant).Scan(&currency); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text FROM environments WHERE name IN ('prod', 'production', 'prd')`)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, id := range ids {
			prod[id] = true
		}
		rows, err = tx.Query(ctx, `SELECT resource_id, metric, day, p95, max, project_id::text, environment_id::text FROM utilisation_daily
			WHERE provider = 'tencent' AND resource_type = 'vm' AND day >= $1 AND day < $2`, from, asOf)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, metric string
			var day time.Time
			var p95, mx float64
			var project, env *string
			if err := rows.Scan(&id, &metric, &day, &p95, &mx, &project, &env); err != nil {
				rows.Close()
				return err
			}
			u := uses[id]
			if u == nil {
				u = &vmUse{id: id, days: map[time.Time]bool{}}
				uses[id] = u
			}
			u.project, u.env = project, env
			switch metric {
			case "cpu_pct":
				u.days[day] = true
				u.cpuP95 = math.Max(u.cpuP95, p95)
			case "memory_pct":
				u.memMeasured = true
				u.memMax = math.Max(u.memMax, mx)
			}
		}
		rows.Close()
		// Each instance's effective monthly cost and account, from cost facts.
		for id, u := range uses {
			var daily *float64
			var account *string
			if err := tx.QueryRow(ctx, `SELECT sum(fx_convert(coalesce(effective_cost, billed_cost), billing_currency, $4, (charge_period_start AT TIME ZONE 'UTC')::date))::float8
					/ greatest(1, count(DISTINCT (charge_period_start AT TIME ZONE 'UTC')::date)), max(sub_account_id)
				FROM cost_facts WHERE current AND resource_id = $1 AND charge_period_start >= $2 AND charge_period_start < $3`,
				id, asOf.AddDate(0, 0, -30), asOf, currency).Scan(&daily, &account); err != nil {
				return err
			}
			if daily != nil {
				u.monthlyEffective = *daily * 30
			}
			if account != nil {
				u.account = *account
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	byAcct := map[string][]string{}
	for id, u := range uses {
		byAcct[u.account] = append(byAcct[u.account], id)
	}
	current := map[string]string{}
	for acct, ids := range byAcct {
		if acct == "" || e.Inventory == nil {
			continue
		}
		got, err := e.Inventory(acct).InstanceTypes(ctx, e.Region, ids)
		if err != nil {
			return fmt.Errorf("inventory %s: %w", acct, err)
		}
		for k, v := range got {
			current[k] = v
		}
	}
	byName := map[string]InstanceType{}
	for _, t := range types {
		byName[t.Name] = t
	}

	for id, u := range uses {
		days := len(u.days)
		cur, ok := byName[current[id]]
		switch {
		case !ok:
			res.Skipped["unknown_type"]++
			continue
		case days < minHistory:
			res.Skipped["insufficient_history"]++
			continue
		case u.env != nil && prod[*u.env] && days < vmProdHistory:
			res.Skipped["low_confidence_prod"]++
			continue
		case u.monthlyEffective <= 0:
			res.Skipped["no_cost"]++
			continue
		}
		needCPU := cur.CPU * u.cpuP95 / 100 / vmTargetCPU
		needMem := cur.MemoryGiB // unmeasured memory: never shrink it
		if u.memMeasured {
			needMem = cur.MemoryGiB * u.memMax / 100 * memHeadroom
		}
		var fits []InstanceType
		for _, t := range types {
			if t.CPU >= needCPU && t.MemoryGiB >= needMem && t.HourlyPrice > 0 {
				fits = append(fits, t)
			}
		}
		sort.Slice(fits, func(i, j int) bool {
			if fits[i].HourlyPrice != fits[j].HourlyPrice {
				return fits[i].HourlyPrice < fits[j].HourlyPrice
			}
			return fits[i].Family == cur.Family // tie → same family
		})
		if len(fits) == 0 || fits[0].HourlyPrice > cur.HourlyPrice*(1-vmMinPriceSaving) {
			res.Skipped["no_change"]++
			continue
		}
		best := fits[0]
		action := "resize"
		if best.Family != cur.Family {
			action = "change_family"
		}
		saving := u.monthlyEffective * (1 - best.HourlyPrice/cur.HourlyPrice)
		span := float64(vmLookback)
		evidence := map[string]any{"lookback_days": days, "cpu_p95_max_pct": u.cpuP95, "needed_vcpu": math.Round(needCPU*100) / 100,
			"needed_memory_gib": math.Round(needMem*100) / 100, "memory_measured": u.memMeasured, "target_cpu_pct": vmTargetCPU * 100,
			"current_monthly_effective": fmt.Sprintf("%.2f", u.monthlyEffective), "method": "cheapest type covering p95 CPU at 70% and max memory × 1.15; savings = effective cost × price ratio"}
		if u.memMeasured {
			evidence["memory_max_pct"] = u.memMax
		}
		r := Recommendation{Source: "engine:vm", Provider: "tencent", AccountID: u.account, Region: e.Region, ResourceID: id, ResourceType: "vm",
			ProjectID: u.project, EnvironmentID: u.env, Action: action,
			Current:     map[string]any{"instance_type": cur.Name, "vcpu": cur.CPU, "memory_gib": cur.MemoryGiB},
			Recommended: map[string]any{"instance_type": best.Name, "vcpu": best.CPU, "memory_gib": best.MemoryGiB},
			Evidence:    evidence, MonthlySavings: new(big.Rat).SetFloat64(saving).FloatString(2), Currency: currency, SavingsBasis: "effective",
			Confidence: math.Round(math.Min(1, float64(days)/span)*100) / 100,
			Risk:       map[string]any{"performance": "medium", "restart": true, "reversible": true, "migration_effort": map[bool]string{true: "medium", false: "low"}[action == "change_family"]}}
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
