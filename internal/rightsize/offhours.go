package rightsize

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
)

// OffHoursEngine recommends stopping non-production VMs outside the hours
// they are used (#73). It reads each day's per-hour CPU maximum, finds the
// local hours (in the Tenant's time zone) that were idle every time they
// were observed, and proposes one working window — weekdays only when
// weekends are idle too. Savings come from the VM's usage-based (hourly)
// cost; subscription charges do not stop with the instance.
type OffHoursEngine struct {
	Service Service
	Now     func() time.Time
}

const (
	offHoursLookback   = 14
	offHoursMinDays    = 10
	offHoursIdleCPU    = 5.0 // percent: an hour whose maximum stays below this is idle
	offHoursMinOffWeek = 40  // hours/week off before a schedule is worth proposing
	offHoursWarmUp     = 1   // start this many hours before first use
)

// OffHoursResult counts what a run did.
type OffHoursResult struct {
	Raised  int            `json:"raised"`
	Kept    int            `json:"kept"`
	Skipped map[string]int `json:"skipped"`
}

type hourUse struct {
	provider     string
	project, env *string
	prod         bool
	days         int
	busy         [7][24]bool // local weekday × hour: used at least once
}

// Run evaluates every Tenant.
func (e OffHoursEngine) Run(ctx context.Context) (OffHoursResult, error) {
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

func (e OffHoursEngine) tenant(ctx context.Context, tenant string, asOf time.Time, res *OffHoursResult) error {
	from := asOf.AddDate(0, 0, -offHoursLookback)
	var currency, zone string
	uses := map[string]*hourUse{}
	cost := map[string]float64{}
	err := e.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT currency, time_zone FROM tenants WHERE id = $1`, tenant).Scan(&currency, &zone); err != nil {
			return err
		}
		loc, err := time.LoadLocation(zone)
		if err != nil {
			return fmt.Errorf("tenant time zone %q: %w", zone, err)
		}
		rows, err := tx.Query(ctx, `SELECT u.resource_id, u.provider, u.project_id::text, u.environment_id::text, coalesce(e.name IN ('prod', 'production', 'prd'), false), u.day, u.hourly_max
			FROM utilisation_daily u LEFT JOIN environments e ON e.id = u.environment_id
			WHERE u.resource_type = 'vm' AND u.metric = 'cpu_pct' AND u.hourly_max IS NOT NULL AND u.day >= $1 AND u.day < $2`, from, asOf)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, provider string
			var project, env *string
			var prod bool
			var day time.Time
			var hourly []float64
			if err := rows.Scan(&id, &provider, &project, &env, &prod, &day, &hourly); err != nil {
				return err
			}
			u := uses[id]
			if u == nil {
				u = &hourUse{provider: provider, project: project, env: env, prod: prod}
				uses[id] = u
			}
			u.days++
			for h, v := range hourly {
				if v < 0 {
					continue
				}
				t := day.UTC().Add(time.Duration(h) * time.Hour).In(loc)
				wd, lh := int(t.Weekday()), t.Hour()
				if v >= offHoursIdleCPU {
					u.busy[wd][lh] = true
				}
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for id := range uses {
			var hourly *float64
			if err := tx.QueryRow(ctx, `SELECT sum(fx_convert(coalesce(effective_cost, billed_cost), billing_currency, $4, (charge_period_start AT TIME ZONE 'UTC')::date))::float8
					/ nullif(count(DISTINCT (charge_period_start AT TIME ZONE 'UTC')::date), 0) / 24
				FROM cost_facts WHERE current AND resource_id = $1 AND charge_period_start >= $2 AND charge_period_start < $3
				  AND charge_category = 'Usage' AND charge_frequency IN ('Usage-Based', '')`, id, from, asOf, currency).Scan(&hourly); err != nil {
				return err
			}
			if hourly != nil {
				cost[id] = *hourly
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for id, u := range uses {
		switch {
		case u.env == nil:
			res.Skipped["unowned"]++
			continue
		case u.prod:
			res.Skipped["production"]++
			continue
		case u.days < offHoursMinDays:
			res.Skipped["short_history"]++
			continue
		case cost[id] <= 0:
			res.Skipped["no_hourly_cost"]++
			continue
		}
		s, ok := schedule(u)
		if !ok {
			res.Skipped["no_quiet_hours"]++
			continue
		}
		if s.offPerWeek < offHoursMinOffWeek {
			res.Skipped["no_quiet_hours"]++
			continue
		}
		monthly := cost[id] * float64(s.offPerWeek) * 30 / 7
		text := fmt.Sprintf("%s %02d:00–%02d:00 %s", s.days, s.start, s.stop, zone)
		if s.weekendsOff {
			text += ", off at weekends"
		}
		r := Recommendation{Source: "engine:offhours", Provider: u.provider, ResourceID: id, ResourceType: "vm", ProjectID: u.project, EnvironmentID: u.env,
			Action: "schedule", Current: map[string]any{"schedule": "always on"},
			Recommended: map[string]any{"schedule": text, "start": fmt.Sprintf("%02d:00", s.start), "stop": fmt.Sprintf("%02d:00", s.stop), "days": s.days, "weekends_off": s.weekendsOff, "time_zone": zone},
			Evidence: map[string]any{"lookback_days": u.days, "off_hours_per_week": s.offPerWeek, "hourly_cost": fmt.Sprintf("%.4f", cost[id]), "idle_below_cpu_pct": offHoursIdleCPU,
				"method": "hours whose CPU maximum stayed below 5% on every observed day are off; savings = usage-based hourly cost × off hours"},
			MonthlySavings: new(big.Rat).SetFloat64(monthly).FloatString(2), Currency: currency, SavingsBasis: "effective",
			Confidence: min(1, float64(u.days)/offHoursLookback),
			Risk:       map[string]any{"stop_mode": "stop without charging; disks and public IPs keep billing", "note": "jobs outside the window will not run"},
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

type window struct {
	days        string
	start, stop int
	weekendsOff bool
	offPerWeek  int
}

// schedule turns observed busy hours into one daily window. ok is false when
// the VM was busy around the clock (no contiguous window fits) or never busy
// (that is Waste, not scheduling).
func schedule(u *hourUse) (window, bool) {
	first, last := 24, -1
	weekendBusy := false
	for wd := 0; wd < 7; wd++ {
		for h := 0; h < 24; h++ {
			if !u.busy[wd][h] {
				continue
			}
			if wd == int(time.Saturday) || wd == int(time.Sunday) {
				weekendBusy = true
			}
			first, last = min(first, h), max(last, h)
		}
	}
	if last < 0 {
		return window{}, false
	}
	w := window{start: max(0, first-offHoursWarmUp), stop: last + 1, weekendsOff: !weekendBusy, days: "Mon–Fri"}
	if !w.weekendsOff {
		w.days = "Daily"
	}
	on := w.stop - w.start
	if w.weekendsOff {
		w.offPerWeek = 168 - 5*on
	} else {
		w.offPerWeek = 168 - 7*on
	}
	return w, true
}
