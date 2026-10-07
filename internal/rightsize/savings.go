package rightsize

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
)

// Tracker measures what applied recommendations actually saved (#75):
// a resource's average daily cost over the 14 days after apply against the
// 14 days before, from cost facts. Resources without their own cost line
// (Kubernetes workloads share node cost) keep the recommended figure, marked
// estimated. It also watches for regressions in the 30 days after apply.
type Tracker struct {
	Service Service
	Now     func() time.Time
}

const (
	savingsWindow    = 14 // days either side of apply
	savingsMinAfter  = 7  // days after apply before a first figure
	regressionWatch  = 30 // days after apply to watch
	underProvisioned = 0.95
	daysPerMonth     = 30
)

// TrackResult counts what a run did.
type TrackResult struct {
	Updated     int `json:"updated"`
	Waiting     int `json:"waiting"`
	Regressions int `json:"regressions"`
}

type applied struct {
	id, provider, resource, action, currency, savings, finding string
	at                                                         time.Time
	regression                                                 *string
}

// Run evaluates every Tenant.
func (t Tracker) Run(ctx context.Context) (TrackResult, error) {
	var res TrackResult
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	rows, err := t.Service.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	today := now().UTC().Truncate(24 * time.Hour)
	for _, tenant := range tenants {
		err := t.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			return t.tenant(ctx, tx, tenant, today, &res)
		})
		if err != nil {
			return res, fmt.Errorf("tenant %s: %w", tenant, err)
		}
	}
	return res, nil
}

func (t Tracker) tenant(ctx context.Context, tx pgx.Tx, tenant string, today time.Time, res *TrackResult) error {
	rows, err := tx.Query(ctx, `SELECT id::text, provider, resource_id, action, currency, monthly_savings::text, coalesce(finding_id::text, ''), applied_at, regression
		FROM recommendations WHERE state = 'applied' AND applied_at IS NOT NULL AND applied_at > $1`, today.AddDate(0, 0, -regressionWatch-savingsWindow))
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (applied, error) {
		var a applied
		err := r.Scan(&a.id, &a.provider, &a.resource, &a.action, &a.currency, &a.savings, &a.finding, &a.at, &a.regression)
		return a, err
	})
	if err != nil {
		return err
	}
	for _, a := range list {
		day := a.at.UTC().Truncate(24 * time.Hour)
		after := int(today.Sub(day).Hours() / 24)
		if after < savingsMinAfter {
			res.Waiting++
			continue
		}
		if after <= savingsWindow+1 { // settle once the after-window is complete
			realised, method, err := t.realised(ctx, tx, a, day, today)
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE recommendations SET realised_savings = $2::numeric, realised_method = $3, updated_at = now()
				WHERE id = $1 AND (realised_savings IS DISTINCT FROM $2::numeric OR realised_method IS DISTINCT FROM $3)`, a.id, realised, method)
			if err != nil {
				return err
			}
			res.Updated += int(tag.RowsAffected())
		}
		if a.regression == nil && after <= regressionWatch {
			why, err := regression(ctx, tx, a, day)
			if err != nil {
				return err
			}
			if why != "" {
				if err := flagRegression(ctx, tx, tenant, a, why); err != nil {
					return err
				}
				res.Regressions++
			}
		}
	}
	return nil
}

// realised returns monthly savings in the recommendation's currency.
func (t Tracker) realised(ctx context.Context, tx pgx.Tx, a applied, day, today time.Time) (string, string, error) {
	end := day.AddDate(0, 0, savingsWindow)
	if today.Before(end) {
		end = today
	}
	var before, afterSum float64
	var beforeDays, afterDays int
	err := tx.QueryRow(ctx, `
		WITH d AS (
			SELECT (charge_period_start AT TIME ZONE 'UTC')::date AS day,
			       sum(fx_convert(coalesce(effective_cost, billed_cost), billing_currency, $5, (charge_period_start AT TIME ZONE 'UTC')::date))::float8 AS amt
			FROM cost_facts WHERE current AND resource_id = $1 AND charge_period_start >= $2 AND charge_period_start < $4
			GROUP BY 1)
		SELECT coalesce(sum(amt) FILTER (WHERE day < $3::date), 0), count(*) FILTER (WHERE day < $3::date),
		       coalesce(sum(amt) FILTER (WHERE day >= $3::date), 0), count(*) FILTER (WHERE day >= $3::date)
		FROM d`, a.resource, day.AddDate(0, 0, -savingsWindow), day, end, a.currency).Scan(&before, &beforeDays, &afterSum, &afterDays)
	if err != nil {
		return "", "", err
	}
	if beforeDays < savingsMinAfter {
		return a.savings, "estimated", nil
	}
	if a.action == "delete" {
		afterDays = int(end.Sub(day).Hours() / 24) // a deleted resource stops billing: missing days are zero
	}
	if afterDays == 0 {
		return a.savings, "estimated", nil
	}
	saving := (before/float64(beforeDays) - afterSum/float64(afterDays)) * daysPerMonth
	return new(big.Rat).SetFloat64(saving).FloatString(2), "measured", nil
}

// regression finds signs the change went too far: newer advice to grow the
// same resource, or requests now running hot.
func regression(ctx context.Context, tx pgx.Tx, a applied, day time.Time) (string, error) {
	var why string
	err := tx.QueryRow(ctx, `SELECT 'newer advice to grow it: ' || action || ' ' || recommended::text FROM recommendations
		WHERE provider = $1 AND resource_id = $2 AND id <> $3 AND generated_at > $4
		  AND (monthly_savings < 0 OR risk->>'under_provisioned' = 'true')
		ORDER BY generated_at LIMIT 1`, a.provider, a.resource, a.id, a.at).Scan(&why)
	if err == nil || err != pgx.ErrNoRows {
		return why, err
	}
	err = tx.QueryRow(ctx, `SELECT format('%s p95 at %s%% of request on %s', metric, round((p95 / request * 100)::numeric), day) FROM utilisation_daily
		WHERE resource_id = $1 AND day >= $2 AND request > 0 AND p95 / request > $3 ORDER BY day LIMIT 1`, a.resource, day, underProvisioned).Scan(&why)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return why, err
}

func flagRegression(ctx context.Context, tx pgx.Tx, tenant string, a applied, why string) error {
	if _, err := tx.Exec(ctx, `UPDATE recommendations SET regression = $2, updated_at = now() WHERE id = $1`, a.id, why); err != nil {
		return err
	}
	if a.finding != "" {
		if _, err := tx.Exec(ctx, `UPDATE findings SET detail = detail || jsonb_build_object('regression', $2::text), last_seen_at = now() WHERE id = $1`, a.finding, why); err != nil {
			return err
		}
	}
	return record(ctx, tx, tenant, a.id, "keel.recommendation.regression", "FlagRegression", activity.Update, keelActor, why)
}

// SavingsItem is one applied recommendation in a summary.
type SavingsItem struct {
	ID          string    `json:"id"`
	ResourceID  string    `json:"resource_id"`
	Action      string    `json:"action"`
	ProjectID   *string   `json:"project_id"`
	Recommended string    `json:"recommended"`
	Realised    *string   `json:"realised"`
	Method      *string   `json:"method"`
	Regression  *string   `json:"regression"`
	AppliedAt   time.Time `json:"applied_at"`
}

// Summary is monthly savings at each stage, in the Tenant's currency.
type Summary struct {
	Currency    string        `json:"currency"`
	Open        string        `json:"open"`
	Accepted    string        `json:"accepted"`
	Applied     string        `json:"applied"`
	Realised    string        `json:"realised"`
	Regressions int           `json:"regressions"`
	Items       []SavingsItem `json:"items"`
}

// Summary totals one Tenant, or one Project when project is set.
func (t Tracker) Summary(ctx context.Context, tenant, project string) (Summary, error) {
	var s Summary
	err := t.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT currency FROM tenants WHERE id = $1`, tenant).Scan(&s.Currency); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			SELECT coalesce(sum(fx_convert(monthly_savings, currency, $2, current_date)) FILTER (WHERE state = 'open'), 0)::numeric(18,2)::text,
			       coalesce(sum(fx_convert(monthly_savings, currency, $2, current_date)) FILTER (WHERE state = 'accepted'), 0)::numeric(18,2)::text,
			       coalesce(sum(fx_convert(monthly_savings, currency, $2, current_date)) FILTER (WHERE state = 'applied'), 0)::numeric(18,2)::text,
			       coalesce(sum(fx_convert(realised_savings, currency, $2, current_date)) FILTER (WHERE state = 'applied'), 0)::numeric(18,2)::text,
			       count(*) FILTER (WHERE state = 'applied' AND regression IS NOT NULL)
			FROM recommendations WHERE ($1 = '' OR project_id::text = $1)`, project, s.Currency).Scan(&s.Open, &s.Accepted, &s.Applied, &s.Realised, &s.Regressions); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text, resource_id, action, project_id::text, monthly_savings::text, realised_savings::text, realised_method, regression, applied_at
			FROM recommendations WHERE state = 'applied' AND applied_at IS NOT NULL AND ($1 = '' OR project_id::text = $1) ORDER BY applied_at DESC LIMIT 200`, project)
		if err != nil {
			return err
		}
		s.Items, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SavingsItem, error) {
			var i SavingsItem
			err := r.Scan(&i.ID, &i.ResourceID, &i.Action, &i.ProjectID, &i.Recommended, &i.Realised, &i.Method, &i.Regression, &i.AppliedAt)
			return i, err
		})
		return err
	})
	return s, err
}
