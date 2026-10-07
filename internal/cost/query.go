package cost

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
)

// Queries reads cost facts within a Tenant's scope. Authorisation is the
// caller's job (the API layer asks the policy first).
type Queries struct {
	Store *store.Store
}

// DailyFilter narrows Daily. Zero values mean all.
type DailyFilter struct {
	From, To      time.Time // [From, To)
	ProjectID     string
	EnvironmentID string
}

// DailyRow is spend for one day, Project and Environment.
type DailyRow struct {
	Day             time.Time `json:"day"`
	ProjectID       *string   `json:"project_id"`
	ProjectSlug     *string   `json:"project_slug"`
	EnvironmentID   *string   `json:"environment_id"`
	EnvironmentName string    `json:"environment_name"`
	Provider        string    `json:"provider"`
	Currency        string    `json:"currency"`
	Billed          string    `json:"billed"`
	Effective       *string   `json:"effective"` // null until derived where the source has none
}

// Daily returns spend per day by charge period start (UTC days).
func (q Queries) Daily(ctx context.Context, tenantID string, f DailyFilter) ([]DailyRow, error) {
	var out []DailyRow
	err := q.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT date_trunc('day', f.charge_period_start AT TIME ZONE 'UTC') AS day, f.project_id::text, p.slug, f.environment_id::text,
			       coalesce(e.name, ''), f.provider, f.billing_currency,
			       to_char(sum(f.billed_cost), 'FM999999999990.00'),
			       CASE WHEN bool_and(f.effective_cost IS NOT NULL) THEN to_char(sum(f.effective_cost), 'FM999999999990.00') END
			FROM cost_facts f
			LEFT JOIN projects p ON p.id = f.project_id
			LEFT JOIN environments e ON e.id = f.environment_id
			WHERE f.current AND f.charge_period_start >= $1 AND f.charge_period_start < $2
			  AND ($3 = '' OR f.project_id::text = $3) AND ($4 = '' OR f.environment_id::text = $4)
			GROUP BY 1, 2, 3, 4, 5, 6, 7
			ORDER BY 1, 3 NULLS LAST, 5`, f.From, f.To, f.ProjectID, f.EnvironmentID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (DailyRow, error) {
			var d DailyRow
			err := r.Scan(&d.Day, &d.ProjectID, &d.ProjectSlug, &d.EnvironmentID, &d.EnvironmentName, &d.Provider, &d.Currency, &d.Billed, &d.Effective)
			d.Day = d.Day.UTC()
			return d, err
		})
		return err
	})
	return out, err
}

// UnallocatedKPI is spend that could not be attributed to a Project.
type UnallocatedKPI struct {
	Total       string  `json:"total"`
	Unallocated string  `json:"unallocated"`
	Percent     float64 `json:"percent"`
	Currency    string  `json:"currency"`
}

// Unallocated reports unattributed spend across current loads for billing
// periods overlapping [from, to). Only meaningful in the home Tenant, which
// holds the load records.
func (q Queries) Unallocated(ctx context.Context, homeTenantID string, from, to time.Time) (UnallocatedKPI, error) {
	var k UnallocatedKPI
	err := q.Store.InTenant(ctx, homeTenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT to_char(coalesce(sum(total_billed), 0), 'FM999999999990.00'), to_char(coalesce(sum(unallocated_billed), 0), 'FM999999999990.00'), coalesce(max(currency), '')
			FROM cost_loads WHERE superseded_at IS NULL AND billing_period >= date_trunc('month', $1::timestamptz) AND billing_period < $2`, from, to).
			Scan(&k.Total, &k.Unallocated, &k.Currency)
	})
	if err != nil {
		return k, err
	}
	t, _ := strconv.ParseFloat(k.Total, 64)
	u, _ := strconv.ParseFloat(k.Unallocated, 64)
	if t > 0 {
		k.Percent = u / t * 100
	}
	return k, nil
}

// LoadSummary is a load with its reconciliation outcome.
type LoadSummary struct {
	ID              string     `json:"id"`
	Provider        string     `json:"provider"`
	BillingAccount  string     `json:"billing_account_id"`
	BillingPeriod   time.Time  `json:"billing_period"`
	Final           bool       `json:"final"`
	Lines           int        `json:"lines"`
	TotalBilled     string     `json:"total_billed"`
	Unallocated     string     `json:"unallocated_billed"`
	Currency        string     `json:"currency"`
	InvoiceTotal    *string    `json:"invoice_total"`
	ReconcileStatus string     `json:"reconcile_status"`
	ReconcileDiff   *string    `json:"reconcile_diff"`
	LoadedAt        time.Time  `json:"loaded_at"`
	SupersededAt    *time.Time `json:"superseded_at"`
}

// Loads lists recent loads (home Tenant only holds them).
func (q Queries) Loads(ctx context.Context, homeTenantID string, limit int) ([]LoadSummary, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []LoadSummary
	err := q.Store.InTenant(ctx, homeTenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, provider, billing_account_id, billing_period, is_final, line_count,
				to_char(total_billed, 'FM999999999990.00'), to_char(unallocated_billed, 'FM999999999990.00'), currency,
				to_char(invoice_total, 'FM999999999990.00'), reconcile_status, to_char(reconcile_diff, 'FM999999999990.00'), loaded_at, superseded_at
			FROM cost_loads ORDER BY loaded_at DESC LIMIT $1`, limit)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[LoadSummary])
		return err
	})
	return out, err
}

// BreakdownRow is spend for one service or resource over a window, in the
// Tenant's currency.
type BreakdownRow struct {
	Key       string `json:"key"`
	Service   string `json:"service"`
	Billed    string `json:"billed"`
	Effective string `json:"effective"`
	Currency  string `json:"currency"`
}

// Breakdown ranks services (by="service") or resources (by="resource") by
// effective spend in [from, to), converted to the Tenant's currency.
func (q Queries) Breakdown(ctx context.Context, tenantID string, f DailyFilter, by string, limit int) ([]BreakdownRow, error) {
	key := "service_name"
	if by == "resource" {
		key = "coalesce(nullif(resource_id, ''), '(no resource id)')"
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []BreakdownRow
	err := q.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH t AS (SELECT currency FROM tenants WHERE id = current_tenant_id())
			SELECT k, svc,
			       to_char(sum(fx_convert(billed, cur, (SELECT currency FROM t), d)), 'FM999999999990.00'),
			       to_char(sum(fx_convert(effective, cur, (SELECT currency FROM t), d)), 'FM999999999990.00'),
			       (SELECT currency FROM t)
			FROM (SELECT `+key+` AS k, max(service_name) AS svc, billing_currency AS cur, (charge_period_start AT TIME ZONE 'UTC')::date AS d,
			             sum(billed_cost) AS billed, sum(coalesce(effective_cost, billed_cost)) AS effective
			      FROM cost_facts
			      WHERE current AND charge_period_start >= $1 AND charge_period_start < $2
			        AND ($3 = '' OR project_id::text = $3) AND ($4 = '' OR environment_id::text = $4)
			      GROUP BY 1, 3, 4) x
			GROUP BY 1, 2
			ORDER BY sum(fx_convert(effective, cur, (SELECT currency FROM t), d)) DESC NULLS LAST
			LIMIT $5`, f.From, f.To, f.ProjectID, f.EnvironmentID, limit)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (BreakdownRow, error) {
			var b BreakdownRow
			var billed, eff *string
			err := r.Scan(&b.Key, &b.Service, &billed, &eff, &b.Currency)
			if billed != nil {
				b.Billed = *billed
			}
			if eff != nil {
				b.Effective = *eff
			}
			return b, err
		})
		return err
	})
	return out, err
}
