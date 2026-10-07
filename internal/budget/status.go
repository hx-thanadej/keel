package budget

import (
	"context"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
)

// Period selects the Status window.
type Period string

// Status windows (the Day / Month / Year toggle).
const (
	Day   Period = "day"
	Month Period = "month"
	Year  Period = "year"
)

// Point is one step of a series: a day of a month, or a month of a year.
type Point struct {
	Start  time.Time `json:"start"`
	Budget string    `json:"budget"`
	Actual string    `json:"actual"` // "" after the as-of date
}

// Status compares spend with budget for one window ending at AsOf.
type Status struct {
	BudgetID       string    `json:"budget_id"`
	Period         Period    `json:"period"`
	Start          time.Time `json:"start"`
	AsOf           time.Time `json:"as_of"`
	Currency       string    `json:"currency"`
	CostBasis      string    `json:"cost_basis"`
	Budget         string    `json:"budget"`          // whole window
	BudgetToDate   string    `json:"budget_to_date"`  // prorated to AsOf
	Actual         string    `json:"actual"`          // to date
	Forecast       string    `json:"forecast"`        // window end; "" for Day
	ForecastMethod string    `json:"forecast_method"` // run_rate until #38
	Variance       string    `json:"variance"`        // actual - budget_to_date
	Final          bool      `json:"final"`           // every provider month in the window is final
	MissingFX      bool      `json:"missing_fx"`      // some spend could not be converted
	Series         []Point   `json:"series"`
}

// daily returns converted spend per UTC day in [from, to) for b's scope.
func (s Service) daily(ctx context.Context, tx pgx.Tx, b Budget, from, to time.Time) (map[time.Time]*big.Rat, bool, []string, error) {
	amount := "coalesce(effective_cost, billed_cost)"
	if b.CostBasis == "billed" {
		amount = "billed_cost"
	}
	rows, err := tx.Query(ctx, `
		SELECT d, fx_convert(amt, cur, $5, d)::text
		FROM (SELECT (charge_period_start AT TIME ZONE 'UTC')::date AS d, billing_currency AS cur, sum(`+amount+`) AS amt
		      FROM cost_facts
		      WHERE current AND project_id = $1 AND ($2::uuid IS NULL OR environment_id = $2) AND ($3::text IS NULL OR provider = $3)
		        AND charge_period_start >= $4 AND charge_period_start < $6
		      GROUP BY 1, 2) x`, b.ProjectID, b.EnvironmentID, b.Provider, from, b.Currency, to)
	if err != nil {
		return nil, false, nil, err
	}
	out := map[time.Time]*big.Rat{}
	missing := false
	for rows.Next() {
		var d time.Time
		var v *string
		if err := rows.Scan(&d, &v); err != nil {
			rows.Close()
			return nil, false, nil, err
		}
		if v == nil {
			missing = true
			continue
		}
		d = time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC)
		if out[d] == nil {
			out[d] = new(big.Rat)
		}
		out[d].Add(out[d], rat(*v))
	}
	rows.Close()
	provRows, err := tx.Query(ctx, `SELECT DISTINCT provider FROM cost_facts WHERE current AND project_id = $1 AND ($2::uuid IS NULL OR environment_id = $2) AND charge_period_start >= $3 AND charge_period_start < $4`,
		b.ProjectID, b.EnvironmentID, from, to)
	if err != nil {
		return nil, false, nil, err
	}
	providers, err := pgx.CollectRows(provRows, pgx.RowTo[string])
	return out, missing, providers, err
}

// Status evaluates b for the Day, Month or Year containing asOf.
func (s Service) Status(ctx context.Context, tenantID, budgetID string, p Period, asOf time.Time) (Status, error) {
	asOf = time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
	var st Status
	err := s.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		b, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM budgets WHERE id = $1 AND archived_at IS NULL`, budgetID))
		if err != nil {
			return err
		}
		yearStart := time.Date(b.Year, 1, 1, 0, 0, 0, 0, time.UTC)
		yearEnd := yearStart.AddDate(1, 0, 0)
		// Clamp to the budget's year.
		if asOf.Before(yearStart) {
			asOf = yearStart
		}
		if !asOf.Before(yearEnd) {
			asOf = yearEnd.AddDate(0, 0, -1)
		}
		spend, missing, providers, err := s.daily(ctx, tx, b, yearStart, asOf.AddDate(0, 0, 1))
		if err != nil {
			return err
		}
		st = Status{BudgetID: b.ID, Period: p, AsOf: asOf, Currency: b.Currency, CostBasis: b.CostBasis, MissingFX: missing}
		var start, end time.Time
		switch p {
		case Day:
			start, end = asOf, asOf.AddDate(0, 0, 1)
		case Month:
			start = time.Date(asOf.Year(), asOf.Month(), 1, 0, 0, 0, 0, time.UTC)
			end = start.AddDate(0, 1, 0)
		default:
			st.Period = Year
			start, end = yearStart, yearEnd
		}
		st.Start = start
		budget, toDate, actual := new(big.Rat), new(big.Rat), new(big.Rat)
		if st.Period == Year {
			for m := time.January; m <= time.December; m++ {
				ms := time.Date(b.Year, m, 1, 0, 0, 0, 0, time.UTC)
				pt := Point{Start: ms, Budget: money(b.monthRat(m))}
				budget.Add(budget, b.monthRat(m))
				if !ms.After(asOf) {
					a := new(big.Rat)
					for d := ms; d.Before(ms.AddDate(0, 1, 0)) && !d.After(asOf); d = d.AddDate(0, 0, 1) {
						if v := spend[d]; v != nil {
							a.Add(a, v)
						}
						toDate.Add(toDate, b.dayRat(d))
					}
					actual.Add(actual, a)
					pt.Actual = money(a)
				}
				st.Series = append(st.Series, pt)
			}
		} else {
			for d := start; d.Before(end); d = d.AddDate(0, 0, 1) {
				pt := Point{Start: d, Budget: money(b.dayRat(d))}
				budget.Add(budget, b.dayRat(d))
				if !d.After(asOf) {
					a := new(big.Rat)
					if v := spend[d]; v != nil {
						a.Set(v)
					}
					actual.Add(actual, a)
					toDate.Add(toDate, b.dayRat(d))
					pt.Actual = money(a)
				}
				if st.Period == Month {
					st.Series = append(st.Series, pt)
				}
			}
		}
		st.Budget, st.BudgetToDate, st.Actual = money(budget), money(toDate), money(actual)
		st.Variance = money(new(big.Rat).Sub(actual, toDate))
		if st.Period != Day {
			st.Forecast, st.ForecastMethod = money(runRate(spend, actual, asOf, end)), "run_rate"
		}
		st.Final, err = s.final(ctx, tx, providers, start, asOf)
		return err
	})
	return st, mapErr(err)
}

// runRate projects to end: actual so far + mean daily spend over the last
// (up to) 7 days with data × days remaining. Replaced by a proper model in #38.
func runRate(spend map[time.Time]*big.Rat, actual *big.Rat, asOf, end time.Time) *big.Rat {
	sum, n := new(big.Rat), 0
	for d := asOf; n < 7 && d.After(asOf.AddDate(0, 0, -30)); d = d.AddDate(0, 0, -1) {
		if v := spend[d]; v != nil {
			sum.Add(sum, v)
			n++
		}
	}
	out := new(big.Rat).Set(actual)
	remaining := int64(end.Sub(asOf.AddDate(0, 0, 1)).Hours() / 24)
	if n > 0 && remaining > 0 {
		avg := new(big.Rat).Quo(sum, big.NewRat(int64(n), 1))
		out.Add(out, new(big.Rat).Mul(avg, big.NewRat(remaining, 1)))
	}
	return out
}

func (s Service) final(ctx context.Context, tx pgx.Tx, providers []string, start, asOf time.Time) (bool, error) {
	if len(providers) == 0 {
		return false, nil
	}
	rows, err := tx.Query(ctx, `SELECT provider, billing_period FROM cost_periods_final($1)`, start)
	if err != nil {
		return false, err
	}
	type key struct {
		p string
		m time.Time
	}
	done := map[key]bool{}
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.p, &k.m); err != nil {
			rows.Close()
			return false, err
		}
		done[key{k.p, time.Date(k.m.Year(), k.m.Month(), 1, 0, 0, 0, 0, time.UTC)}] = true
	}
	rows.Close()
	for m := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC); !m.After(asOf); m = m.AddDate(0, 1, 0) {
		for _, p := range providers {
			if !done[key{p, m}] {
				return false, nil
			}
		}
	}
	return true, nil
}
