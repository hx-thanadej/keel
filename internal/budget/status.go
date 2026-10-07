package budget

import (
	"context"
	"hash/fnv"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/forecast"
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
	Budget         string    `json:"budget"`         // whole window
	BudgetToDate   string    `json:"budget_to_date"` // prorated to AsOf
	Actual         string    `json:"actual"`         // to date
	Forecast       string    `json:"forecast"`       // p50 at window end; "" for Day or without enough history
	ForecastP10    string    `json:"forecast_p10"`
	ForecastP90    string    `json:"forecast_p90"`
	ForecastMethod string    `json:"forecast_method"` // seasonal_trend | insufficient_history
	HistoryDays    int       `json:"history_days"`
	BacktestMAPE   *float64  `json:"backtest_mape,omitempty"` // month-total error on up to 3 past months
	Variance       string    `json:"variance"`                // actual - budget_to_date
	Final          bool      `json:"final"`                   // every provider month in the window is final
	MissingFX      bool      `json:"missing_fx"`              // some spend could not be converted
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
		histStart := yearStart.AddDate(0, 0, -forecast.MinHistory*3)
		spend, missing, providers, err := s.daily(ctx, tx, b, histStart, asOf.AddDate(0, 0, 1))
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
			s.forecast(&st, b, spend, actual, asOf, end)
		}
		st.Final, err = s.final(ctx, tx, providers, start, asOf)
		return err
	})
	return st, mapErr(err)
}

// forecast fills the forecast fields: actual so far plus the model's
// projection of the remaining days. History starts at the scope's first day
// with spend; with less than forecast.MinHistory days the forecast is withheld.
func (s Service) forecast(st *Status, b Budget, spend map[time.Time]*big.Rat, actual *big.Rat, asOf, end time.Time) {
	first := asOf
	for d := range spend {
		if d.Before(first) {
			first = d
		}
	}
	series := forecast.Series{Start: first}
	for d := first; !d.After(asOf); d = d.AddDate(0, 0, 1) {
		v := 0.0
		if r := spend[d]; r != nil {
			v, _ = r.Float64()
		}
		series.Values = append(series.Values, v)
	}
	horizon := int(end.Sub(asOf.AddDate(0, 0, 1)).Hours() / 24)
	h := fnv.New64a()
	_, _ = h.Write([]byte(b.ID))
	r := forecast.Total(series, horizon, h.Sum64())
	st.ForecastMethod, st.HistoryDays = r.Method, r.HistoryDays
	if r.Method != forecast.SeasonalTrend {
		return
	}
	add := func(v float64) string { return money(new(big.Rat).Add(actual, new(big.Rat).SetFloat64(v))) }
	st.Forecast, st.ForecastP10, st.ForecastP90 = add(r.P50), add(r.P10), add(r.P90)
	if bt := forecast.Backtest(series, 3); bt.Months > 0 {
		st.BacktestMAPE = &bt.MAPE
	}
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
