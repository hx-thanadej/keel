// Package forecast projects daily spend to the end of a Budget window
// (#38, ADR-0012). The model is classical decomposition: a linear trend
// (damped for long horizons) times day-of-week factors, with p10/p90 bands
// from resampling the model's own recent errors. It needs at least one full
// cycle (28 days) of history; with less it says so instead of guessing.
//
// Deterministic: the same series and seed always give the same result.
package forecast

import (
	"math"
	"math/rand/v2"
	"sort"
	"time"
)

// Methods reported with a Result.
const (
	SeasonalTrend       = "seasonal_trend"
	InsufficientHistory = "insufficient_history"
)

// MinHistory is the history required before forecasting (one full cycle).
const MinHistory = 28

const (
	window      = 84   // days used for seasonality
	trendDays   = 56   // days used for the trend
	damping     = 0.99 // per-day trend damping
	simulations = 1000
)

// Series is spend on consecutive UTC days starting at Start.
type Series struct {
	Start  time.Time
	Values []float64
}

// At returns the value at index i (ignores day; matches test helpers).
func (s Series) At(i int, _ time.Time) float64 { return s.Values[i] }

// Result is a forecast of the total over the horizon.
type Result struct {
	P10, P50, P90 float64
	Method        string
	HistoryDays   int
}

type model struct {
	a, b    float64    // trend: a + b*t, t = index within the series
	factors [7]float64 // by time.Weekday
	resid   []float64
	n       int
}

func fit(s Series) model {
	n := len(s.Values)
	lo := max(0, n-window)
	ys := s.Values[lo:]
	ts := make([]float64, len(ys))
	for i := range ys {
		ts[i] = float64(lo + i)
	}
	a0, b0 := linear(ts, ys)

	// Day-of-week factors from ratios to the raw trend, normalised to mean 1.
	var sum, cnt [7]float64
	for i, y := range ys {
		tr := a0 + b0*ts[i]
		if tr <= 0 {
			continue
		}
		d := s.Start.AddDate(0, 0, lo+i).Weekday()
		sum[d] += y / tr
		cnt[d]++
	}
	var m model
	total := 0.0
	for d := 0; d < 7; d++ {
		m.factors[d] = 1
		if cnt[d] > 0 {
			m.factors[d] = sum[d] / cnt[d]
		}
		total += m.factors[d]
	}
	if total > 0 {
		for d := range m.factors {
			m.factors[d] *= 7 / total
		}
	}

	// Trend on deseasonalised recent days.
	tlo := max(0, n-trendDays)
	var tt, dd []float64
	for i := tlo; i < n; i++ {
		f := m.factors[s.Start.AddDate(0, 0, i).Weekday()]
		if f <= 0 {
			continue
		}
		tt = append(tt, float64(i))
		dd = append(dd, s.Values[i]/f)
	}
	m.a, m.b = linear(tt, dd)
	m.n = n
	for i := tlo; i < n; i++ {
		m.resid = append(m.resid, s.Values[i]-m.point(s, i))
	}
	return m
}

// point is the model's expected value at index i (i ≥ n is the future,
// with the trend damped beyond the last observation).
func (m model) point(s Series, i int) float64 {
	t := float64(i)
	if i >= m.n {
		k := float64(i - (m.n - 1))
		last := float64(m.n - 1)
		t = last + (damping*(1-math.Pow(damping, k)))/(1-damping)
	}
	return math.Max(0, (m.a+m.b*t)*m.factors[s.Start.AddDate(0, 0, i).Weekday()])
}

// Total forecasts the sum of the next horizon days after the series.
func Total(s Series, horizon int, seed uint64) Result {
	n := len(s.Values)
	if n < MinHistory {
		return Result{Method: InsufficientHistory, HistoryDays: n}
	}
	if horizon <= 0 {
		return Result{Method: SeasonalTrend, HistoryDays: n}
	}
	m := fit(s)
	p50 := 0.0
	points := make([]float64, horizon)
	for h := 0; h < horizon; h++ {
		points[h] = m.point(s, n+h)
		p50 += points[h]
	}
	rng := rand.New(rand.NewPCG(seed, uint64(n)))
	sims := make([]float64, simulations)
	for k := range sims {
		total := 0.0
		for _, p := range points {
			total += math.Max(0, p+m.resid[rng.IntN(len(m.resid))])
		}
		sims[k] = total
	}
	sort.Float64s(sims)
	r := Result{P10: sims[simulations/10], P50: p50, P90: sims[simulations*9/10], Method: SeasonalTrend, HistoryDays: n}
	r.P10, r.P90 = math.Min(r.P10, r.P50), math.Max(r.P90, r.P50)
	return r
}

// BacktestResult is forecast accuracy on past months.
type BacktestResult struct {
	Months int     // months evaluated
	MAPE   float64 // mean absolute percentage error of the month total, 0..1
}

// Backtest forecasts each of the last `months` complete months as of their
// 10th day and compares the predicted month total with the actual one.
func Backtest(s Series, months int) BacktestResult {
	end := s.Start.AddDate(0, 0, len(s.Values))
	monthStart := time.Date(end.Year(), end.Month(), 1, 0, 0, 0, 0, time.UTC)
	var errs []float64
	for k := 1; k <= months; k++ {
		ms := monthStart.AddDate(0, -k, 0)
		me := ms.AddDate(0, 1, 0)
		cut := ms.AddDate(0, 0, 10)
		ci := int(cut.Sub(s.Start).Hours() / 24)
		ei := int(me.Sub(s.Start).Hours() / 24)
		si := int(ms.Sub(s.Start).Hours() / 24)
		if si < 0 || ci < MinHistory || ei > len(s.Values) {
			continue
		}
		actual, sofar := 0.0, 0.0
		for i := si; i < ei; i++ {
			actual += s.Values[i]
			if i < ci {
				sofar += s.Values[i]
			}
		}
		if actual == 0 {
			continue
		}
		pred := sofar + Total(Series{Start: s.Start, Values: s.Values[:ci]}, ei-ci, 1).P50
		errs = append(errs, math.Abs(pred-actual)/actual)
	}
	r := BacktestResult{Months: len(errs)}
	for _, e := range errs {
		r.MAPE += e / float64(len(errs))
	}
	return r
}

func linear(x, y []float64) (a, b float64) {
	n := float64(len(x))
	if n == 0 {
		return 0, 0
	}
	var sx, sy, sxx, sxy float64
	for i := range x {
		sx += x[i]
		sy += y[i]
		sxx += x[i] * x[i]
		sxy += x[i] * y[i]
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return sy / n, 0
	}
	b = (n*sxy - sx*sy) / den
	return (sy - b*sx) / n, b
}
