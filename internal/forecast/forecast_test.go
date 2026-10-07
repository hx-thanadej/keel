package forecast_test

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/forecast"
)

// monday is a Monday, so day-of-week patterns are easy to read.
var monday = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func series(n int, f func(i int, day time.Time) float64) forecast.Series {
	s := forecast.Series{Start: monday}
	for i := 0; i < n; i++ {
		s.Values = append(s.Values, f(i, monday.AddDate(0, 0, i)))
	}
	return s
}

func near(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

func TestConstantSpend(t *testing.T) {
	s := series(60, func(int, time.Time) float64 { return 100 })
	r := forecast.Total(s, 10, 1)
	if r.Method != forecast.SeasonalTrend || !near(r.P50, 1000, 1) || !near(r.P10, r.P90, 1) {
		t.Fatalf("constant: %+v", r)
	}
}

func TestWeeklySeasonality(t *testing.T) {
	// Weekdays 100, weekends 20. Next 7 days must total ~540, not 7×mean (≈491).
	s := series(70, func(_ int, d time.Time) float64 {
		if d.Weekday() == time.Saturday || d.Weekday() == time.Sunday {
			return 20
		}
		return 100
	})
	r := forecast.Total(s, 7, 1)
	if !near(r.P50, 540, 5) {
		t.Fatalf("weekly: p50 %.2f, want ~540", r.P50)
	}
	// Starting on a weekend (horizon 2 after a Friday) must be the low days.
	s2 := series(68, s.At) // ends on a Friday (day 67)
	if r2 := forecast.Total(s2, 2, 1); !near(r2.P50, 40, 3) {
		t.Fatalf("weekend horizon p50 %.2f, want ~40", r2.P50)
	}
}

func TestTrend(t *testing.T) {
	s := series(60, func(i int, _ time.Time) float64 { return 100 + 2*float64(i) })
	r := forecast.Total(s, 10, 1)
	// Days 60..69: 220..238 → 2290.
	if !near(r.P50, 2290, 25) {
		t.Fatalf("trend p50 %.2f, want ~2290", r.P50)
	}
}

func TestNoiseGivesOrderedBands(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 7))
	s := series(90, func(int, time.Time) float64 { return 100 + rng.NormFloat64()*20 })
	r := forecast.Total(s, 20, 42)
	if !(r.P10 < r.P50 && r.P50 < r.P90) || !near(r.P50, 2000, 150) {
		t.Fatalf("noise %+v", r)
	}
	if r2 := forecast.Total(s, 20, 42); r2 != r {
		t.Fatal("same input and seed must give the same forecast")
	}
}

func TestNeverNegative(t *testing.T) {
	s := series(40, func(i int, _ time.Time) float64 { return math.Max(0, 100-3*float64(i)) })
	if r := forecast.Total(s, 30, 1); r.P10 < 0 || r.P50 < 0 {
		t.Fatalf("negative forecast %+v", r)
	}
}

func TestInsufficientHistory(t *testing.T) {
	s := series(20, func(int, time.Time) float64 { return 100 })
	if r := forecast.Total(s, 10, 1); r.Method != forecast.InsufficientHistory {
		t.Fatalf("20 days: %+v", r)
	}
}

func TestBacktest(t *testing.T) {
	s := series(200, func(_ int, d time.Time) float64 {
		if d.Weekday() == time.Sunday {
			return 30
		}
		return 100
	})
	bt := forecast.Backtest(s, 3)
	if bt.Months != 3 || bt.MAPE > 0.02 {
		t.Fatalf("backtest %+v", bt)
	}
}
