// Package anomaly finds days whose spend departs from its own recent
// baseline and raises them as Cost Anomaly Findings for the owning Team (#40).
package anomaly

import (
	"math"
	"sort"
)

// Config tunes detection. Zero values take the defaults.
type Config struct {
	// MinExcess is the smallest excess over baseline worth a Finding, in the
	// series' currency. Default 5.
	MinExcess float64
	// MinRatio is the smallest excess relative to baseline. Default 0.3 (30%).
	MinRatio float64
	// K is how many robust standard deviations above the median count. Default 3.
	K float64
}

// MinHistory is the number of baseline days required before judging a day.
const MinHistory = 14

// Verdict is the judgement on one day.
type Verdict struct {
	Anomalous bool
	Expected  float64 // baseline median
	Actual    float64
	Excess    float64
	Severity  string // low | medium | high | critical, from excess / expected
}

// Detect judges actual against history (the preceding days, oldest first)
// using the median and the median absolute deviation, which a few earlier
// spikes cannot drag around the way a mean and standard deviation would.
func Detect(history []float64, actual float64, c Config) Verdict {
	if c.MinExcess == 0 {
		c.MinExcess = 5
	}
	if c.MinRatio == 0 {
		c.MinRatio = 0.3
	}
	if c.K == 0 {
		c.K = 3
	}
	med := median(history)
	dev := make([]float64, len(history))
	for i, h := range history {
		dev[i] = math.Abs(h - med)
	}
	sigma := 1.4826 * median(dev) // MAD scaled to a normal standard deviation
	v := Verdict{Expected: med, Actual: actual, Excess: actual - med}
	v.Severity = severity(v.Excess, med)
	if len(history) < MinHistory || v.Excess <= 0 {
		return v
	}
	v.Anomalous = v.Excess >= c.MinExcess && v.Excess > c.K*sigma && (med == 0 || v.Excess/med >= c.MinRatio)
	return v
}

func severity(excess, expected float64) string {
	if expected <= 0 {
		if excess > 0 {
			return "high"
		}
		return "low"
	}
	switch r := excess / expected; {
	case r >= 4:
		return "critical"
	case r >= 1:
		return "high"
	case r >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}
