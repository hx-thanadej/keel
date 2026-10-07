package anomaly_test

import (
	"math/rand/v2"
	"testing"

	"github.com/hx-thanadej/keel/internal/anomaly"
)

func base(n int, f func(i int) float64) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

var cfg = anomaly.Config{MinExcess: 5}

func TestSpikeDetected(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 1))
	hist := base(28, func(int) float64 { return 100 + rng.NormFloat64()*5 })
	v := anomaly.Detect(hist, 300, cfg)
	if !v.Anomalous || v.Expected < 95 || v.Expected > 105 || v.Excess < 190 || v.Severity != "high" {
		t.Fatalf("spike %+v", v)
	}
}

func TestNormalDayNotFlagged(t *testing.T) {
	rng := rand.New(rand.NewPCG(2, 2))
	hist := base(28, func(int) float64 { return 100 + rng.NormFloat64()*5 })
	if v := anomaly.Detect(hist, 110, cfg); v.Anomalous {
		t.Fatalf("normal %+v", v)
	}
}

func TestSmallAbsoluteChangeIgnored(t *testing.T) {
	hist := base(28, func(int) float64 { return 0.10 })
	if v := anomaly.Detect(hist, 2.00, cfg); v.Anomalous { // 20× but only 1.90 excess
		t.Fatalf("tiny %+v", v)
	}
}

func TestFlatHistorySpike(t *testing.T) {
	hist := base(28, func(int) float64 { return 50 }) // MAD 0
	if v := anomaly.Detect(hist, 80, cfg); !v.Anomalous || v.Severity != "medium" {
		t.Fatalf("flat spike %+v", v)
	}
}

func TestNewSpendWithNoHistory(t *testing.T) {
	hist := base(28, func(int) float64 { return 0 })
	if v := anomaly.Detect(hist, 40, cfg); !v.Anomalous || v.Expected != 0 {
		t.Fatalf("new spend %+v", v)
	}
}

func TestNeedsHistory(t *testing.T) {
	if v := anomaly.Detect([]float64{1, 2, 3}, 100, cfg); v.Anomalous {
		t.Fatal("must not judge without 14 days of history")
	}
}

func TestSeverityScales(t *testing.T) {
	hist := base(28, func(int) float64 { return 100 })
	for actual, want := range map[float64]string{140: "low", 170: "medium", 260: "high", 600: "critical"} {
		if v := anomaly.Detect(hist, actual, cfg); v.Severity != want {
			t.Errorf("%v → %s, want %s", actual, v.Severity, want)
		}
	}
}
