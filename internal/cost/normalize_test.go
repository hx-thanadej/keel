package cost_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/cost"
)

func ratSum(t *testing.T, vals ...string) string {
	t.Helper()
	s := new(big.Rat)
	for _, v := range vals {
		r, ok := new(big.Rat).SetString(v)
		if !ok {
			t.Fatalf("bad decimal %q", v)
		}
		s.Add(s, r)
	}
	return s.FloatString(6)
}

func TestNormalizeTencent(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 9, d, 0, 0, 0, 0, time.UTC) }
	in := []cost.Line{
		{ServiceName: "Cloud Virtual Machine", ChargeCategory: "Usage", BilledCost: "4.80", ChargePeriodStart: day(1), ChargePeriodEnd: day(2), Vendor: map[string]string{"x_ComponentName": "CPU"}},
		{ServiceName: "Cloud Object Storage", ChargeCategory: "Usage", BilledCost: "0.40", ChargePeriodStart: day(1), ChargePeriodEnd: day(2), Vendor: map[string]string{}},
		{ServiceName: "Something New", ChargeCategory: "Usage", BilledCost: "1", ChargePeriodStart: day(1), ChargePeriodEnd: day(2), Vendor: map[string]string{}},
		{ServiceName: "TencentDB for MySQL", ChargeCategory: "Purchase", BilledCost: "30.00", ResourceID: "cdb-1", ChargePeriodStart: day(1), ChargePeriodEnd: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Vendor: map[string]string{}},
		{ServiceName: "Cloud Block Storage", ChargeCategory: "Purchase", BilledCost: "100.00", ResourceID: "disk-1", ChargePeriodStart: day(1), ChargePeriodEnd: time.Date(2027, 9, 1, 0, 0, 0, 0, time.UTC), Vendor: map[string]string{}},
	}
	out := cost.Normalize("tencent", in)

	if out[0].ServiceCategory != "Compute" || out[1].ServiceCategory != "Storage" || out[2].ServiceCategory != "Other" || out[3].ServiceCategory != "Databases" {
		t.Errorf("categories: %q %q %q %q", out[0].ServiceCategory, out[1].ServiceCategory, out[2].ServiceCategory, out[3].ServiceCategory)
	}
	if out[0].SkuID != "tencent:Cloud Virtual Machine/CPU" || out[0].EffectiveCost != "4.80" || out[0].EffectiveCostMethod != "billed" {
		t.Errorf("usage line: %+v", out[0])
	}
	if out[3].EffectiveCost != "0" || out[3].EffectiveCostMethod != "amortized" {
		t.Errorf("purchase line must carry 0 effective (spread below): %+v", out[3])
	}

	var monthly, yearly []string
	var monthlyBilled []string
	for _, l := range out[5:] {
		if l.ChargeCategory != "Usage" || l.EffectiveCostMethod != "amortization" || l.BilledCost != "0" {
			t.Fatalf("amortization row %+v", l)
		}
		switch l.ResourceID {
		case "cdb-1":
			monthly = append(monthly, l.EffectiveCost)
			monthlyBilled = append(monthlyBilled, l.BilledCost)
		case "disk-1":
			yearly = append(yearly, l.EffectiveCost)
		}
	}
	if len(monthly) != 30 || ratSum(t, monthly...) != "30.000000" || monthly[0] != "1.000000" {
		t.Errorf("monthly amortization: %d rows summing %s (first %s)", len(monthly), ratSum(t, monthly...), monthly[0])
	}
	if len(yearly) != 365 || ratSum(t, yearly...) != "100.000000" {
		t.Errorf("yearly amortization: %d rows summing %s, want 365 summing exactly 100", len(yearly), ratSum(t, yearly...))
	}
	if ratSum(t, monthlyBilled...) != "0.000000" {
		t.Error("amortization rows must not add billed cost")
	}
}

func TestNormalizeKeepsSourceEffectiveCost(t *testing.T) {
	out := cost.Normalize("aws", []cost.Line{{ChargeCategory: "Usage", BilledCost: "5", EffectiveCost: "3.5", Vendor: map[string]string{}}})
	if out[0].EffectiveCost != "3.5" || out[0].EffectiveCostMethod != "source" {
		t.Errorf("%+v", out[0])
	}
}

func TestFinality(t *testing.T) {
	sep := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	bkk := time.FixedZone("UTC+8", 8*3600)
	cases := []struct {
		provider string
		now      time.Time
		invoiced bool
		want     bool
	}{
		{"tencent", time.Date(2026, 10, 1, 19, 59, 0, 0, bkk), false, false},
		{"tencent", time.Date(2026, 10, 1, 20, 1, 0, 0, bkk), false, true},
		{"aws", time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), false, false},
		{"aws", time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), true, false},
		{"aws", time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC), true, true},
		{"azure", time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), false, false},
		{"azure", time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), false, true},
		{"alibaba", time.Date(2026, 10, 6, 13, 0, 0, 0, bkk), false, true},
		{"gcp", time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), false, false},
		{"gcp", time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC), false, true},
		{"unknown", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), false, false},
	}
	for _, c := range cases {
		if got := cost.PeriodFinal(c.provider, sep, c.now, c.invoiced); got != c.want {
			t.Errorf("%s at %s invoiced=%v: final=%v, want %v", c.provider, c.now, c.invoiced, got, c.want)
		}
	}
}
