package cost_test

import (
	"os"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/cost"
)

func TestParseFOCUSAllEncodings(t *testing.T) {
	for _, f := range []string{"tencent-focus-2026-09.csv", "tencent-focus-2026-09.csv.gz", "tencent-focus-2026-09.zip"} {
		raw, err := os.ReadFile("testdata/" + f)
		if err != nil {
			t.Fatal(err)
		}
		lines, err := cost.ParseFOCUS(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(lines) != 9 {
			t.Fatalf("%s: %d lines, want 9", f, len(lines))
		}
		l := lines[1]
		if l.SubAccountID != "200048351622" || l.BilledCost != "4.80" || l.ListCost != "6.00" || l.BillingCurrency != "USD" ||
			l.ServiceName != "Cloud Virtual Machine" || l.ResourceID != "ins-prod1" || l.Tags["env"] != "prod" ||
			l.ChargePeriodStart.Format("2006-01-02") != "2026-09-01" || l.BillingPeriodStart.Format("2006-01") != "2026-09" ||
			l.Vendor["x_ComponentName"] != "CPU" || l.EffectiveCost != "" {
			t.Errorf("%s: parsed %+v", f, l)
		}
	}
}

func TestParseFOCUSRejectsMissingRequiredColumns(t *testing.T) {
	if _, err := cost.ParseFOCUS([]byte("BilledCost,ChargePeriodStart\n1,2026-09-01T00:00:00Z\n")); err == nil {
		t.Fatal("want error for missing columns")
	}
	if _, err := cost.ParseFOCUS([]byte("")); err == nil {
		t.Fatal("want error for empty file")
	}
}

func TestParseFOCUSRejectsBadNumbers(t *testing.T) {
	raw, _ := os.ReadFile("testdata/tencent-focus-2026-09.csv")
	bad := strings.Replace(string(raw), ",4.80,", ",4.8O,", 1) // letter O, not zero
	if _, err := cost.ParseFOCUS([]byte(bad)); err == nil || !strings.Contains(err.Error(), "BilledCost") {
		t.Fatalf("err = %v, want BilledCost decimal error", err)
	}
	for _, v := range []string{"abc", "1e5x", ""} {
		if cost.ValidDecimal(v) {
			t.Errorf("ValidDecimal(%q) = true", v)
		}
	}
	for _, v := range []string{"0", "-1.25", "123456.000001"} {
		if !cost.ValidDecimal(v) {
			t.Errorf("ValidDecimal(%q) = false", v)
		}
	}
}
