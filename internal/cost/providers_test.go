package cost_test

import (
	"os"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/cost"
)

func parse(t *testing.T, f string) []cost.Line {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + f)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := cost.ParseFOCUS(raw)
	if err != nil {
		t.Fatalf("%s: %v", f, err)
	}
	return lines
}

func TestAzurePublishedSample(t *testing.T) {
	lines := parse(t, "azure-focus-1.0-ea-sample.csv")
	if len(lines) != 6 {
		t.Fatalf("%d lines", len(lines))
	}
	l := lines[0]
	if l.BilledCost != "0.0000576" || l.ServiceName != "Azure DNS" || l.ChargeCategory != "Usage" ||
		!l.ChargePeriodStart.Equal(time.Date(2024, 6, 12, 0, 0, 0, 0, time.UTC)) || l.Tags["CostCenter"] != "1234" || l.Vendor["x_AccountId"] == "" {
		t.Fatalf("%+v", l)
	}
	n := cost.Normalize("azure", lines[:1])
	if n[0].SubAccountID != "ed570627-0265-4620-bb42-bae06bcfa914" {
		t.Fatalf("subscription %q", n[0].SubAccountID)
	}
}

func TestAlibabaStandardBillMapsToFOCUS(t *testing.T) {
	lines := parse(t, "alibaba-bill-2026-09.csv")
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	l := lines[0]
	if l.SubAccountID != "5098765432109876" || l.BilledCost != "9.60" || l.ListCost != "12.00" || l.ResourceID != "i-t4n1" ||
		l.ServiceName != "Elastic Compute Service" || l.ChargeCategory != "Usage" || l.Tags["project"] != "tat-crm" || l.Tags["env"] != "prod" ||
		l.BillingPeriodStart.Format("2006-01-02") != "2026-09-01" || l.ChargePeriodStart.Format("2006-01-02") != "2026-09-06" ||
		l.ChargePeriodEnd.Format("2006-01-02") != "2026-09-07" || l.Vendor["x_DiscountAmount"] != "2.40" {
		t.Fatalf("%+v", l)
	}
	if lines[1].ChargeCategory != "Credit" || lines[1].BilledCost != "-1.25" || len(lines[1].Tags) != 0 {
		t.Fatalf("%+v", lines[1])
	}
}

func TestAlibabaFOCUSPreviewKeepsXColumns(t *testing.T) {
	l := parse(t, "alibaba-focus-preview-2026-09.csv")[0]
	if l.Vendor["X_CommodityCode"] != "ecs" || l.Tags["project"] != "tat-crm" || l.EffectiveCost != "3.50" {
		t.Fatalf("%+v", l)
	}
}

func TestGoogleCSVExport(t *testing.T) {
	l := parse(t, "gcp-focus-2026-09.csv")[0]
	if !l.ChargePeriodStart.Equal(time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)) || l.BillingPeriodStart.Format("2006-01") != "2026-09" ||
		l.SubAccountID != "tat-crm-prod" || l.EffectiveCost != "1.100000" || l.Vendor["x_Tags"] == "" || l.Tags["env"] != "prod" {
		t.Fatalf("%+v", l)
	}
}

func TestProviderFinality(t *testing.T) {
	sep := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		provider string
		now      time.Time
		want     bool
	}{
		{"azure", time.Date(2026, 10, 5, 23, 0, 0, 0, time.UTC), false},
		{"azure", time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), true},
		{"gcp", time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), false},
		{"gcp", time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC), true},
		{"alibaba", time.Date(2026, 10, 6, 3, 59, 0, 0, time.UTC), false}, // 11:59 UTC+8
		{"alibaba", time.Date(2026, 10, 6, 4, 0, 0, 0, time.UTC), true},
	} {
		if got := cost.PeriodFinal(c.provider, sep, c.now, false); got != c.want {
			t.Errorf("%s at %v: %v", c.provider, c.now, got)
		}
	}
}
