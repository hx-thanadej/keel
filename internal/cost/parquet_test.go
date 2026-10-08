package cost

import (
	"bytes"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"
)

// A Parquet export shaped like Azure's and Google's: typed decimals and
// timestamps, Tags as a MAP, optional columns left null.
type pqRow struct {
	BilledCost         int64             `parquet:"BilledCost,decimal(6:18)"`
	EffectiveCost      int32             `parquet:"EffectiveCost,decimal(2:9)"`
	ListCost           float64           `parquet:"ListCost"`
	BillingCurrency    string            `parquet:"BillingCurrency"`
	BillingPeriodStart time.Time         `parquet:"BillingPeriodStart,timestamp(millisecond)"`
	ChargePeriodStart  time.Time         `parquet:"ChargePeriodStart,timestamp(microsecond)"`
	ChargePeriodEnd    time.Time         `parquet:"ChargePeriodEnd,timestamp(microsecond)"`
	ChargeCategory     string            `parquet:"ChargeCategory"`
	SubAccountId       string            `parquet:"SubAccountId"`
	ResourceId         *string           `parquet:"ResourceId,optional"`
	Tags               map[string]string `parquet:"Tags"`
	XSkuMeterCategory  string            `parquet:"x_SkuMeterCategory"`
}

func TestParquetFOCUS(t *testing.T) {
	day := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	vm := "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
	var buf bytes.Buffer
	w := parquet.NewGenericWriter[pqRow](&buf)
	if _, err := w.Write([]pqRow{
		{BilledCost: 12345678, EffectiveCost: -150, ListCost: 13.5, BillingCurrency: "USD", BillingPeriodStart: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			ChargePeriodStart: day, ChargePeriodEnd: day.AddDate(0, 0, 1), ChargeCategory: "Usage", SubAccountId: "s1", ResourceId: &vm,
			Tags: map[string]string{"project": "tat-crm", "env": "prod"}, XSkuMeterCategory: "Virtual Machines"},
		{BilledCost: 0, BillingCurrency: "USD", BillingPeriodStart: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			ChargePeriodStart: day, ChargePeriodEnd: day.AddDate(0, 0, 1), ChargeCategory: "Tax", SubAccountId: "s1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	lines, err := ParseFOCUS(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	l := lines[0]
	if l.BilledCost != "12.345678" || l.EffectiveCost != "-1.50" || l.ListCost != "13.5" {
		t.Fatalf("costs %q %q %q", l.BilledCost, l.EffectiveCost, l.ListCost)
	}
	if !l.ChargePeriodStart.Equal(day) || !l.BillingPeriodStart.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("times %v %v", l.ChargePeriodStart, l.BillingPeriodStart)
	}
	if l.Tags["project"] != "tat-crm" || l.Tags["env"] != "prod" || len(l.Tags) != 2 {
		t.Fatalf("tags %v", l.Tags)
	}
	if l.ResourceID != vm || l.Vendor["x_SkuMeterCategory"] != "Virtual Machines" {
		t.Fatalf("resource %q vendor %v", l.ResourceID, l.Vendor)
	}
	if lines[1].ResourceID != "" || len(lines[1].Tags) != 0 || lines[1].BilledCost != "0.000000" {
		t.Fatalf("second line %+v", lines[1])
	}
}

func TestParquetMissingRequiredColumn(t *testing.T) {
	type bad struct {
		BilledCost string `parquet:"BilledCost"`
	}
	var buf bytes.Buffer
	w := parquet.NewGenericWriter[bad](&buf)
	_, _ = w.Write([]bad{{"1"}})
	_ = w.Close()
	if _, err := ParseFOCUS(buf.Bytes()); err == nil {
		t.Fatal("expected a missing-column error")
	}
}

func TestDecimalBytesTwosComplement(t *testing.T) {
	v := parquet.ValueOf([]byte{0xff, 0x85}) // -123
	got, err := decimalText(v, 2)
	if err != nil || got != "-1.23" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestGoogleStyleTags(t *testing.T) {
	m := map[string]string{}
	if err := parseTags(`[{"key":"project","value":"tat-crm"},{"key":"team","value":"crm"}]`, m); err != nil || m["project"] != "tat-crm" || m["team"] != "crm" {
		t.Fatalf("%v %v", m, err)
	}
	if err := parseTags(`"nope"`, map[string]string{}); err == nil {
		t.Fatal("expected an error")
	}
}
