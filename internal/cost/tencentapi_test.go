package cost_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"

	"github.com/hx-thanadej/keel/internal/cost"
)

func TestTencentBillLinesMapping(t *testing.T) {
	// A prepaid purchase under a contract price (Cost "-"), two components,
	// no currency in PriceUnit; shapes from the BillDetail data structure.
	raw := `[{"PayerUin": "200045645249", "OwnerUin": "200048351622", "BusinessCodeName": "TencentDB for MySQL",
		"ActionType": "prepay_purchase", "FeeBeginTime": "2026-09-01 00:00:00", "FeeEndTime": "2026-09-30 23:59:59", "ResourceId": "cdb-1",
		"ComponentSet": [{"ComponentCodeName": "Compute", "Cost": "-", "RealCost": "20.00", "PriceUnit": "-"},
		                 {"ComponentCodeName": "Storage", "Cost": "12.00", "RealCost": "10.00", "PriceUnit": "USD/GB/month"}]}]`
	var details []*billing.BillDetail
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		t.Fatal(err)
	}
	m, err := cost.TencentBillLines(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), details, "")
	lines := m.Lines
	if err != nil || len(lines) != 2 {
		t.Fatalf("lines %+v err %v", lines, err)
	}
	l := lines[0]
	if l.ChargeCategory != "Purchase" || l.ChargeFrequency != "One-Time" || l.ListCost != "" || l.BilledCost != "20.00" ||
		l.BillingCurrency != "USD" || l.ServiceName != "TencentDB for MySQL" || l.Vendor["x_ComponentName"] != "Compute" ||
		!l.ChargePeriodStart.Equal(time.Date(2026, 8, 31, 16, 0, 0, 0, time.UTC)) ||
		!l.ChargePeriodEnd.Equal(time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)) ||
		!l.BillingPeriodStart.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("line %+v", l)
	}
	if lines[1].ListCost != "12.00" || lines[1].BilledCost != "10.00" {
		t.Errorf("storage line %+v", lines[1])
	}

	details[0].ComponentSet[1].RealCost = new(string)
	if _, err := cost.TencentBillLines(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), details, "USD"); err == nil {
		t.Error("a component without RealCost loaded; want an error so the pull fails")
	}
}

func TestTencentBillLinesNeverGuessCurrency(t *testing.T) {
	month := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	month1 := func(units ...string) []*billing.BillDetail {
		d := &billing.BillDetail{FeeBeginTime: new("2026-09-01 00:00:00"), FeeEndTime: new("2026-09-01 23:59:59"), ActionType: new("postpay_deduct_h")}
		for _, u := range units {
			d.ComponentSet = append(d.ComponentSet, &billing.BillDetailComponent{RealCost: new("1.00"), PriceUnit: new(u)})
		}
		return []*billing.BillDetail{d}
	}
	for _, tc := range []struct {
		name, explicit string
		units          []string
		want           string // "" wants ErrBillCurrency
	}{
		{"zh-CN yuan unit", "", []string{"元/核/小时"}, ""},
		{"contract prices only", "", []string{"-", "-"}, ""},
		{"no PriceUnit", "", []string{""}, ""},
		{"mixed USD and CNY", "", []string{"USD/core/hour", "CNY/core/hour"}, ""},
		{"lower case", "", []string{"usd/core/hour"}, ""},
		{"code Keel does not support", "", []string{"JPY/core/hour"}, ""},
		{"one currency", "", []string{"CNY/core/hour", "-"}, "CNY"},
		{"explicit with contract prices", "USD", []string{"-"}, "USD"},
		{"explicit agrees", "USD", []string{"USD/core/hour", "-"}, "USD"},
		{"explicit contradicted", "USD", []string{"CNY/core/hour"}, ""},
		{"explicit with yuan unit", "CNY", []string{"元/核/小时"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := cost.TencentBillLines(month, month1(tc.units...), tc.explicit)
			lines := m.Lines
			if tc.want == "" {
				if !errors.Is(err, cost.ErrBillCurrency) {
					t.Fatalf("units %q explicit %q: err %v lines %d, want ErrBillCurrency", tc.units, tc.explicit, err, len(lines))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range lines {
				if l.BillingCurrency != tc.want {
					t.Errorf("currency %q, want %q", l.BillingCurrency, tc.want)
				}
			}
		})
	}
}

func TestParseCurrency(t *testing.T) {
	for in, ok := range map[string]bool{"USD": true, "CNY": true, "THB": true, "EUR": true, "元": false, "usd": false, "US": false, "USDX": false, "JPY": false, "-": false} {
		if _, err := cost.ParseCurrency(in); (err == nil) != ok {
			t.Errorf("ParseCurrency(%q) err %v, want ok=%v", in, err, ok)
		}
	}
}
