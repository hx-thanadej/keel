package cost_test

import (
	"encoding/json"
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
		                 {"ComponentCodeName": "Storage", "Cost": "12.00", "RealCost": "10.00"}]}]`
	var details []*billing.BillDetail
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		t.Fatal(err)
	}
	lines, err := cost.TencentBillLines(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), details, "USD")
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
