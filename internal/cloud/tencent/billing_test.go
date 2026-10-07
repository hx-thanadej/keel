package tencent_test

import (
	"encoding/json"
	"testing"

	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

func TestSumRealTotalCost(t *testing.T) {
	// Shape from the DescribeBillSummaryByPayMode response model.
	raw := `{"Ready": 1, "SummaryOverview": [
		{"PayMode": "prePay", "PayModeName": "Monthly Subscription", "RealTotalCost": "30.00", "TotalCost": "30.00"},
		{"PayMode": "postPay", "PayModeName": "Pay-As-You-Go", "RealTotalCost": "16.80", "TotalCost": "18.20"}]}`
	var r billing.DescribeBillSummaryByPayModeResponseParams
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	total, ready, err := tencent.SumRealTotalCost(&r)
	if err != nil || total != "46.800000" || !ready {
		t.Fatalf("got %s %v %v", total, ready, err)
	}
}
