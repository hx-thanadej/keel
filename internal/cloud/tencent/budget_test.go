package tencent_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"

	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

func TestTencentRequestShape(t *testing.T) {
	spec := budget.NativeSpec{Name: "tat-crm 2026", Year: 2026, Accounts: []string{"200048351622"}, Currency: "USD", Basis: "effective",
		Thresholds: []budget.Threshold{{Pct: 80, Basis: "actual"}, {Pct: 100, Basis: "forecast"}}}
	for i := range spec.Monthly {
		spec.Monthly[i] = "100.00"
	}
	req := tencent.CreateBudgetRequest(spec)
	if *req.CycleType != "MONTH" || *req.PlanType != "CYCLE" || *req.PeriodBegin != "2026-01" || *req.PeriodEnd != "2026-12" ||
		*req.BillType != "CONSUMPTION" || *req.FeeType != "REAL_COST" || *req.DimensionsRange.OwnerUins[0] != "200048351622" ||
		!strings.Contains(*req.BudgetQuota, `{"dateDesc":"2026-09","quota":"100.00"}`) ||
		*req.WarnJson[0].WarnType != "ACTUAL" || *req.WarnJson[1].WarnType != "FORECAST" || *req.WarnJson[0].CalType != "PERCENTAGE" || *req.WarnJson[0].ThresholdValue != "80" {
		t.Fatalf("request %+v", req)
	}
	billed := spec
	billed.Basis = "billed"
	if *tencent.CreateBudgetRequest(billed).BillType != "BILL" {
		t.Error("billed basis must mirror to BILL")
	}
}

// What Keel writes must read back identically, or every sync would report drift.
func TestSpecRoundTrip(t *testing.T) {
	spec := budget.NativeSpec{Year: 2026, Accounts: []string{"200046202634", "200048351622"}, Currency: "USD", Basis: "billed",
		Thresholds: []budget.Threshold{{Pct: 80, Basis: "actual"}, {Pct: 110, Basis: "forecast"}}}
	for i := range spec.Monthly {
		spec.Monthly[i] = "857.14"
	}
	req := tencent.CreateBudgetRequest(spec)
	var plan []struct{ DateDesc, Quota string }
	if err := json.Unmarshal([]byte(*req.BudgetQuota), &plan); err != nil {
		t.Fatal(err)
	}
	ext := &billing.BudgetExtend{PeriodBegin: req.PeriodBegin, BillType: req.BillType, DimensionsRange: req.DimensionsRange, WarnJson: req.WarnJson}
	for _, p := range plan {
		d, q := p.DateDesc, p.Quota
		ext.BudgetQuotaJson = append(ext.BudgetQuotaJson, &billing.BudgetPlan{DateDesc: &d, Quota: &q})
	}
	got := tencent.SpecFromBudget(ext)
	got.Name = spec.Name
	if fmt.Sprint(got) != fmt.Sprint(spec) {
		t.Fatalf("round trip\n got %+v\nwant %+v", got, spec)
	}
}
