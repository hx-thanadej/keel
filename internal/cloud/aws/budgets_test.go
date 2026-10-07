package aws_test

import (
	"fmt"
	"testing"

	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/cloud/aws"
)

func TestBudgetRoundTrip(t *testing.T) {
	spec := budget.NativeSpec{Name: "keel-x-2026", Year: 2026, Accounts: []string{"222222222222", "333333333333"}, Currency: "USD", Basis: "effective"}
	for i := range spec.Monthly {
		spec.Monthly[i] = fmt.Sprintf("%d.00", 100+i)
	}
	b := aws.BudgetFor("keel-x-2026", spec)
	if b.Metrics[0] != "AmortizedCost" || len(b.PlannedBudgetLimits) != 12 || *b.PlannedBudgetLimits["1788220800"].Amount != "108.00" { // 2026-09-01 UTC
		t.Fatalf("budget %+v", b)
	}
	got := aws.SpecFromBudget(b)
	if fmt.Sprint(got) != fmt.Sprint(spec) {
		t.Fatalf("round trip\n got %+v\nwant %+v", got, spec)
	}
	spec.Basis = "billed"
	if aws.SpecFromBudget(aws.BudgetFor("n", spec)).Basis != "billed" {
		t.Error("billed basis lost")
	}
}
