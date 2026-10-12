package aws

import (
	"strconv"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	budgettypes "github.com/aws/aws-sdk-go-v2/service/budgets/types"

	"github.com/hx-thanadej/keel/internal/clientreads"
)

// TestBudgetFromAWSUsesThePlannedLimitInForce: a budget with planned
// limits has no BudgetLimit, so its limit is the one for the latest period
// already started, never a future one.
func TestBudgetFromAWSUsesThePlannedLimitInForce(t *testing.T) {
	month := func(m time.Month) string {
		return strconv.FormatInt(time.Date(2026, m, 1, 0, 0, 0, 0, time.UTC).Unix(), 10)
	}
	b := budgettypes.Budget{BudgetName: sdk.String("planned"), PlannedBudgetLimits: map[string]budgettypes.Spend{
		month(8):  {Amount: sdk.String("800"), Unit: sdk.String("USD")},
		month(9):  {Amount: sdk.String("900"), Unit: sdk.String("USD")},
		month(10): {Amount: sdk.String("1000"), Unit: sdk.String("USD")},
	}, CalculatedSpend: &budgettypes.CalculatedSpend{ActualSpend: &budgettypes.Spend{Amount: sdk.String("950"), Unit: sdk.String("USD")}}}
	got := budgetFromAWS(b, time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	if want := (clientreads.Budget{Name: "planned", Limit: "900", Actual: "950", Unit: "USD"}); got != want {
		t.Errorf("budget %+v, want %+v", got, want)
	}
}
