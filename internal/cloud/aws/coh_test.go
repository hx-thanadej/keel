package aws_test

import (
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	cohtypes "github.com/aws/aws-sdk-go-v2/service/costoptimizationhub/types"

	"github.com/hx-thanadej/keel/internal/cloud/aws"
)

func TestFromCOH(t *testing.T) {
	r := aws.FromCOH(cohtypes.Recommendation{
		AccountId: sdk.String("222222222222"), ActionType: sdk.String("Rightsize"), CurrencyCode: sdk.String("USD"),
		CurrentResourceType: sdk.String("Ec2Instance"), CurrentResourceSummary: sdk.String("m5.2xlarge"), RecommendedResourceSummary: sdk.String("m5.large"),
		EstimatedMonthlySavings: sdk.Float64(123.456), ImplementationEffort: sdk.String("Medium"), RecommendationId: sdk.String("rec-1"),
		RecommendationLookbackPeriodInDays: sdk.Int32(14), Region: sdk.String("ap-southeast-1"), ResourceId: sdk.String("i-0abc"),
		RestartNeeded: sdk.Bool(true), RollbackPossible: sdk.Bool(true),
	})
	if r.Provider != "aws" || r.Action != "resize" || r.ResourceID != "i-0abc" || r.MonthlySavings != "123.46" || r.Currency != "USD" ||
		r.Recommended["summary"] != "m5.large" || r.Risk["restart"] != true || r.Evidence["lookback_days"] != int32(14) || r.ResourceType != "ec2instance" {
		t.Fatalf("mapped %+v", r)
	}
}
