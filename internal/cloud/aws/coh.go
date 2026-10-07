package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	coh "github.com/aws/aws-sdk-go-v2/service/costoptimizationhub"
	cohtypes "github.com/aws/aws-sdk-go-v2/service/costoptimizationhub/types"

	"github.com/hx-thanadej/keel/internal/rightsize"
)

// COH reads AWS Cost Optimization Hub, which already deduplicates
// recommendations across Compute Optimizer and Savings Plans and prices
// savings after discounts (#71).
type COH struct{ client *coh.Client }

// NewCOH uses the default credential chain (web identity / instance role).
// Cost Optimization Hub is served from us-east-1.
func NewCOH(ctx context.Context) (*COH, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil, err
	}
	return &COH{client: coh.NewFromConfig(cfg)}, nil
}

// List returns every recommendation, mapped to Keel's record.
func (c *COH) List(ctx context.Context) ([]rightsize.Recommendation, error) {
	var out []rightsize.Recommendation
	p := coh.NewListRecommendationsPaginator(c.client, &coh.ListRecommendationsInput{IncludeAllRecommendations: false})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListRecommendations: %w", err)
		}
		for _, r := range page.Items {
			out = append(out, FromCOH(r))
		}
	}
	return out, nil
}

var actions = map[string]string{
	"Rightsize": "resize", "Stop": "stop", "Delete": "delete", "Upgrade": "change_family",
	"MigrateToGraviton": "change_family", "PurchaseSavingsPlans": "purchase_commitment", "PurchaseReservedInstances": "purchase_commitment",
	"ScaleIn": "resize",
}

// FromCOH maps one Cost Optimization Hub recommendation.
func FromCOH(r cohtypes.Recommendation) rightsize.Recommendation {
	s := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	action := actions[s(r.ActionType)]
	if action == "" {
		action = strings.ToLower(s(r.ActionType))
	}
	resource := s(r.ResourceId)
	if resource == "" {
		resource = s(r.ResourceArn)
	}
	rec := rightsize.Recommendation{
		Source: "native:aws_coh", Provider: "aws", AccountID: s(r.AccountId), Region: s(r.Region), ResourceID: resource,
		ResourceType: strings.ToLower(s(r.CurrentResourceType)), Action: action,
		Current:     map[string]any{"summary": s(r.CurrentResourceSummary), "type": s(r.CurrentResourceType)},
		Recommended: map[string]any{"summary": s(r.RecommendedResourceSummary), "type": s(r.RecommendedResourceType)},
		Evidence:    map[string]any{"aws_recommendation_id": s(r.RecommendationId), "method": "AWS Cost Optimization Hub"},
		Currency:    s(r.CurrencyCode), SavingsBasis: "effective", Confidence: 0.8,
		Risk: map[string]any{"migration_effort": strings.ToLower(s(r.ImplementationEffort))},
	}
	if rec.Currency == "" {
		rec.Currency = "USD"
	}
	if r.EstimatedMonthlySavings != nil {
		rec.MonthlySavings = fmt.Sprintf("%.2f", *r.EstimatedMonthlySavings)
	}
	if r.RecommendationLookbackPeriodInDays != nil {
		rec.Evidence["lookback_days"] = *r.RecommendationLookbackPeriodInDays
	}
	if r.RestartNeeded != nil {
		rec.Risk["restart"] = *r.RestartNeeded
	}
	if r.RollbackPossible != nil {
		rec.Risk["reversible"] = *r.RollbackPossible
	}
	return rec
}
