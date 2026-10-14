package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/budgets"
	budgettypes "github.com/aws/aws-sdk-go-v2/service/budgets/types"
	coh "github.com/aws/aws-sdk-go-v2/service/costoptimizationhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/hx-thanadej/keel/internal/clientreads"
	"github.com/hx-thanadej/keel/internal/rightsize"
)

// ReadActions are the only actions a client-reads session may use. AWS
// authorizes DescribeBudgets with budgets:ViewBudget and lists the legacy
// aws-portal:ViewBilling for it too, GetFindings with securityhub:GetFindings
// and ListRecommendations with cost-optimization-hub:ListRecommendations.
var ReadActions = []string{"budgets:ViewBudget", "aws-portal:ViewBilling", "securityhub:GetFindings", "cost-optimization-hub:ListRecommendations"}

var awsRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)

// readsPolicy is the session policy on every client-reads session. AWS
// grants the intersection with the role's own policies, so through Keel
// even an over-broad role makes only ReadActions, on the payer's own budgets
// and its Security Hub in region. aws-portal and Cost Optimization Hub
// define no resource types, so they stay on "*".
func readsPolicy(partition, account, region string) (string, error) {
	if !awsRegion.MatchString(region) {
		return "", fmt.Errorf("security hub region %q is not an AWS region", region)
	}
	b, err := json.Marshal(struct {
		Version   string
		Statement []statement
	}{"2012-10-17", []statement{
		{Effect: "Allow", Action: "budgets:ViewBudget", Resource: "arn:" + partition + ":budgets::" + account + ":budget/*"},
		{Effect: "Allow", Action: "aws-portal:ViewBilling", Resource: "*"},
		{Effect: "Allow", Action: "securityhub:GetFindings", Resource: "arn:" + partition + ":securityhub:" + region + ":" + account + ":hub/default"},
		{Effect: "Allow", Action: "cost-optimization-hub:ListRecommendations", Resource: "*"},
	}})
	return string(b), err
}

// ReadsRole assumes a client's read-only role in its management account for
// Budgets, Security Hub (read in region) and Cost Optimization Hub reads,
// with the same checks and ExternalId as ReadOnlyRole but a session limited
// to readsPolicy. stsEndpoint overrides the STS endpoint, for tests.
func ReadsRole(base Identity, arn, account, externalID, region, stsEndpoint string) (*ClientRole, error) {
	m, err := clientRoleARN(arn, account, externalID)
	if err != nil {
		return nil, err
	}
	policy, err := readsPolicy(m[1], m[2], region)
	if err != nil {
		return nil, err
	}
	return assume(base, arn, externalID, policy, "us-east-1", stsEndpoint), nil
}

// ClientReads reads a client management account through a ReadsRole
// session. It implements clientreads.Reader and makes no write call.
type ClientReads struct {
	account string
	budgets *budgets.Client
	hub     *securityhub.Client
	coh     *COH
	now     func() time.Time
}

// NewClientReads reads account through role. Budgets and Cost Optimization
// Hub are served from us-east-1; Security Hub is read in region, where the
// client aggregates its findings. endpoint overrides every service endpoint,
// for tests.
func NewClientReads(role *ClientRole, account, region, endpoint string) *ClientReads {
	var be *string
	if endpoint != "" {
		be = &endpoint
	}
	return &ClientReads{
		account: account,
		budgets: budgets.New(budgets.Options{Region: "us-east-1", Credentials: role.creds, BaseEndpoint: be}),
		hub:     securityhub.New(securityhub.Options{Region: region, Credentials: role.creds, BaseEndpoint: be}),
		coh:     &COH{client: coh.New(coh.Options{Region: "us-east-1", Credentials: role.creds, BaseEndpoint: be})},
		now:     time.Now,
	}
}

// Budgets implements clientreads.Reader with DescribeBudgets.
func (c *ClientReads) Budgets(ctx context.Context) ([]clientreads.Budget, error) {
	var out []clientreads.Budget
	p := budgets.NewDescribeBudgetsPaginator(c.budgets, &budgets.DescribeBudgetsInput{AccountId: &c.account})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeBudgets: %w", err)
		}
		for _, b := range page.Budgets {
			out = append(out, budgetFromAWS(b, c.now()))
		}
	}
	return out, nil
}

// budgetFromAWS maps one budget. A budget with planned limits has no
// BudgetLimit; its limit is the planned one for the latest period started
// by now.
func budgetFromAWS(b budgettypes.Budget, now time.Time) clientreads.Budget {
	out := clientreads.Budget{Name: sdk.ToString(b.BudgetName)}
	limit := b.BudgetLimit
	if limit == nil {
		var latest int64 = -1
		for k, v := range b.PlannedBudgetLimits {
			sec, err := strconv.ParseInt(k, 10, 64)
			if err == nil && sec <= now.Unix() && sec > latest {
				latest, limit = sec, &v
			}
		}
	}
	if limit != nil {
		out.Limit, out.Unit = sdk.ToString(limit.Amount), sdk.ToString(limit.Unit)
	}
	if s := b.CalculatedSpend; s != nil {
		if s.ActualSpend != nil {
			out.Actual = sdk.ToString(s.ActualSpend.Amount)
		}
		if s.ForecastedSpend != nil {
			out.Forecast = sdk.ToString(s.ForecastedSpend.Amount)
		}
	}
	return out
}

// activeFindings selects the findings a Team should act on: active, not yet
// suppressed or resolved by the client, and not informational.
var activeFindings = &shtypes.AwsSecurityFindingFilters{
	RecordState:    []shtypes.StringFilter{{Value: sdk.String("ACTIVE"), Comparison: shtypes.StringFilterComparisonEquals}},
	WorkflowStatus: []shtypes.StringFilter{{Value: sdk.String("NEW"), Comparison: shtypes.StringFilterComparisonEquals}, {Value: sdk.String("NOTIFIED"), Comparison: shtypes.StringFilterComparisonEquals}},
	SeverityLabel: []shtypes.StringFilter{
		{Value: sdk.String("CRITICAL"), Comparison: shtypes.StringFilterComparisonEquals}, {Value: sdk.String("HIGH"), Comparison: shtypes.StringFilterComparisonEquals},
		{Value: sdk.String("MEDIUM"), Comparison: shtypes.StringFilterComparisonEquals}, {Value: sdk.String("LOW"), Comparison: shtypes.StringFilterComparisonEquals},
	},
}

// Findings implements clientreads.Reader with Security Hub GetFindings.
// AWS Config rule evaluations reach it through Security Hub's Config
// integration, as findings whose product is Config.
func (c *ClientReads) Findings(ctx context.Context) ([]clientreads.Finding, error) {
	var out []clientreads.Finding
	p := securityhub.NewGetFindingsPaginator(c.hub, &securityhub.GetFindingsInput{Filters: activeFindings, MaxResults: sdk.Int32(100)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("GetFindings: %w", err)
		}
		for _, f := range page.Findings {
			cf := clientreads.Finding{ID: sdk.ToString(f.Id), Account: sdk.ToString(f.AwsAccountId), Title: sdk.ToString(f.Title), Source: sdk.ToString(f.ProductName)}
			if f.Severity != nil {
				cf.Severity = strings.ToLower(string(f.Severity.Label))
			}
			if len(f.Resources) > 0 {
				cf.Resource = sdk.ToString(f.Resources[0].Id)
			}
			out = append(out, cf)
		}
	}
	return out, nil
}

// Recommendations implements clientreads.Reader with Cost Optimization Hub,
// which carries Compute Optimizer's savings recommendations only: its
// under-provisioned findings never arrive. The listing is complete or an
// error (COH.List), so Sync.Listing may be COHSource.
func (c *ClientReads) Recommendations(ctx context.Context) ([]rightsize.Recommendation, error) {
	return c.coh.List(ctx)
}
