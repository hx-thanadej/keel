package tencent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	advisor "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/advisor/v20200721"
	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
	monitor "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/monitor/v20180724"

	"github.com/hx-thanadej/keel/internal/clientreads"
)

// ClientReads reads a client payer through a ReadsRole session. Its
// methods make only the read calls ReadActions allows.
type ClientReads struct {
	payer   string
	billing *billing.Client
	advisor *advisor.Client
	monitor *monitor.Client
	cvm     *cvm.Client
}

// clientProfile points a client at endpoint (scheme://host) when set, for
// tests.
func clientProfile(endpoint string) *profile.ClientProfile {
	cpf := profile.NewClientProfile()
	if scheme, host, ok := strings.Cut(endpoint, "://"); ok {
		cpf.HttpProfile.Scheme, cpf.HttpProfile.Endpoint = scheme, host
	}
	return cpf
}

// NewClientReads reads payer through role in region. endpoint overrides
// every service endpoint (scheme://host), for tests.
func NewClientReads(role common.Provider, payer, region, endpoint string) (*ClientReads, error) {
	cred, err := role.GetCredential()
	if err != nil {
		return nil, err
	}
	c := &ClientReads{payer: payer}
	if c.billing, err = billing.NewClient(cred, region, clientProfile(endpoint)); err != nil {
		return nil, err
	}
	if c.advisor, err = advisor.NewClient(cred, region, clientProfile(endpoint)); err != nil {
		return nil, err
	}
	if c.monitor, err = monitor.NewClient(cred, region, clientProfile(endpoint)); err != nil {
		return nil, err
	}
	if c.cvm, err = cvm.NewClient(cred, region, clientProfile(endpoint)); err != nil {
		return nil, err
	}
	return c, nil
}

// MonitorAPI is the one Cloud Monitor call the client reads make.
type MonitorAPI interface {
	GetMonitorDataWithContext(context.Context, *monitor.GetMonitorDataRequest) (*monitor.GetMonitorDataResponse, error)
}

// Monitor reads the payer's Cloud Monitor data through the session.
func (c *ClientReads) Monitor() MonitorAPI { return c.monitor }

// Inventory reads the payer account's current CVM instance types with
// DescribeInstances.
func (c *ClientReads) Inventory() Inventory { return Inventory{API: c.cvm} }

// Budgets implements clientreads.Reader with DescribeBudget, active
// budgets only.
func (c *ClientReads) Budgets(ctx context.Context) ([]clientreads.Budget, error) {
	var out []clientreads.Budget
	size, status := int64(20), "ACTIVE"
	for page := int64(1); ; page++ {
		req := billing.NewDescribeBudgetRequest()
		req.PageNo, req.PageSize, req.BudgetStatus = &page, &size, &status
		res, err := c.billing.DescribeBudgetWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("DescribeBudget: %w", err)
		}
		if res.Response == nil || res.Response.Data == nil {
			return out, nil
		}
		for _, b := range res.Response.Data.Records {
			if b != nil {
				out = append(out, BudgetFromTencent(b))
			}
		}
		if int64(len(res.Response.Data.Records)) < size {
			return out, nil
		}
	}
}

// BudgetFromTencent maps one budget. A fixed budget's limit is BudgetQuota;
// a planned (CYCLE) budget's is the quota for the period holding
// CurDateDesc. Tencent bills international accounts in USD and reports no
// currency on a budget.
func BudgetFromTencent(b *billing.BudgetExtend) clientreads.Budget {
	out := clientreads.Budget{Name: str(b.BudgetName), Actual: str(b.RealCost), Forecast: str(b.ForecastCost), Unit: "USD"}
	if str(b.PlanType) != "CYCLE" {
		out.Limit = str(b.BudgetQuota)
		return out
	}
	now := str(b.CurDateDesc)
	for _, q := range b.BudgetQuotaJson {
		if q != nil && q.DateDesc != nil && *q.DateDesc != "" && strings.HasPrefix(now, *q.DateDesc) {
			out.Limit = str(q.Quota)
		}
	}
	return out
}

// advisorSeverity maps a Smart Advisor risk level: 2 is medium risk, 3 is
// high risk.
var advisorSeverity = map[int]string{2: "medium", 3: "high"}

// Findings implements clientreads.Reader with Smart Advisor: every
// assessment item (DescribeStrategies) and its risky instances
// (DescribeTaskStrategyRisks). Smart Advisor assesses the account that
// calls it, so every finding is on the payer.
func (c *ClientReads) Findings(ctx context.Context) ([]clientreads.Finding, error) {
	res, err := c.advisor.DescribeStrategiesWithContext(ctx, advisor.NewDescribeStrategiesRequest())
	if err != nil {
		return nil, fmt.Errorf("DescribeStrategies: %w", err)
	}
	if res.Response == nil {
		return nil, nil
	}
	var out []clientreads.Finding
	for _, s := range res.Response.Strategies {
		if s == nil || s.StrategyId == nil {
			continue
		}
		fs, err := c.strategyRisks(ctx, s)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

func (c *ClientReads) strategyRisks(ctx context.Context, s *advisor.Strategies) ([]clientreads.Finding, error) {
	worst := 0
	for _, cond := range s.Conditions {
		if cond != nil && cond.Level != nil {
			worst = max(worst, int(*cond.Level))
		}
	}
	var out []clientreads.Finding
	limit := uint64(200)
	for offset := uint64(0); ; offset += limit {
		req := advisor.NewDescribeTaskStrategyRisksRequest()
		req.StrategyId, req.Limit, req.Offset = s.StrategyId, &limit, &offset
		res, err := c.advisor.DescribeTaskStrategyRisksWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("DescribeTaskStrategyRisks %d: %w", *s.StrategyId, err)
		}
		if res.Response == nil || res.Response.Risks == nil || *res.Response.Risks == "" {
			return out, nil
		}
		var risks []map[string]any
		if err := json.Unmarshal([]byte(*res.Response.Risks), &risks); err != nil {
			return nil, fmt.Errorf("DescribeTaskStrategyRisks %d: risks: %w", *s.StrategyId, err)
		}
		key := "InstanceId"
		if d := res.Response.RiskFieldsDesc; len(d) > 0 && d[0] != nil && d[0].Field != nil {
			key = *d[0].Field
		}
		for _, r := range risks {
			resource, _ := r[key].(string)
			level := worst
			if l, err := strconv.Atoi(fmt.Sprint(r["Level"])); err == nil {
				level = l
			}
			out = append(out, clientreads.Finding{ID: fmt.Sprintf("%d/%s", *s.StrategyId, resource), Account: c.payer, Severity: advisorSeverity[level],
				Title: str(s.Name), Source: "Smart Advisor " + str(s.GroupName) + " " + str(s.ProductDesc), Resource: resource})
		}
		if uint64(len(risks)) < limit {
			return out, nil
		}
	}
}
