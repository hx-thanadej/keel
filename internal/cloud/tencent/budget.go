package tencent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"

	"github.com/hx-thanadej/keel/internal/budget"
)

// Budgets mirrors Keel Budgets into Tencent Cloud budgets (#39): one monthly
// CYCLE budget per Keel Budget with each month's quota, scoped to the
// accounts (OwnerUins), consumption bill for effective cost, bill for billed.
type Budgets struct {
	Region string
	Creds  common.Provider
}

// Provider implements budget.Native.
func (Budgets) Provider() string { return "tencent" }

const note = "Managed by Keel. Changes made here are overwritten."

type quota struct {
	DateDesc string `json:"dateDesc"`
	Quota    string `json:"quota"`
}

// CreateBudgetRequest maps a spec to Tencent's CreateBudget request.
func CreateBudgetRequest(s budget.NativeSpec) *billing.CreateBudgetRequest {
	req := billing.NewCreateBudgetRequest()
	name, cycle, plan, fee := "keel-"+s.Name, "MONTH", "CYCLE", "REAL_COST"
	begin, end := fmt.Sprintf("%d-01", s.Year), fmt.Sprintf("%d-12", s.Year)
	bill := "CONSUMPTION" // amortised, like Keel's effective cost
	if s.Basis == "billed" {
		bill = "BILL"
	}
	qs := make([]quota, 12)
	for i, v := range s.Monthly {
		qs[i] = quota{DateDesc: fmt.Sprintf("%d-%02d", s.Year, i+1), Quota: v}
	}
	qj, _ := json.Marshal(qs)
	quotas := string(qj)
	n := note
	req.BudgetName, req.CycleType, req.PlanType, req.FeeType, req.BillType = &name, &cycle, &plan, &fee, &bill
	req.PeriodBegin, req.PeriodEnd, req.BudgetQuota, req.BudgetNote = &begin, &end, &quotas, &n
	req.DimensionsRange = &billing.BudgetConditionsForm{OwnerUins: common.StringPtrs(s.Accounts)}
	for _, t := range s.Thresholds {
		wt, ct, v := "ACTUAL", "PERCENTAGE", strconv.FormatFloat(t.Pct, 'f', -1, 64)
		if t.Basis == "forecast" {
			wt = "FORECAST"
		}
		req.WarnJson = append(req.WarnJson, &billing.BudgetWarn{WarnType: &wt, CalType: &ct, ThresholdValue: &v})
	}
	return req
}

func (b Budgets) client() (*billing.Client, error) {
	cred, err := b.Creds.GetCredential()
	if err != nil {
		return nil, fmt.Errorf("tencent credentials: %w", err)
	}
	return billing.NewClient(cred, b.Region, profile.NewClientProfile())
}

// Create implements budget.Native.
func (b Budgets) Create(ctx context.Context, s budget.NativeSpec) (string, error) {
	c, err := b.client()
	if err != nil {
		return "", err
	}
	res, err := c.CreateBudgetWithContext(ctx, CreateBudgetRequest(s))
	if err != nil {
		return "", fmt.Errorf("CreateBudget: %w", err)
	}
	if res.Response == nil || res.Response.Data == nil || res.Response.Data.BudgetId == nil {
		return "", errors.New("CreateBudget: no budget id in response")
	}
	return *res.Response.Data.BudgetId, nil
}

// Update implements budget.Native.
func (b Budgets) Update(ctx context.Context, id string, s budget.NativeSpec) error {
	c, err := b.client()
	if err != nil {
		return err
	}
	cr := CreateBudgetRequest(s)
	req := billing.NewModifyBudgetRequest()
	req.BudgetId = &id
	req.BudgetName, req.CycleType, req.PlanType, req.FeeType, req.BillType = cr.BudgetName, cr.CycleType, cr.PlanType, cr.FeeType, cr.BillType
	req.PeriodBegin, req.PeriodEnd, req.BudgetQuota, req.BudgetNote = cr.PeriodBegin, cr.PeriodEnd, cr.BudgetQuota, cr.BudgetNote
	req.DimensionsRange, req.WarnJson = cr.DimensionsRange, cr.WarnJson
	if _, err := c.ModifyBudgetWithContext(ctx, req); err != nil {
		return fmt.Errorf("ModifyBudget: %w", err)
	}
	return nil
}

// Get implements budget.Native.
func (b Budgets) Get(ctx context.Context, id string) (budget.NativeSpec, bool, error) {
	c, err := b.client()
	if err != nil {
		return budget.NativeSpec{}, false, err
	}
	req := billing.NewDescribeBudgetRequest()
	page, size := int64(1), int64(10)
	req.BudgetId, req.PageNo, req.PageSize = &id, &page, &size
	res, err := c.DescribeBudgetWithContext(ctx, req)
	if err != nil {
		return budget.NativeSpec{}, false, fmt.Errorf("DescribeBudget: %w", err)
	}
	if res.Response == nil || res.Response.Data == nil {
		return budget.NativeSpec{}, false, nil
	}
	for _, r := range res.Response.Data.Records {
		if r != nil && r.BudgetId != nil && *r.BudgetId == id {
			return SpecFromBudget(r), true, nil
		}
	}
	return budget.NativeSpec{}, false, nil
}

// SpecFromBudget reads a described Tencent budget back into a spec.
func SpecFromBudget(r *billing.BudgetExtend) budget.NativeSpec {
	var s budget.NativeSpec
	if r.PeriodBegin != nil && len(*r.PeriodBegin) >= 4 {
		s.Year, _ = strconv.Atoi((*r.PeriodBegin)[:4])
	}
	s.Basis = "effective"
	if r.BillType != nil && *r.BillType == "BILL" {
		s.Basis = "billed"
	}
	s.Currency = "USD"
	for _, q := range r.BudgetQuotaJson {
		if q == nil || q.DateDesc == nil || q.Quota == nil || len(*q.DateDesc) < 7 {
			continue
		}
		if m, err := strconv.Atoi((*q.DateDesc)[5:7]); err == nil && m >= 1 && m <= 12 {
			s.Monthly[m-1] = *q.Quota
		}
	}
	if r.DimensionsRange != nil {
		for _, u := range r.DimensionsRange.OwnerUins {
			if u != nil {
				s.Accounts = append(s.Accounts, *u)
			}
		}
		slices.Sort(s.Accounts)
	}
	for _, w := range r.WarnJson {
		if w == nil || w.ThresholdValue == nil {
			continue
		}
		p, _ := strconv.ParseFloat(*w.ThresholdValue, 64)
		basis := "actual"
		if w.WarnType != nil && *w.WarnType == "FORECAST" {
			basis = "forecast"
		}
		s.Thresholds = append(s.Thresholds, budget.Threshold{Pct: p, Basis: basis})
	}
	if r.BudgetName != nil {
		s.Name = *r.BudgetName
	}
	return s
}

// Delete implements budget.Native.
func (b Budgets) Delete(ctx context.Context, id string) error {
	c, err := b.client()
	if err != nil {
		return err
	}
	req := billing.NewDeleteBudgetRequest()
	req.BudgetIds = []*string{&id}
	if _, err := c.DeleteBudgetWithContext(ctx, req); err != nil {
		return fmt.Errorf("DeleteBudget: %w", err)
	}
	return nil
}
