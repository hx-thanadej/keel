package tencent

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

// Invoices reads a payer's monthly total for reconciliation (#32) via
// DescribeBillSummaryByPayMode. Credentials must belong to (or be allowed to
// read) the payer account; member accounts see nothing (research/04).
type Invoices struct {
	Region string
	Creds  common.Provider
}

// InvoiceTotal sums RealTotalCost (after discounts) across pay modes.
func (i Invoices) InvoiceTotal(ctx context.Context, payerUIN string, period time.Time) (string, bool, error) {
	cred, err := i.Creds.GetCredential()
	if err != nil {
		return "", false, fmt.Errorf("tencent credentials: %w", err)
	}
	client, err := billing.NewClient(cred, i.Region, profile.NewClientProfile())
	if err != nil {
		return "", false, err
	}
	req := billing.NewDescribeBillSummaryByPayModeRequest()
	month := period.Format("2006-01")
	req.BeginTime, req.EndTime, req.PayerUin = &month, &month, &payerUIN
	res, err := client.DescribeBillSummaryByPayModeWithContext(ctx, req)
	if err != nil {
		return "", false, fmt.Errorf("DescribeBillSummaryByPayMode: %w", err)
	}
	if res.Response == nil {
		return "", false, errors.New("DescribeBillSummaryByPayMode: empty response")
	}
	return SumRealTotalCost(res.Response)
}

// SumRealTotalCost totals a DescribeBillSummaryByPayMode response.
func SumRealTotalCost(r *billing.DescribeBillSummaryByPayModeResponseParams) (string, bool, error) {
	total := new(big.Rat)
	for _, item := range r.SummaryOverview {
		if item == nil || item.RealTotalCost == nil {
			continue
		}
		v, ok := new(big.Rat).SetString(*item.RealTotalCost)
		if !ok {
			return "", false, fmt.Errorf("RealTotalCost %q is not a decimal", *item.RealTotalCost)
		}
		total.Add(total, v)
	}
	ready := r.Ready != nil && *r.Ready == 1
	return total.FloatString(6), ready, nil
}
