package tencent

import (
	"context"
	"fmt"
	"time"

	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"

	"github.com/hx-thanadej/keel/internal/cost"
)

// DescribeBillDetail limits (https://www.tencentcloud.com/document/api/555/30756):
// at most 300 lines a page and 5 requests a second.
const (
	billDetailPage     = 300
	billDetailInterval = 250 * time.Millisecond
	billDetailMaxPages = 10000
)

// BillDetails pulls a payer's month from DescribeBillDetail as FOCUS lines
// (cost.TencentBillLines). Creds is the identity that reads the payer's
// bill: Keel's base identity, or the payer billing role assumed from it.
//
// Pages are fetched one at a time: each passes the previous page's Context,
// and the cached Total can undercount, so the pull ends on a short page.
// Requests are spaced to stay under the rate limit, and the SDK retries
// RequestLimitExceeded with Backoff.
type BillDetails struct {
	Region   string
	Creds    common.Provider
	Endpoint string               // scheme://host, for tests
	Backoff  profile.DurationFunc // nil: exponential, 1s, 2s, 4s, ...
	// Currency is KEEL_TENCENT_BILL_CURRENCY: when set, the payer's billing
	// currency, and a line naming another blocks the month.
	Currency string
}

// billingProfile asks the billing API for English: under the SDK's zh-CN
// default PriceUnit can read "元/核/小时" rather than naming a currency code.
func billingProfile(endpoint string) *profile.ClientProfile {
	cpf := clientProfile(endpoint)
	cpf.Language = "en-US"
	return cpf
}

// MonthLines implements cost.BillDetails. Any page failing fails the month.
func (d *BillDetails) MonthLines(ctx context.Context, payer string, month time.Time) (cost.BillMonth, error) {
	cred, err := d.Creds.GetCredential()
	if err != nil {
		return cost.BillMonth{}, fmt.Errorf("tencent credentials: %w", err)
	}
	cpf := billingProfile(d.Endpoint)
	cpf.RateLimitExceededMaxRetries = 5
	cpf.RateLimitExceededRetryDuration = d.Backoff
	if d.Backoff == nil {
		cpf.RateLimitExceededRetryDuration = profile.ExponentialBackoff
	}
	client, err := guard(billing.NewClient(cred, d.Region, cpf))
	if err != nil {
		return cost.BillMonth{}, err
	}
	m := month.Format("2006-01")
	var details []*billing.BillDetail
	var next *string
	for page := range billDetailMaxPages {
		if page > 0 {
			select {
			case <-ctx.Done():
				return cost.BillMonth{}, ctx.Err()
			case <-time.After(billDetailInterval):
			}
		}
		req := billing.NewDescribeBillDetailRequest()
		offset, limit := uint64(page*billDetailPage), uint64(billDetailPage)
		req.Month, req.PayerUin, req.Offset, req.Limit, req.Context = &m, &payer, &offset, &limit, next
		res, err := client.DescribeBillDetailWithContext(ctx, req)
		if err != nil {
			return cost.BillMonth{}, fmt.Errorf("DescribeBillDetail %s offset %d: %w", m, offset, err)
		}
		if res.Response == nil {
			return cost.BillMonth{}, fmt.Errorf("DescribeBillDetail %s offset %d: empty response", m, offset)
		}
		details = append(details, res.Response.DetailSet...)
		if len(res.Response.DetailSet) < billDetailPage {
			return cost.TencentBillLines(month, details, d.Currency)
		}
		next = res.Response.Context
	}
	return cost.BillMonth{}, fmt.Errorf("DescribeBillDetail %s: more than %d pages", m, billDetailMaxPages)
}
