package cost

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"
)

// TencentBillLines maps a month of Tencent DescribeBillDetail lines
// (billing v20180709, https://www.tencentcloud.com/document/api/555/30756)
// to FOCUS lines, one per BillDetailComponent: the grain of Tencent's
// Standard bill (FOCUS) CSV, whose columns ParseFOCUS reads by name.
//
//	FOCUS column        DescribeBillDetail field
//	BillingAccountId    PayerUin
//	SubAccountId        OwnerUin (the Cloud Account; x_OwnerAccountID too, as in the CSV)
//	BillingPeriodStart  the month pulled
//	ChargePeriodStart   FeeBeginTime, UTC+8
//	ChargePeriodEnd     FeeEndTime, UTC+8; an end at :59 seconds is inclusive and gets +1s
//	ChargeCategory      ActionType: prepay*/pre_*/ripay* → Purchase, recon* → Adjustment, else Usage
//	ServiceName         BusinessCodeName without its trailing acronym ("Cloud Virtual Machine CVM")
//	RegionId            RegionId (Tencent's numeric id; RegionName in x_RegionName)
//	AvailabilityZone    ZoneName
//	ResourceId/Name     ResourceId / ResourceName
//	ListCost            Cost (list price; Tencent leaves it empty or "-" under contract prices)
//	BilledCost          RealCost (after discounts: what DescribeBillSummaryByPayMode's RealTotalCost sums)
//	EffectiveCost       left to Normalize: BilledCost, or amortized for a multi-day Purchase
//	PricingQuantity     UsedAmount, in UsedAmountUnit
//	BillingCurrency     PriceUnit's prefix ("USD/core/hour"); the response has no currency field
//	Tags                Tags (TagKey → TagValue)
//	x_ columns          vouchers and other payment splits (Voucher/Cash/Incentive/TransferPayAmount),
//	                    Discount, DiscountType, ActionType, BillId, ComponentName, ItemCode, ...
//
// Vouchers pay for a line; they do not lower its RealCost, so BilledCost
// keeps them and x_VoucherPayAmount says how much they paid. A month with
// more than one currency fails: Keel's loads carry one. fallbackCurrency is
// used only when no component names one.
func TencentBillLines(month time.Time, details []*billing.BillDetail, fallbackCurrency string) ([]Line, error) {
	start := monthOf(month)
	var out []Line
	var currencies []string
	for _, d := range details {
		if d == nil {
			continue
		}
		cs, ce, err := tencentChargePeriod(str(d.FeeBeginTime), str(d.FeeEndTime))
		if err != nil {
			return nil, fmt.Errorf("bill %s: %w", str(d.BillId), err)
		}
		category := tencentChargeCategory(str(d.ActionType))
		frequency := "Usage-Based"
		if category == "Purchase" {
			frequency = "One-Time"
		}
		tags := map[string]string{}
		for _, t := range d.Tags {
			if t != nil && str(t.TagKey) != "" {
				tags[str(t.TagKey)] = str(t.TagValue)
			}
		}
		for _, c := range d.ComponentSet {
			if c == nil {
				continue
			}
			billed := str(c.RealCost)
			if !ValidDecimal(billed) {
				return nil, fmt.Errorf("bill %s: RealCost %q is not a decimal", str(d.BillId), billed)
			}
			if cur, _, ok := strings.Cut(str(c.PriceUnit), "/"); ok && len(cur) == 3 && !slices.Contains(currencies, cur) {
				currencies = append(currencies, cur)
			}
			l := Line{
				BillingAccountID: str(d.PayerUin), SubAccountID: str(d.OwnerUin),
				BillingPeriodStart: start, BillingPeriodEnd: start.AddDate(0, 1, 0),
				ChargePeriodStart: cs, ChargePeriodEnd: ce,
				ChargeCategory: category, ChargeFrequency: frequency,
				ServiceName: tencentServiceName(str(d.BusinessCodeName)),
				RegionID:    str(d.RegionId), AvailabilityZone: str(d.ZoneName),
				ResourceID: str(d.ResourceId), ResourceName: str(d.ResourceName),
				ListCost: decimalOrEmpty(str(c.Cost)), BilledCost: billed,
				PricingQuantity: decimalOrEmpty(str(c.UsedAmount)), PricingUnit: str(c.UsedAmountUnit),
				Tags: tags, Vendor: map[string]string{},
			}
			for k, v := range map[string]*string{
				"x_OwnerAccountID": d.OwnerUin, "x_OperateUin": d.OperateUin, "x_BusinessCode": d.BusinessCode,
				"x_ProductCodeName": d.ProductCodeName, "x_PayModeName": d.PayModeName, "x_ActionType": d.ActionType,
				"x_ActionTypeName": d.ActionTypeName, "x_BillId": d.BillId, "x_OrderId": d.OrderId, "x_RegionName": d.RegionName,
				"x_ProjectName": d.ProjectName, "x_DiscountType": d.DiscountType, "x_DiscountObject": d.DiscountObject,
				"x_ComponentName": c.ComponentCodeName, "x_ItemName": c.ItemCodeName, "x_ItemCode": c.ItemCode,
				"x_Discount": c.Discount, "x_InstanceType": c.InstanceType, "x_VoucherPayAmount": c.VoucherPayAmount,
				"x_CashPayAmount": c.CashPayAmount, "x_IncentivePayAmount": c.IncentivePayAmount, "x_TransferPayAmount": c.TransferPayAmount,
			} {
				if s := str(v); s != "" {
					l.Vendor[k] = s
				}
			}
			out = append(out, l)
		}
	}
	currency := fallbackCurrency
	switch len(currencies) {
	case 0:
	case 1:
		currency = currencies[0]
	default:
		return nil, fmt.Errorf("bill lines in more than one currency (%s); Keel loads one currency per period", strings.Join(currencies, ", "))
	}
	for i := range out {
		out[i].BillingCurrency = currency
	}
	return out, nil
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func decimalOrEmpty(s string) string {
	if ValidDecimal(s) {
		return s
	}
	return ""
}

func tencentChargePeriod(begin, end string) (time.Time, time.Time, error) {
	const layout = "2006-01-02 15:04:05"
	s, err := time.ParseInLocation(layout, begin, beijing)
	if err != nil {
		return s, s, fmt.Errorf("FeeBeginTime %q: %w", begin, err)
	}
	e, err := time.ParseInLocation(layout, end, beijing)
	if err != nil {
		return s, s, fmt.Errorf("FeeEndTime %q: %w", end, err)
	}
	if e.Second() == 59 {
		e = e.Add(time.Second)
	}
	if e.Before(s) {
		return s, s, errors.New("FeeEndTime before FeeBeginTime")
	}
	return s.UTC(), e.UTC(), nil
}

// tencentChargeCategory reads DescribeBillDetail's ActionType code. The docs
// list only the names; pre_to_post is the documented example code.
func tencentChargeCategory(action string) string {
	a := strings.ToLower(action)
	switch {
	case strings.HasPrefix(a, "prepay"), strings.HasPrefix(a, "pre_"), strings.HasPrefix(a, "ripay"):
		return "Purchase"
	case strings.HasPrefix(a, "recon"):
		return "Adjustment"
	}
	return "Usage"
}

// tencentServiceName drops the acronym the API appends to the English product
// name ("Cloud Virtual Machine CVM"), so the name matches the FOCUS CSV's
// ServiceName and tencentCategories.
func tencentServiceName(name string) string {
	i := strings.LastIndexByte(name, ' ')
	if i < 0 {
		return name
	}
	last := name[i+1:]
	for _, r := range last {
		if !unicode.IsUpper(r) && !unicode.IsDigit(r) {
			return name
		}
	}
	return name[:i]
}
