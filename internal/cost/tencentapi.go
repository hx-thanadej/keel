package cost

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"

	"github.com/hx-thanadej/keel/internal/fx"
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
//	RegionId            RegionId, raw: Tencent's numeric id (no offline source maps it to a code); RegionName in x_RegionName
//	AvailabilityZone    ZoneName
//	ResourceId/Name     ResourceId / ResourceName
//	ListCost            Cost (list price; Tencent leaves it empty or "-" under contract prices)
//	BilledCost          RealCost (after discounts: what DescribeBillSummaryByPayMode's RealTotalCost sums)
//	EffectiveCost       left to Normalize: BilledCost, or amortized for a multi-day Purchase
//	PricingQuantity     UsedAmount, in UsedAmountUnit
//	BillingCurrency     PriceUnit's prefix ("USD/core/hour"), or the explicit currency; the response has no currency field
//	Tags                Tags (TagKey → TagValue)
//	x_ columns          vouchers and other payment splits (Voucher/Cash/Incentive/TransferPayAmount),
//	                    Discount, DiscountType, ActionType, BillId, ComponentName, ItemCode, ...
//
// Vouchers pay for a line; they do not lower its RealCost, so BilledCost
// keeps them and x_VoucherPayAmount says how much they paid.
//
// The currency is never guessed. Each component's PriceUnit prefix must be a
// currency ParseCurrency accepts, or empty or "-" (contract price, no unit).
// Without an explicit currency the month must name exactly one; with one,
// every named currency must match it. Anything else fails with
// ErrBillCurrency. Assumptions lists what the mapping assumed, for the
// load's Activity, so the first real load can be checked against them.
func TencentBillLines(month time.Time, details []*billing.BillDetail, explicitCurrency string) (BillMonth, error) {
	start := monthOf(month)
	var out []Line
	var currencies, unreadable []string
	defaulted := map[string]int{}
	for _, d := range details {
		if d == nil {
			continue
		}
		cs, ce, err := tencentChargePeriod(str(d.FeeBeginTime), str(d.FeeEndTime))
		if err != nil {
			return BillMonth{}, fmt.Errorf("bill %s: %w", str(d.BillId), err)
		}
		category, mapped := tencentChargeCategory(str(d.ActionType))
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
				return BillMonth{}, fmt.Errorf("bill %s: RealCost %q is not a decimal", str(d.BillId), billed)
			}
			if !mapped {
				defaulted[str(d.ActionType)]++
			}
			switch cur, _, _ := strings.Cut(str(c.PriceUnit), "/"); {
			case cur == "" || cur == "-":
			case slices.Contains(currencies, cur) || slices.Contains(unreadable, cur):
			default:
				if _, err := ParseCurrency(cur); err != nil {
					unreadable = append(unreadable, cur)
				} else {
					currencies = append(currencies, cur)
				}
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
	if len(out) == 0 {
		return BillMonth{}, nil
	}
	currency, from, err := tencentCurrency(currencies, unreadable, explicitCurrency)
	if err != nil {
		return BillMonth{}, err
	}
	for i := range out {
		out[i].BillingCurrency = currency
	}
	return BillMonth{Lines: out, Assumptions: []string{
		"FeeBeginTime/FeeEndTime read as UTC+8",
		"currency " + currency + " from " + from,
		tencentDefaultedActions(defaulted),
		"RegionId raw (Tencent numeric id, not mapped to a region code)",
	}}, nil
}

// ErrBillCurrency is a bill whose currency cannot be read with certainty.
var ErrBillCurrency = errors.New("bill currency unknown")

// ParseCurrency accepts an ISO 4217 code that Keel stores rates for.
func ParseCurrency(s string) (string, error) {
	if utf8.RuneCountInString(s) != 3 || strings.IndexFunc(s, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0 {
		return "", fmt.Errorf("%q is not an ISO 4217 currency code", s)
	}
	if !fx.Kept[s] {
		return "", fmt.Errorf("currency %s is not one Keel supports", s)
	}
	return s, nil
}

func tencentCurrency(named, unreadable []string, explicit string) (currency, from string, err error) {
	fail := func(format string, a ...any) (string, string, error) {
		return "", "", fmt.Errorf("%w: %s; set KEEL_TENCENT_BILL_CURRENCY to the payer's billing currency once confirmed in the console",
			ErrBillCurrency, fmt.Sprintf(format, a...))
	}
	switch {
	case len(unreadable) > 0:
		return fail("PriceUnit names %s, not a supported ISO 4217 code", strings.Join(unreadable, ", "))
	case explicit != "":
		if i := slices.IndexFunc(named, func(c string) bool { return c != explicit }); i >= 0 {
			return fail("lines in %s contradict KEEL_TENCENT_BILL_CURRENCY=%s", named[i], explicit)
		}
		return explicit, "KEEL_TENCENT_BILL_CURRENCY", nil
	case len(named) == 0:
		return fail("no line's PriceUnit names a currency")
	case len(named) > 1:
		return fail("lines in more than one currency (%s); Keel loads one currency per period", strings.Join(named, ", "))
	}
	return named[0], "PriceUnit", nil
}

func tencentDefaultedActions(n map[string]int) string {
	if len(n) == 0 {
		return "ActionType defaulted to Usage: none"
	}
	total := 0
	var each []string
	for _, a := range slices.Sorted(maps.Keys(n)) {
		total += n[a]
		each = append(each, fmt.Sprintf("%s %d", a, n[a]))
	}
	return fmt.Sprintf("ActionType defaulted to Usage: %d lines (%s)", total, strings.Join(each, ", "))
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
// list only the names; pre_to_post is the documented example code. mapped is
// false for a code no rule names, which defaults to Usage.
func tencentChargeCategory(action string) (category string, mapped bool) {
	a := strings.ToLower(action)
	switch {
	case strings.HasPrefix(a, "prepay"), strings.HasPrefix(a, "pre_"), strings.HasPrefix(a, "ripay"):
		return "Purchase", true
	case strings.HasPrefix(a, "recon"):
		return "Adjustment", true
	}
	return "Usage", false
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
