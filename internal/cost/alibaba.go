package cost

import (
	"encoding/json"
	"strings"
)

// Alibaba Cloud's standard detailed bill (OSS bill subscription, new version)
// names columns by path, e.g. BillingDetails/BillingMonth. Where an account
// has the invitation-only "Standard Bill FOCUS" export, that is FOCUS already
// and parses directly (its extension columns are X_-prefixed). Otherwise
// alibabaRow maps the standard bill to FOCUS columns.
//
// Documented gaps of this mapping (#153):
//   - ChargePeriod is the bill's day (BillingDate, a UTC+8 calendar date)
//     taken as that UTC day; hourly lines collapse into the day.
//   - ChargeCategory is derived from LineItemType by keyword; values not
//     recognised count as Usage.
//   - EffectiveCost is left empty (billed is used), so prepaid purchases are
//     amortized by Keel rather than by Alibaba's amortized bill.
//   - ResourceTag is parsed as "key:k value:v; key:k2 value:v2" (the API's
//     format); other shapes are kept verbatim in x_ResourceTag only.
//   - BillingAccountId is the purchasing account; Keel's sync supplies the
//     payer explicitly.
const alibabaMarker = "BillingDetails/BillingMonth"

var alibabaColumns = map[string][]string{ // FOCUS column ← first non-empty source
	"BillingAccountId": {"IdentityDetails/ResourcePurchaseAccountId"},
	"SubAccountId":     {"IdentityDetails/ResourceOwnerAccountId", "IdentityDetails/ResourcePurchaseAccountId"},
	"SubAccountName":   {"IdentityDetails/ResourceOwnerAccountName"},
	"ServiceName":      {"ProductDetails/ProductName", "ProductDetails/ProductCode"},
	"SkuId":            {"ProductDetails/BillingItemCode", "ProductDetails/CommodityCode"},
	"ResourceId":       {"ResourceDetails/InstanceId", "ResourceDetails/ResourceId"},
	"RegionId":         {"ResourceDetails/RegionCode"},
	"AvailabilityZone": {"ResourceDetails/Zone"},
	"ConsumedQuantity": {"UsageDetails/Usage"},
	"ConsumedUnit":     {"UsageDetails/UsageUnit"},
	"ListCost":         {"FeeDetails/GrossAmount"},
	"BilledCost":       {"PayableDetails/TaxExclusivePayableAmount"},
	"BillingCurrency":  {"PricingDetails/Currency"},
	"x_ProductCode":    {"ProductDetails/ProductCode"},
	"x_CommodityCode":  {"ProductDetails/CommodityCode"},
	"x_LineItemType":   {"BillingDetails/LineItemType"},
	"x_DiscountAmount": {"DiscountDetails/DiscountAmount"},
	"x_ResourceTag":    {"ResourceDetails/ResourceTag"},
}

func isAlibabaBill(has func(string) bool) bool { return has(alibabaMarker) }

// alibabaRow maps one standard-bill row (by its column names) to FOCUS.
func alibabaRow(src map[string]string) map[string]string {
	get := func(names ...string) string {
		for _, n := range names {
			if v := strings.TrimSpace(src[n]); v != "" {
				return v
			}
		}
		return ""
	}
	row := map[string]string{}
	for focus, from := range alibabaColumns {
		row[focus] = get(from...)
	}
	if month := get("BillingDetails/BillingMonth"); len(month) == 6 { // 202609
		row["BillingPeriodStart"] = month[:4] + "-" + month[4:] + "-01"
	}
	day := get("BillingDetails/BillingDate") // 20260906
	if len(day) == 8 {
		day = day[:4] + "-" + day[4:6] + "-" + day[6:]
	} else if day == "" {
		day = row["BillingPeriodStart"]
	}
	row["ChargePeriodStart"] = day
	if t, err := parseTime(day); err == nil {
		row["ChargePeriodEnd"] = t.AddDate(0, 0, 1).Format("2006-01-02")
	}
	row["ChargeCategory"] = alibabaCategory(get("BillingDetails/LineItemType"))
	if row["BillingCurrency"] == "" {
		row["BillingCurrency"] = "USD" // international site default; CNY on the China site carries the column
	}
	if tags := alibabaTags(get("ResourceDetails/ResourceTag")); tags != nil {
		b, _ := json.Marshal(tags)
		row["Tags"] = string(b)
	}
	return row
}

func alibabaCategory(t string) string {
	l := strings.ToLower(t)
	switch {
	case strings.Contains(l, "refund"), strings.Contains(l, "credit"), strings.Contains(l, "coupon"):
		return "Credit"
	case strings.Contains(l, "adjust"):
		return "Adjustment"
	case strings.Contains(l, "tax"):
		return "Tax"
	case strings.Contains(l, "subscription"), strings.Contains(l, "purchase"), strings.Contains(l, "prepaid"):
		return "Purchase"
	}
	return "Usage"
}

// alibabaTags parses "key:k value:v; key:k2 value:v2"; nil when it isn't that.
func alibabaTags(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, " value:")
		if !ok || !strings.HasPrefix(k, "key:") {
			return nil
		}
		out[strings.TrimPrefix(k, "key:")] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
