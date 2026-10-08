package cost

import (
	"fmt"
	"math/big"
	"strings"
	"time"
)

// tencentCategories maps Tencent Cloud service names (as they appear in
// ServiceName) to FOCUS ServiceCategory, which Tencent leaves empty.
// Unknown services map to "Other"; extend as new names appear in bills.
var tencentCategories = map[string]string{
	"cloud virtual machine":               "Compute",
	"lighthouse":                          "Compute",
	"tencent kubernetes engine":           "Compute",
	"elastic kubernetes service":          "Compute",
	"serverless cloud function":           "Compute",
	"auto scaling":                        "Compute",
	"cloud block storage":                 "Storage",
	"cloud object storage":                "Storage",
	"cloud file storage":                  "Storage",
	"cloud archive storage":               "Storage",
	"tencentdb for mysql":                 "Databases",
	"tencentdb for postgresql":            "Databases",
	"tencentdb for redis":                 "Databases",
	"tencentdb for mongodb":               "Databases",
	"tdsql-c for mysql":                   "Databases",
	"tencentdb for sql server":            "Databases",
	"cloud load balancer":                 "Networking",
	"nat gateway":                         "Networking",
	"elastic ip":                          "Networking",
	"virtual private cloud":               "Networking",
	"vpn connections":                     "Networking",
	"content delivery network":            "Networking",
	"cloud connect network":               "Networking",
	"direct connect":                      "Networking",
	"bandwidth package":                   "Networking",
	"tencent container registry":          "Developer Tools",
	"cloud log service":                   "Management and Governance",
	"cloud monitor":                       "Management and Governance",
	"cloudaudit":                          "Management and Governance",
	"key management service":              "Security",
	"secrets manager":                     "Security",
	"ssl certificate service":             "Security",
	"web application firewall":            "Security",
	"anti-ddos":                           "Security",
	"cloud workload protection platform":  "Security",
	"tencent cloud elasticsearch service": "Analytics",
	"tdmq for ckafka":                     "Integration",
	"tdmq for rabbitmq":                   "Integration",
	"api gateway":                         "Integration",
	"tencent cloud mini program":          "Mobile",
}

// Normalize fills FOCUS columns a provider leaves empty and returns the lines
// plus derived amortization rows (ADR-0011, #32).
//
//   - EffectiveCost from the source is kept ("source").
//   - Otherwise usage lines get EffectiveCost = BilledCost ("billed").
//   - A prepaid Purchase spanning more than a day keeps its BilledCost (so
//     monthly billed totals still reconcile to the invoice) but carries
//     EffectiveCost 0 ("amortized"), and one zero-billed Usage row per day of
//     its term carries the cost spread evenly ("amortization"), summing exactly.
//
// Azure's SubAccountId (an ARM path) becomes the bare subscription id.
// Tencent also gets ServiceCategory from tencentCategories and a SkuId derived
// from service and component, since its FOCUS export leaves both empty.
func Normalize(provider string, lines []Line) []Line {
	out := make([]Line, 0, len(lines))
	var extra []Line
	for _, l := range lines {
		if provider == "azure" {
			// Azure's SubAccountId is the subscription's ARM path; Cloud
			// Accounts are registered by subscription id.
			l.SubAccountID = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(l.SubAccountID, "/subscriptions/"), "/SUBSCRIPTIONS/"))
		}
		if provider == "tencent" {
			if l.ServiceCategory == "" {
				l.ServiceCategory = tencentCategory(l.ServiceName)
			}
			if l.SkuID == "" && l.ServiceName != "" {
				l.SkuID = "tencent:" + l.ServiceName
				if c := l.Vendor["x_ComponentName"]; c != "" {
					l.SkuID += "/" + c
				}
			}
		}
		switch {
		case l.EffectiveCost != "":
			l.EffectiveCostMethod = "source"
		case strings.EqualFold(l.ChargeCategory, "Purchase") && days(l) > 1:
			l.EffectiveCost, l.EffectiveCostMethod = "0", "amortized"
			extra = append(extra, amortize(l)...)
		default:
			l.EffectiveCost, l.EffectiveCostMethod = l.BilledCost, "billed"
		}
		out = append(out, l)
	}
	return append(out, extra...)
}

func tencentCategory(service string) string {
	if c, ok := tencentCategories[strings.ToLower(strings.TrimSpace(service))]; ok {
		return c
	}
	return "Other"
}

func days(l Line) int {
	start := l.ChargePeriodStart.Truncate(24 * time.Hour)
	return int(l.ChargePeriodEnd.Sub(start).Hours() / 24)
}

// amortize spreads a purchase over its term, one row per UTC day, rounding to
// 6 decimals and putting the remainder on the last day so the sum is exact.
func amortize(p Line) []Line {
	n := days(p)
	total, ok := new(big.Rat).SetString(p.BilledCost)
	if !ok || n < 2 {
		return nil
	}
	per := new(big.Rat).Quo(total, big.NewRat(int64(n), 1))
	perStr := per.FloatString(6)
	perRounded, _ := new(big.Rat).SetString(perStr)
	last := new(big.Rat).Sub(total, new(big.Rat).Mul(perRounded, big.NewRat(int64(n-1), 1)))
	start := p.ChargePeriodStart.Truncate(24 * time.Hour)
	out := make([]Line, n)
	for i := range n {
		row := p
		row.ChargeCategory, row.ChargeFrequency, row.ChargeClass = "Usage", "Recurring", ""
		row.ChargePeriodStart = start.AddDate(0, 0, i)
		row.ChargePeriodEnd = row.ChargePeriodStart.AddDate(0, 0, 1)
		row.BilledCost, row.ListCost, row.ContractedCost = "0", "", ""
		row.PricingQuantity, row.ConsumedQuantity = "", ""
		row.EffectiveCost, row.EffectiveCostMethod = perStr, "amortization"
		if i == n-1 {
			row.EffectiveCost = last.FloatString(6)
		}
		row.Vendor = map[string]string{"x_AmortizedFrom": fmt.Sprintf("%s purchase %s", p.ResourceID, p.ChargePeriodStart.Format("2006-01-02"))}
		out[i] = row
	}
	return out
}
