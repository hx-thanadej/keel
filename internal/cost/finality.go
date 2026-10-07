package cost

import "time"

var beijing = time.FixedZone("UTC+8", 8*3600)

// PeriodFinal reports whether a provider's billing period (first day of the
// month, UTC) can no longer change, per its documented finality (research/04):
//
//	tencent  previous month final 19:00 on the 1st (UTC+8); +1h buffer
//	aws      lines carry an invoice id; edits possible ≤2 weeks → after the 15th
//	azure    ~72h after month end, changes up to day 5 → from the 6th
//	alibaba  12:00 on the 3rd/4th, amortized on the 6th (UTC+8) → 6th 12:00
//	gcp      no guarantee; treated final from the 16th (documented heuristic)
//
// Unknown providers are never final, so data keeps refreshing.
func PeriodFinal(provider string, period, now time.Time, invoiced bool) bool {
	next := time.Date(period.Year(), period.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	at := func(day, hour int, loc *time.Location) time.Time {
		return time.Date(next.Year(), next.Month(), day, hour, 0, 0, 0, loc)
	}
	switch provider {
	case "tencent":
		return !now.Before(at(1, 20, beijing))
	case "aws":
		return invoiced && !now.Before(at(16, 0, time.UTC))
	case "azure":
		return !now.Before(at(6, 0, time.UTC))
	case "alibaba":
		return !now.Before(at(6, 12, beijing))
	case "gcp":
		return !now.Before(at(16, 0, time.UTC))
	}
	return false
}
