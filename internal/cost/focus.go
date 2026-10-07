// Package cost ingests provider billing data into FOCUS-shaped cost facts,
// attributes it to Tenants, Projects and Environments, and answers cost
// queries (#30, #31, #34; ADR-0011).
package cost

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// Line is one FOCUS row. Monetary and quantity values stay as decimal
// strings and are stored as Postgres numeric, never float.
type Line struct {
	BillingAccountID, SubAccountID, SubAccountName string
	BillingPeriodStart, BillingPeriodEnd           time.Time
	ChargePeriodStart, ChargePeriodEnd             time.Time
	ChargeCategory, ChargeClass, ChargeFrequency   string
	ServiceCategory, ServiceName, ServiceSubcat    string
	SkuID, RegionID, AvailabilityZone              string
	ResourceID, ResourceName, ResourceType         string
	PricingQuantity, PricingUnit                   string
	ConsumedQuantity, ConsumedUnit                 string
	ListCost, BilledCost, EffectiveCost            string
	ContractedCost, BillingCurrency                string
	CommitmentDiscountID, CommitmentDiscountType   string
	CommitmentDiscountStatus                       string
	Tags                                           map[string]string
	Vendor                                         map[string]string // x_ columns
}

var required = []string{"BilledCost", "BillingCurrency", "BillingPeriodStart", "ChargePeriodStart", "ChargePeriodEnd", "ChargeCategory", "SubAccountId"}

var decimalRE = regexp.MustCompile(`^-?\d+(\.\d+)?$`)

// ValidDecimal reports whether s is a plain decimal number.
func ValidDecimal(s string) bool { return decimalRE.MatchString(s) }

// ParseFOCUS reads a FOCUS CSV export, plain, gzip or zip (first .csv entry).
// Columns are matched by name, so order and extra columns don't matter.
func ParseFOCUS(raw []byte) ([]Line, error) {
	data, err := decompress(raw)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // UTF-8 BOM
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("focus header: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	for _, c := range required {
		if _, ok := col[c]; !ok {
			return nil, fmt.Errorf("focus: required column %s missing", c)
		}
	}
	var out []Line
	for n := 2; ; n++ {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("focus line %d: %w", n, err)
		}
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		l := Line{
			BillingAccountID: get("BillingAccountId"), SubAccountID: get("SubAccountId"), SubAccountName: get("SubAccountName"),
			ChargeCategory: get("ChargeCategory"), ChargeClass: get("ChargeClass"), ChargeFrequency: get("ChargeFrequency"),
			ServiceCategory: get("ServiceCategory"), ServiceName: get("ServiceName"), ServiceSubcat: get("ServiceSubcategory"),
			SkuID: get("SkuId"), RegionID: get("RegionId"), AvailabilityZone: get("AvailabilityZone"),
			ResourceID: get("ResourceId"), ResourceName: get("ResourceName"), ResourceType: get("ResourceType"),
			PricingQuantity: get("PricingQuantity"), PricingUnit: get("PricingUnit"),
			ConsumedQuantity: get("ConsumedQuantity"), ConsumedUnit: get("ConsumedUnit"),
			ListCost: get("ListCost"), BilledCost: get("BilledCost"), EffectiveCost: get("EffectiveCost"),
			ContractedCost: get("ContractedCost"), BillingCurrency: get("BillingCurrency"),
			CommitmentDiscountID: get("CommitmentDiscountId"), CommitmentDiscountType: get("CommitmentDiscountType"),
			CommitmentDiscountStatus: get("CommitmentDiscountStatus"),
			Tags:                     map[string]string{}, Vendor: map[string]string{},
		}
		for _, f := range []struct {
			name string
			dst  *time.Time
		}{{"BillingPeriodStart", &l.BillingPeriodStart}, {"BillingPeriodEnd", &l.BillingPeriodEnd}, {"ChargePeriodStart", &l.ChargePeriodStart}, {"ChargePeriodEnd", &l.ChargePeriodEnd}} {
			v := get(f.name)
			if v == "" && f.name == "BillingPeriodEnd" {
				continue
			}
			t, err := parseTime(v)
			if err != nil {
				return nil, fmt.Errorf("focus line %d: %s %q: %w", n, f.name, v, err)
			}
			*f.dst = t
		}
		if !ValidDecimal(l.BilledCost) {
			return nil, fmt.Errorf("focus line %d: BilledCost %q is not a decimal", n, l.BilledCost)
		}
		for name, v := range map[string]string{"ListCost": l.ListCost, "EffectiveCost": l.EffectiveCost, "ContractedCost": l.ContractedCost, "PricingQuantity": l.PricingQuantity, "ConsumedQuantity": l.ConsumedQuantity} {
			if v != "" && !ValidDecimal(v) {
				return nil, fmt.Errorf("focus line %d: %s %q is not a decimal", n, name, v)
			}
		}
		if tags := get("Tags"); tags != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(tags), &m); err != nil {
				return nil, fmt.Errorf("focus line %d: Tags is not a JSON object: %w", n, err)
			}
			for k, v := range m {
				l.Tags[k] = fmt.Sprint(v)
			}
		}
		for name, i := range col {
			if strings.HasPrefix(name, "x_") && i < len(rec) && rec[i] != "" {
				l.Vendor[name] = rec[i]
			}
		}
		out = append(out, l)
	}
}

func parseTime(v string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("not an ISO 8601 time")
}

func decompress(raw []byte) ([]byte, error) {
	switch {
	case len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b:
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(io.LimitReader(zr, 4<<30))
	case len(raw) >= 4 && string(raw[:4]) == "PK\x03\x04":
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer func() { _ = rc.Close() }()
				return io.ReadAll(io.LimitReader(rc, 4<<30))
			}
		}
		return nil, errors.New("zip contains no .csv")
	case len(raw) == 0:
		return nil, errors.New("empty file")
	default:
		return raw, nil
	}
}
