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
	EffectiveCostMethod                            string // source | billed | amortized | amortization
	InvoiceID                                      string
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

// ParseFOCUS reads a FOCUS export: CSV (plain, gzip or zip with a .csv
// entry) or Parquet (Azure and Google Cloud exports). Columns are matched by
// name, so order and extra columns don't matter. Alibaba Cloud's standard
// detailed bill is recognised by its headers and mapped to FOCUS.
func ParseFOCUS(raw []byte) ([]Line, error) {
	if isParquet(raw) {
		return parseParquet(raw)
	}
	data, err := decompress(raw)
	if err != nil {
		return nil, err
	}
	if isParquet(data) {
		return parseParquet(data)
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
	has := func(c string) bool { _, ok := col[c]; return ok }
	alibaba := isAlibabaBill(has)
	if !alibaba {
		if err := checkRequired(has); err != nil {
			return nil, err
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
		row := make(map[string]string, len(col))
		for name, i := range col {
			if i < len(rec) {
				row[name] = rec[i]
			}
		}
		if alibaba {
			row = alibabaRow(row)
		}
		l, err := lineFrom(row)
		if err != nil {
			return nil, fmt.Errorf("focus line %d: %w", n, err)
		}
		out = append(out, l)
	}
}

// ErrNotFOCUS marks a file with none of the FOCUS required columns, or a zip
// with no CSV inside, such as another bill type delivered under the same
// prefix. A file with some but not all of them is a malformed FOCUS file and
// fails with a plain error.
var ErrNotFOCUS = errors.New("not a FOCUS bill")

func checkRequired(has func(string) bool) error {
	var missing []string
	for _, c := range required {
		if !has(c) {
			missing = append(missing, c)
		}
	}
	switch len(missing) {
	case 0:
		return nil
	case len(required):
		return fmt.Errorf("%w: no FOCUS required columns", ErrNotFOCUS)
	}
	return fmt.Errorf("focus: required column %s missing", missing[0])
}

// lineFrom maps one row, by FOCUS column name, to a Line.
func lineFrom(row map[string]string) (Line, error) {
	get := func(name string) string { return strings.TrimSpace(row[name]) }
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
		CommitmentDiscountStatus: get("CommitmentDiscountStatus"), InvoiceID: get("InvoiceId"),
		Tags: map[string]string{}, Vendor: map[string]string{},
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
			return l, fmt.Errorf("%s %q: %w", f.name, v, err)
		}
		*f.dst = t
	}
	if !ValidDecimal(l.BilledCost) {
		return l, fmt.Errorf("BilledCost %q is not a decimal", l.BilledCost)
	}
	for name, v := range map[string]string{"ListCost": l.ListCost, "EffectiveCost": l.EffectiveCost, "ContractedCost": l.ContractedCost, "PricingQuantity": l.PricingQuantity, "ConsumedQuantity": l.ConsumedQuantity} {
		if v != "" && !ValidDecimal(v) {
			return l, fmt.Errorf("%s %q is not a decimal", name, v)
		}
	}
	// Tags; Google leaves it empty and carries labels in x_ columns, which
	// its CSV exports hold as JSON (later sources win).
	for _, c := range tagColumns {
		if tags := get(c); tags != "" && tags != "[]" {
			if err := parseTags(tags, l.Tags); err != nil {
				return l, fmt.Errorf("%s: %w", c, err)
			}
		}
	}
	for name, v := range row {
		// x_ columns; Alibaba writes X_.
		if (strings.HasPrefix(name, "x_") || strings.HasPrefix(name, "X_")) && v != "" {
			l.Vendor[name] = v
		}
	}
	return l, nil
}

// parseTags reads Tags as a JSON object (FOCUS, Azure, AWS, Tencent) or as a
// JSON array of {"key", "value"} pairs (Google Cloud's billing export shape).
func parseTags(raw string, into map[string]string) error {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err == nil {
		for k, v := range m {
			into[k] = fmt.Sprint(v)
		}
		return nil
	}
	var kv []struct {
		Key   string `json:"key"`
		Value any    `json:"value"`
	}
	if err := json.Unmarshal([]byte(raw), &kv); err != nil {
		return errors.New("tags column is neither a JSON object nor a list of key/value pairs")
	}
	for _, p := range kv {
		if p.Key != "" {
			into[p.Key] = fmt.Sprint(p.Value)
		}
	}
	return nil
}

func parseTime(v string) (time.Time, error) {
	// RFC 3339; Azure FOCUS 1.0 without seconds; BigQuery CSV ("... UTC");
	// plain date-times and dates as UTC.
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04Z07:00", "2006-01-02 15:04:05.999999999 MST", "2006-01-02 15:04:05", "2006-01-02"} {
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
		return nil, fmt.Errorf("%w: zip contains no .csv", ErrNotFOCUS)
	case len(raw) == 0:
		return nil, errors.New("empty file")
	default:
		return raw, nil
	}
}
