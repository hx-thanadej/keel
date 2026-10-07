// Package fx provides daily exchange rates for converting spend into a
// Tenant's currency (#43). Source: the European Central Bank's daily euro
// reference rates (free, keyless, includes THB and USD); cross rates are
// derived through EUR.
package fx

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ECBDailyURL and ECB90DaysURL are the ECB reference-rate feeds.
const (
	ECBDailyURL  = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"
	ECB90DaysURL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-hist-90d.xml"
)

// Rate is units of Currency per 1 EUR on Day.
type Rate struct {
	Day      time.Time
	Currency string
	PerEUR   string // decimal string, kept exact
}

type envelope struct {
	Cube struct {
		Days []struct {
			Time  string `xml:"time,attr"`
			Rates []struct {
				Currency string `xml:"currency,attr"`
				Rate     string `xml:"rate,attr"`
			} `xml:"Cube"`
		} `xml:"Cube"`
	} `xml:"Cube"`
}

// ParseECB reads an ECB eurofxref XML document.
func ParseECB(r io.Reader) ([]Rate, error) {
	var e envelope
	if err := xml.NewDecoder(r).Decode(&e); err != nil {
		return nil, fmt.Errorf("ecb xml: %w", err)
	}
	var out []Rate
	for _, d := range e.Cube.Days {
		day, err := time.Parse("2006-01-02", d.Time)
		if err != nil {
			return nil, fmt.Errorf("ecb day %q: %w", d.Time, err)
		}
		out = append(out, Rate{Day: day, Currency: "EUR", PerEUR: "1"})
		for _, r := range d.Rates {
			out = append(out, Rate{Day: day, Currency: r.Currency, PerEUR: r.Rate})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ecb xml: no rates")
	}
	return out, nil
}

// FetchECB downloads and parses a feed.
func FetchECB(ctx context.Context, c *http.Client, url string) ([]Rate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ecb: HTTP %d", res.StatusCode)
	}
	return ParseECB(io.LimitReader(res.Body, 8<<20))
}

// Saver stores rates in the home Tenant (reference data; read through the
// fx_convert function by every Tenant).
type Saver interface {
	SaveRates(ctx context.Context, rates []Rate) (int, error)
}
