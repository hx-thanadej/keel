package cost

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ParseOpenCost reads an OpenCost /allocation response aggregated by
// namespace with step=1d into day → namespace → total cost.
func ParseOpenCost(raw []byte) (map[time.Time]map[string]float64, error) {
	var resp struct {
		Code int `json:"code"`
		Data []map[string]struct {
			Name   string `json:"name"`
			Window struct {
				Start time.Time `json:"start"`
			} `json:"window"`
			TotalCost float64 `json:"totalCost"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("opencost: %w", err)
	}
	if resp.Code != 0 && resp.Code != http.StatusOK {
		return nil, fmt.Errorf("opencost: code %d", resp.Code)
	}
	out := map[time.Time]map[string]float64{}
	for _, step := range resp.Data {
		for ns, a := range step {
			d := a.Window.Start.UTC()
			d = time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC)
			if out[d] == nil {
				out[d] = map[string]float64{}
			}
			out[d][ns] += a.TotalCost
		}
	}
	return out, nil
}

// FetchOpenCost asks an OpenCost endpoint for per-namespace daily cost in [from, to).
func FetchOpenCost(ctx context.Context, c *http.Client, base string, from, to time.Time) (map[time.Time]map[string]float64, error) {
	q := url.Values{"window": {from.UTC().Format(time.RFC3339) + "," + to.UTC().Format(time.RFC3339)}, "aggregate": {"namespace"}, "step": {"1d"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/allocation?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opencost: HTTP %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	return ParseOpenCost(raw)
}
