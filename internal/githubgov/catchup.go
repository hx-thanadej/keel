package githubgov

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/jackc/pgx/v5"
)

// maxAttempts bounds how often one delivery is tried, so a payload Keel
// keeps rejecting stops being resent. The hourly reconcile still reports
// its end state.
const maxAttempts = 3

// Catchup asks GitHub to redeliver organisation webhook deliveries Keel
// missed (#226). GitHub does not retry a failed delivery on its own. The
// job keeps no cursor: webhook_deliveries makes a redelivery Keel already
// recorded a 200 duplicate, and the attempt history decides the rest.
type Catchup struct {
	Store   *store.Store
	Org     string
	HookID  int64
	Token   func(ctx context.Context) (string, error) // a short-lived token with organisation webhooks write
	BaseURL string                                    // default https://api.github.com
	HTTP    *http.Client                              // nil uses http.DefaultClient, which never times out
	Window  time.Duration                             // how far back to look; wider than the run interval
	Pause   time.Duration                             // between redeliveries, for GitHub's secondary rate limits
	Now     func() time.Time                          // defaults to time.Now
}

// CatchupResult counts one run.
type CatchupResult struct {
	Attempts, Missed, Redelivered int
}

type hookAttempt struct {
	ID          int64     `json:"id"`
	GUID        string    `json:"guid"`
	DeliveredAt time.Time `json:"delivered_at"`
	Redelivery  bool      `json:"redelivery"`
	StatusCode  int       `json:"status_code"`
	Event       string    `json:"event"`
}

// delivery is every attempt GitHub made for one X-GitHub-Delivery guid.
type delivery struct {
	original  *hookAttempt
	attempts  int
	succeeded bool
}

// Run redelivers each delivery first sent within Window that no attempt
// delivered, that Keel has not recorded, and that has had fewer than
// maxAttempts tries. It stops at the first rate-limit response.
func (c Catchup) Run(ctx context.Context) (CatchupResult, error) {
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	tok, err := c.Token(ctx)
	if err != nil {
		return CatchupResult{}, fmt.Errorf("installation token: %w", err)
	}
	gh := ghapi.Client{BaseURL: c.BaseURL, Token: tok, HTTP: c.HTTP}
	hook := fmt.Sprintf("/orgs/%s/hooks/%d/deliveries", url.PathEscape(c.Org), c.HookID)
	byGUID, res, err := c.list(ctx, gh, hook, now.Add(-c.Window))
	if err != nil {
		return res, err
	}
	var missed []*hookAttempt
	for _, d := range byGUID {
		if d.original != nil && !d.succeeded && d.attempts < maxAttempts {
			missed = append(missed, d.original)
		}
	}
	recorded, err := c.recorded(ctx, missed)
	if err != nil {
		return res, err
	}
	missed = slices.DeleteFunc(missed, func(a *hookAttempt) bool { return recorded[a.GUID] })
	slices.SortFunc(missed, func(a, b *hookAttempt) int { return a.DeliveredAt.Compare(b.DeliveredAt) })
	res.Missed = len(missed)
	for i, a := range missed {
		if i > 0 && c.Pause > 0 {
			select {
			case <-ctx.Done():
				return res, ctx.Err()
			case <-time.After(c.Pause):
			}
		}
		err := gh.Do(ctx, http.MethodPost, fmt.Sprintf("%s/%d/attempts", hook, a.ID), nil, nil)
		if st := ghapi.Status(err); st == http.StatusForbidden || st == http.StatusTooManyRequests {
			return res, fmt.Errorf("redeliver %s: rate limited: %w", a.GUID, err)
		}
		if err != nil {
			slog.Error("github webhook catch-up", "delivery", a.GUID, "event", a.Event, "err", err)
			continue
		}
		slog.Info("github webhook redelivered", "delivery", a.GUID, "event", a.Event, "first_attempt", a.DeliveredAt)
		res.Redelivered++
	}
	return res, nil
}

// list reads the hook's attempts, newest first, back to since.
func (c Catchup) list(ctx context.Context, gh ghapi.Client, hook string, since time.Time) (map[string]*delivery, CatchupResult, error) {
	var res CatchupResult
	byGUID := map[string]*delivery{}
	for next := hook + "?per_page=100"; next != ""; {
		var page []hookAttempt
		var err error
		if next, err = gh.DoList(ctx, next, &page); err != nil {
			return nil, res, err
		}
		for _, a := range page {
			if a.DeliveredAt.Before(since) {
				return byGUID, res, nil
			}
			res.Attempts++
			d := byGUID[a.GUID]
			if d == nil {
				d = &delivery{}
				byGUID[a.GUID] = d
			}
			d.attempts++
			d.succeeded = d.succeeded || (a.StatusCode >= 200 && a.StatusCode < 300)
			if !a.Redelivery {
				d.original = &a
			}
		}
	}
	return byGUID, res, nil
}

// recorded reports which guids Keel already wrote to webhook_deliveries,
// in any Tenant.
func (c Catchup) recorded(ctx context.Context, as []*hookAttempt) (map[string]bool, error) {
	out := map[string]bool{}
	if len(as) == 0 {
		return out, nil
	}
	guids := make([]string, len(as))
	for i, a := range as {
		guids[i] = a.GUID
	}
	rows, err := c.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return nil, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, t := range tenants {
		err := c.Store.InTenant(ctx, t, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT delivery_id FROM webhook_deliveries WHERE source = 'github' AND delivery_id = ANY($1)`, guids)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
			for _, id := range ids {
				out[id] = true
			}
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
