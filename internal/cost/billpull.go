package cost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// BillDetails pulls a payer's whole month of bill lines from a provider's
// billing API. It returns every line or an error, never a partial month.
type BillDetails interface {
	MonthLines(ctx context.Context, payer string, month time.Time) ([]Line, error)
}

// BillPull keeps a payer's loads current from a billing API instead of bill
// files (#252). Each run pulls the current and the previous month, unless
// that month already has a final load. A pull whose lines match the current
// load, and whose finality has not changed, makes no load. Loads, finality,
// reconciliation and bill_sync_blocked Findings behave as in BillSync.
type BillPull struct {
	Ingester         *Ingester
	Details          BillDetails
	Provider         string
	BillingAccountID string
	Invoices         InvoiceSource // optional
	Now              func() time.Time
}

// PullReport summarises a pull run.
type PullReport struct {
	Loads     []SyncedLoad `json:"loads"`
	Unchanged []string     `json:"unchanged"` // periods (YYYY-MM) whose pull matched the current load
	Empty     []string     `json:"empty"`     // periods with no lines yet
}

// Run pulls and loads each open month. A failed pull leaves that month's
// current load in place and is returned, joined, after the other months run.
func (b *BillPull) Run(ctx context.Context) (PullReport, error) {
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	var rep PullReport
	home, err := homeTenant(ctx, b.Ingester.Store)
	if err != nil {
		return rep, err
	}
	bs := &BillSync{Ingester: b.Ingester, Provider: b.Provider, BillingAccountID: b.BillingAccountID, Invoices: b.Invoices}
	// Tencent's months are UTC+8 months (finality.go).
	local := now().In(beijing)
	current := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, time.UTC)
	var failed []error
	for _, p := range []time.Time{current.AddDate(0, -1, 0), current} {
		month := p.Format("2006-01")
		var source string
		var loaded, wasFinal bool
		err := b.Ingester.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
			err := tx.QueryRow(ctx, `SELECT source, is_final FROM cost_loads WHERE provider = $1 AND billing_account_id = $2 AND billing_period = $3 AND superseded_at IS NULL
				ORDER BY loaded_at DESC LIMIT 1`, b.Provider, b.BillingAccountID, p).Scan(&source, &wasFinal)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			loaded = err == nil
			return err
		})
		if err != nil {
			return rep, err
		}
		if wasFinal {
			continue
		}
		lines, err := b.Details.MonthLines(ctx, b.BillingAccountID, p)
		if err != nil {
			failed = append(failed, fmt.Errorf("pull %s: %w", month, err))
			continue
		}
		if len(lines) == 0 {
			rep.Empty = append(rep.Empty, month)
			continue
		}
		final := PeriodFinal(b.Provider, p, now(), false)
		src := pullSource(month, lines)
		if loaded && src == source && !final {
			rep.Unchanged = append(rep.Unchanged, month)
			continue
		}
		res, err := b.Ingester.Load(ctx, Load{Provider: b.Provider, BillingAccountID: b.BillingAccountID, BillingPeriod: p,
			Source: src, Final: final, Lines: lines})
		if errors.Is(err, ErrPeriodFinal) {
			continue
		}
		if err != nil {
			return rep, fmt.Errorf("load %s: %w", month, err)
		}
		if err := bs.resolveBlocked(ctx, home, p, now()); err != nil {
			return rep, err
		}
		sl := SyncedLoad{LoadID: res.LoadID, Period: p, Final: final, Lines: res.Lines, Dropped: res.Dropped, Unallocated: res.Unallocated, Reconcile: "pending"}
		if b.Invoices != nil {
			if sl.Reconcile, err = bs.reconcile(ctx, home, res.LoadID, p); err != nil {
				return rep, err
			}
		}
		rep.Loads = append(rep.Loads, sl)
	}
	return rep, errors.Join(failed...)
}

// pullSource names a pull by its month and a digest of its lines, in any
// order, so an unchanged bill is recognised on the next run.
func pullSource(month string, lines []Line) string {
	enc := make([]string, len(lines))
	for i, l := range lines {
		b, _ := json.Marshal(l)
		enc[i] = string(b)
	}
	slices.Sort(enc)
	h := sha256.New()
	for _, e := range enc {
		h.Write([]byte(e))
		h.Write([]byte{'\n'})
	}
	return "api:DescribeBillDetail/" + month + "@sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}
