package cost

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
)

// FileMode says how a provider's bill files make up a billing period. Which
// one Tencent uses must be confirmed on the first real delivery (#29).
type FileMode int

const (
	// PerDayFiles: each file holds different lines; a period is all its files.
	PerDayFiles FileMode = iota
	// CumulativeFiles: each file is month-to-date; a period is its newest file.
	CumulativeFiles
	// LatestExportFolder: an export run writes one or more part files to a
	// folder, overwriting in place or in a new folder (AWS Data Exports); a
	// period is the current version of every file in its newest folder.
	LatestExportFolder
)

// ObjectInfo is an object key and its ETag (content version).
type ObjectInfo struct {
	Key, ETag string
}

// ETagLister is implemented by stores that report ETags (S3, COS). With it,
// a file rewritten under the same key is picked up as a new version.
type ETagLister interface {
	ListWithETag(ctx context.Context, prefix string) ([]ObjectInfo, error)
}

// Objects lists and reads bill files (e.g. a COS bucket via archive.S3).
type Objects interface {
	List(ctx context.Context, prefix string) ([]string, error)
	Get(ctx context.Context, key string) ([]byte, error)
}

// InvoiceSource returns a payer's invoiced total for a month.
type InvoiceSource interface {
	InvoiceTotal(ctx context.Context, billingAccountID string, period time.Time) (total string, ready bool, err error)
}

// BillSync picks up a provider's bill files and keeps loads current (#33).
type BillSync struct {
	Ingester         *Ingester
	Objects          Objects
	Provider         string
	BillingAccountID string
	Prefix           string
	Mode             FileMode
	Invoices         InvoiceSource // optional
	Now              func() time.Time
}

// SyncedLoad reports one load made by a sync run.
type SyncedLoad struct {
	LoadID    string    `json:"load_id"`
	Period    time.Time `json:"period"`
	Final     bool      `json:"final"`
	Lines     int       `json:"lines"`
	Reconcile string    `json:"reconcile"`
}

// SyncReport summarises a run.
type SyncReport struct {
	NewFiles int          `json:"new_files"`
	Loads    []SyncedLoad `json:"loads"`
	Skipped  []string     `json:"skipped"` // files for already-final periods
}

var billExt = []string{".csv", ".csv.gz", ".gz", ".zip", ".parquet"}

// Run loads every period with new files, and finalises periods whose
// provider finality time has passed.
func (b *BillSync) Run(ctx context.Context) (SyncReport, error) {
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	var rep SyncReport
	home, err := b.home(ctx)
	if err != nil {
		return rep, err
	}
	var objects []ObjectInfo
	if el, ok := b.Objects.(ETagLister); ok {
		objects, err = el.ListWithETag(ctx, b.Prefix)
	} else {
		var keys []string
		keys, err = b.Objects.List(ctx, b.Prefix)
		for _, k := range keys {
			objects = append(objects, ObjectInfo{Key: k})
		}
	}
	if err != nil {
		return rep, fmt.Errorf("list bills: %w", err)
	}
	type fileInfo struct {
		key, etag string
		period    time.Time
		seen      time.Time
	}
	var known []fileInfo
	finalPeriods := map[time.Time]bool{}
	err = b.Ingester.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT object_key, etag, billing_period, seen_at FROM cost_source_files WHERE provider = $1 AND billing_account_id = $2 ORDER BY seen_at`, b.Provider, b.BillingAccountID)
		if err != nil {
			return err
		}
		known, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (fileInfo, error) {
			var f fileInfo
			err := r.Scan(&f.key, &f.etag, &f.period, &f.seen)
			f.period = f.period.UTC()
			return f, err
		})
		if err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT billing_period FROM cost_loads WHERE provider = $1 AND billing_account_id = $2 AND is_final`, b.Provider, b.BillingAccountID)
		if err != nil {
			return err
		}
		ps, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
		for _, p := range ps {
			finalPeriods[p.UTC()] = true
		}
		return err
	})
	if err != nil {
		return rep, err
	}
	seen := map[string]bool{}
	for _, f := range known {
		seen[f.key+"\x00"+f.etag] = true
	}
	current := map[string]string{} // key → ETag as listed now
	for _, o := range objects {
		current[o.Key] = o.ETag
	}

	// Register new files (or new versions) under the periods their lines belong to.
	touched := map[time.Time]bool{}
	for _, o := range objects {
		key := o.Key
		if seen[key+"\x00"+o.ETag] || !slices.ContainsFunc(billExt, func(e string) bool { return strings.HasSuffix(strings.ToLower(key), e) }) {
			continue
		}
		raw, err := b.Objects.Get(ctx, key)
		if err != nil {
			return rep, fmt.Errorf("get %s: %w", key, err)
		}
		lines, err := ParseFOCUS(raw)
		if err != nil {
			return rep, fmt.Errorf("%s: %w", key, err)
		}
		counts := map[time.Time]int{}
		for _, l := range lines {
			counts[monthOf(l.BillingPeriodStart)]++
		}
		err = b.Ingester.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
			for p, n := range counts {
				if _, err := tx.Exec(ctx, `INSERT INTO cost_source_files (tenant_id, provider, billing_account_id, object_key, etag, billing_period, line_count) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
					home, b.Provider, b.BillingAccountID, key, o.ETag, p, n); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return rep, err
		}
		rep.NewFiles++
		for p := range counts {
			known = append(known, fileInfo{key: key, etag: o.ETag, period: p, seen: now()})
			if finalPeriods[p] {
				rep.Skipped = append(rep.Skipped, key)
			} else {
				touched[p] = true
			}
		}
	}
	// Periods that have become final need one last load.
	for _, f := range known {
		if !finalPeriods[f.period] && PeriodFinal(b.Provider, f.period, now(), false) {
			touched[f.period] = true
		}
	}

	periods := make([]time.Time, 0, len(touched))
	for p := range touched {
		periods = append(periods, p)
	}
	slices.SortFunc(periods, func(a, b time.Time) int { return a.Compare(b) })
	for _, p := range periods {
		// Files of this period that still exist, each at its current version.
		var files []string
		var newestSeen time.Time
		newestDir := ""
		for _, f := range known {
			if f.period.Equal(p) && !slices.Contains(files, f.key) {
				if etag, ok := current[f.key]; ok && etag == f.etag {
					files = append(files, f.key)
					// Export folders are named by run id (Azure) or
					// overwritten in place (AWS), so the newest folder is
					// the one Keel saw most recently, not the last by name.
					if d := path.Dir(f.key); f.seen.After(newestSeen) || (f.seen.Equal(newestSeen) && d > newestDir) {
						newestSeen, newestDir = f.seen, d
					}
				}
			}
		}
		slices.Sort(files)
		if len(files) == 0 {
			continue
		}
		switch b.Mode {
		case CumulativeFiles:
			files = files[len(files)-1:]
		case LatestExportFolder:
			files = slices.DeleteFunc(files, func(k string) bool { return path.Dir(k) != newestDir })
		}
		var lines []Line
		invoiced := true
		for _, key := range files {
			raw, err := b.Objects.Get(ctx, key)
			if err != nil {
				return rep, fmt.Errorf("get %s: %w", key, err)
			}
			ls, err := ParseFOCUS(raw)
			if err != nil {
				return rep, fmt.Errorf("%s: %w", key, err)
			}
			for _, l := range ls {
				if monthOf(l.BillingPeriodStart).Equal(p) {
					lines = append(lines, l)
					invoiced = invoiced && l.InvoiceID != ""
				}
			}
		}
		final := PeriodFinal(b.Provider, p, now(), invoiced && len(lines) > 0)
		res, err := b.Ingester.Load(ctx, Load{Provider: b.Provider, BillingAccountID: b.BillingAccountID, BillingPeriod: p,
			Source: strings.Join(files, ","), Final: final, Lines: lines})
		if errors.Is(err, ErrPeriodFinal) {
			continue
		}
		if err != nil {
			return rep, fmt.Errorf("load %s: %w", p.Format("2006-01"), err)
		}
		sl := SyncedLoad{LoadID: res.LoadID, Period: p, Final: final, Lines: res.Lines, Reconcile: "pending"}
		if b.Invoices != nil {
			if sl.Reconcile, err = b.reconcile(ctx, home, res.LoadID, p); err != nil {
				return rep, err
			}
		}
		rep.Loads = append(rep.Loads, sl)
	}
	return rep, nil
}

func monthOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func (b *BillSync) home(ctx context.Context) (string, error) {
	var home *string
	if err := b.Ingester.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil || home == nil {
		return "", errors.New("bill sync needs a home tenant")
	}
	return *home, nil
}

// Tolerance is the largest relative difference between Keel's billed total
// and the provider invoice that still counts as reconciled.
const Tolerance = 0.005

// reconcile compares a load's billed total with the provider's invoice and
// records the outcome on the load and as an Activity.
func (b *BillSync) reconcile(ctx context.Context, home, loadID string, period time.Time) (string, error) {
	invoice, ready, err := b.Invoices.InvoiceTotal(ctx, b.BillingAccountID, period)
	status, detail := "unavailable", ""
	var invTotal, diff *string
	if err == nil {
		inv, ok := new(big.Rat).SetString(invoice)
		if !ok {
			err = fmt.Errorf("invoice total %q is not a decimal", invoice)
		} else {
			invTotal = &invoice
			status = "not_ready"
			if ready {
				status = "ok"
			}
			var total string
			if qerr := b.Ingester.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT total_billed::text FROM cost_loads WHERE id = $1`, loadID).Scan(&total)
			}); qerr != nil {
				return "", qerr
			}
			ours, _ := new(big.Rat).SetString(total)
			d := new(big.Rat).Sub(ours, inv)
			ds := d.FloatString(6)
			diff = &ds
			if ready && inv.Sign() != 0 {
				rel, _ := new(big.Rat).Abs(new(big.Rat).Quo(d, inv)).Float64()
				if rel > Tolerance {
					status = "mismatch"
				}
			}
			detail = fmt.Sprintf("keel %s vs invoice %s (diff %s)", total, invoice, ds)
		}
	}
	if err != nil {
		detail = err.Error()
	}
	outcome := activity.Success
	if status == "mismatch" || status == "unavailable" {
		outcome = activity.Failure
	}
	return status, b.Ingester.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE cost_loads SET invoice_total = $2::numeric, invoice_ready = $3, reconcile_status = $4, reconcile_diff = $5::numeric, reconciled_at = now() WHERE id = $1`,
			loadID, invTotal, ready, status, diff); err != nil {
			return err
		}
		_, err := activity.Record(ctx, tx, activity.Activity{TenantID: home, Source: "keel/cost", Type: "keel.cost.reconciled",
			Subject: "cost_load/" + loadID, Operation: "ReconcileInvoice", Kind: activity.Read, Actor: actor, Outcome: outcome,
			StatusDetail: status + ": " + detail})
		return err
	})
}
