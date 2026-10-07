package cost_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
)

type memObjects struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func (m *memObjects) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memObjects) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objs[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return b, nil
}

// splitByDay returns fixture rows whose ChargePeriodStart day is in days, as CSV.
func splitByDay(t *testing.T, days ...string) []byte {
	t.Helper()
	recs, err := csv.NewReader(bytes.NewReader(fixture(t))).ReadAll()
	must(t, err)
	col := map[string]int{}
	for i, h := range recs[0] {
		col[h] = i
	}
	out := [][]string{recs[0]}
	for _, r := range recs[1:] {
		for _, d := range days {
			if strings.HasPrefix(r[col["ChargePeriodStart"]], "2026-09-"+d) {
				out = append(out, r)
			}
		}
	}
	var buf bytes.Buffer
	must(t, csv.NewWriter(&buf).WriteAll(out))
	return buf.Bytes()
}

type fakeInvoices struct{ total string }

func (f fakeInvoices) InvoiceTotal(context.Context, string, time.Time) (string, bool, error) {
	return f.total, true, nil
}

func billedTotal(t *testing.T, w world) string {
	return sum(t, w, w.tat, "true")
}

func TestBillSyncPerDayFilesThenFinal(t *testing.T) {
	w := setup(t)
	objs := &memObjects{objs: map[string][]byte{}}
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Invoices: fakeInvoices{total: "46.80"}, Now: func() time.Time { return now }}

	objs.objs["bills/2026-09-01.csv"] = splitByDay(t, "01")
	rep, err := bs.Run(context.Background())
	must(t, err)
	if rep.NewFiles != 1 || len(rep.Loads) != 1 || rep.Loads[0].Final {
		t.Fatalf("first run %+v", rep)
	}
	if got := billedTotal(t, w); got != "36.40" { // day 1: dev 1.20 + prod 4.80 + 0.40 + 30.00
		t.Fatalf("after day 1 billed = %s", got)
	}

	objs.objs["bills/2026-09-02.csv"] = splitByDay(t, "02")
	rep, err = bs.Run(context.Background())
	must(t, err)
	if rep.NewFiles != 1 || len(rep.Loads) != 1 {
		t.Fatalf("second run %+v", rep)
	}
	if got := billedTotal(t, w); got != "42.80" {
		t.Fatalf("after day 2 billed = %s, want both days", got)
	}
	if rep.Loads[0].Reconcile != "ok" {
		t.Errorf("reconcile = %q, want ok (46.80 incl. unallocated)", rep.Loads[0].Reconcile)
	}

	// Nothing new, not yet final: no load.
	rep, err = bs.Run(context.Background())
	must(t, err)
	if len(rep.Loads) != 0 {
		t.Fatalf("idle run loaded %+v", rep.Loads)
	}

	// Past Tencent's finality time: a final load, then the period is frozen.
	now = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	rep, err = bs.Run(context.Background())
	must(t, err)
	if len(rep.Loads) != 1 || !rep.Loads[0].Final {
		t.Fatalf("finalising run %+v", rep)
	}
	objs.objs["bills/2026-09-late.csv"] = splitByDay(t, "02")
	rep, err = bs.Run(context.Background())
	must(t, err)
	if len(rep.Loads) != 0 || len(rep.Skipped) != 1 {
		t.Fatalf("file after final should be skipped, got %+v", rep)
	}
	if got := billedTotal(t, w); got != "42.80" {
		t.Fatalf("frozen total changed: %s", got)
	}
}

func TestBillSyncCumulativeTakesLatestFile(t *testing.T) {
	w := setup(t)
	objs := &memObjects{objs: map[string][]byte{
		"bills/2026-09-01.csv": splitByDay(t, "01"),
		"bills/2026-09-02.csv": splitByDay(t, "01", "02"), // month-to-date
	}}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.CumulativeFiles, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}
	_, err := bs.Run(context.Background())
	must(t, err)
	if got := billedTotal(t, w); got != "42.80" {
		t.Fatalf("cumulative billed = %s, want 42.80 (not double-counted)", got)
	}
}

func TestReconcileMismatchRecorded(t *testing.T) {
	w := setup(t)
	objs := &memObjects{objs: map[string][]byte{"bills/all.csv": fixture(t)}}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Invoices: fakeInvoices{total: "50.00"}, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}
	rep, err := bs.Run(context.Background())
	must(t, err)
	if rep.Loads[0].Reconcile != "mismatch" {
		t.Fatalf("reconcile = %q, want mismatch", rep.Loads[0].Reconcile)
	}
	var status, diff string
	must(t, w.s.InTenant(context.Background(), w.home, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT reconcile_status, reconcile_diff::text FROM cost_loads WHERE id = $1`, rep.Loads[0].LoadID).Scan(&status, &diff)
	}))
	if status != "mismatch" || diff != "-3.200000" {
		t.Errorf("stored %s %s", status, diff)
	}
}
