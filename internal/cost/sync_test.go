package cost_test

import (
	"archive/zip"
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

func TestBillSyncSkipsNonFOCUSFiles(t *testing.T) {
	w := setup(t)
	objs := &memObjects{objs: map[string][]byte{
		"bills/2026-09-01.csv": splitByDay(t, "01", "02"),
		"bills/cost-allocation-2026-09.csv": []byte("PayerUin,OwnerUin,BusinessCodeName,ProductCodeName,BillMonth,RealTotalCost\n" +
			"200045645249,100001,CVM,Standard S5,2026-09,99.00\n"),
	}}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}
	rep, err := bs.Run(context.Background())
	must(t, err)
	if rep.NewFiles != 1 || len(rep.NotFOCUS) != 1 || rep.NotFOCUS[0] != "bills/cost-allocation-2026-09.csv" {
		t.Fatalf("run %+v", rep)
	}
	if got := billedTotal(t, w); got != "42.80" {
		t.Fatalf("billed = %s, want the FOCUS file alone (42.80)", got)
	}
	skips := func() int {
		var n int
		must(t, w.s.InTenant(context.Background(), w.home, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT count(*) FROM activities WHERE type = 'keel.cost.bill_file_skipped' AND subject LIKE '%cost-allocation-2026-09.csv@'`).Scan(&n)
		}))
		return n
	}
	if n := skips(); n != 1 {
		t.Fatalf("skip activities = %d, want 1", n)
	}

	rep, err = bs.Run(context.Background())
	must(t, err)
	if len(rep.NotFOCUS) != 0 || skips() != 1 {
		t.Fatalf("second run re-reported the skipped file: %+v, activities %d", rep, skips())
	}
}

func TestBillSyncFailsOnMalformedFOCUSFile(t *testing.T) {
	w := setup(t)
	bad := strings.Replace(string(splitByDay(t, "01")), "SubAccountId", "SubAccount", 1)
	objs := &memObjects{objs: map[string][]byte{"bills/2026-09-01.csv": []byte(bad)}}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}
	if _, err := bs.Run(context.Background()); err == nil || errors.Is(err, cost.ErrNotFOCUS) {
		t.Fatalf("err = %v, want a malformed-FOCUS failure", err)
	}
}

func zipped(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	must(t, err)
	_, err = w.Write(body)
	must(t, err)
	must(t, zw.Close())
	return buf.Bytes()
}

func skipActivities(t *testing.T, w world, key string) int {
	t.Helper()
	var n int
	must(t, w.s.InTenant(context.Background(), w.home, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM activities WHERE type = 'keel.cost.bill_file_skipped' AND subject LIKE '%/' || $1 || '@'`, key).Scan(&n)
	}))
	return n
}

func TestBillSyncSkipsCostAllocationFOCUSBill(t *testing.T) {
	w := setup(t)
	alloc := "bills/200045645249-20260902-FOCUS-Cost Allocation Bill-Component-detail.zip"
	objs := &memObjects{objs: map[string][]byte{
		"bills/200045645249-20260902-by_used_time-FOCUS-Bill Details.zip": zipped(t, "bill.csv", splitByDay(t, "01", "02")),
		alloc: zipped(t, "bill.csv", splitByDay(t, "01", "02")),
	}}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}
	rep, err := bs.Run(context.Background())
	must(t, err)
	if rep.NewFiles != 1 || len(rep.NotFOCUS) != 1 || rep.NotFOCUS[0] != alloc {
		t.Fatalf("run %+v", rep)
	}
	if got := billedTotal(t, w); got != "42.80" {
		t.Fatalf("billed = %s, want the standard bill alone (42.80)", got)
	}
	rep, err = bs.Run(context.Background())
	must(t, err)
	if len(rep.NotFOCUS) != 0 || skipActivities(t, w, alloc) != 1 {
		t.Fatalf("second run re-reported the allocation bill: %+v, activities %d", rep, skipActivities(t, w, alloc))
	}
}

func TestBillSyncSkipsZipWithoutCSV(t *testing.T) {
	w := setup(t)
	pack := "bills/200045645249-202609-by_used_time-bill_pack.zip"
	objs := &memObjects{objs: map[string][]byte{
		"bills/2026-09-01.zip": zipped(t, "BILL.CSV", splitByDay(t, "01", "02")),
		pack:                   zipped(t, "bill.xlsx", []byte("not a csv")),
	}}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}
	rep, err := bs.Run(context.Background())
	must(t, err)
	if rep.NewFiles != 1 || len(rep.NotFOCUS) != 1 || rep.NotFOCUS[0] != pack {
		t.Fatalf("run %+v", rep)
	}
	if got := billedTotal(t, w); got != "42.80" {
		t.Fatalf("billed = %s, want the upper-case .CSV zip loaded (42.80)", got)
	}
	rep, err = bs.Run(context.Background())
	must(t, err)
	if len(rep.NotFOCUS) != 0 || skipActivities(t, w, pack) != 1 {
		t.Fatalf("second run re-reported the zip: %+v, activities %d", rep, skipActivities(t, w, pack))
	}
}

func TestBillSyncPerDayOverlapFailsClosed(t *testing.T) {
	w := setup(t)
	day1 := "bills/200045645249-20260901-by_used_time-FOCUS-Bill Details.zip"
	mtd := "bills/200045645249-20260902-by_used_time-FOCUS-Bill Details.zip"
	objs := &memObjects{objs: map[string][]byte{day1: zipped(t, "bill.csv", splitByDay(t, "01"))}}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}
	_, err := bs.Run(context.Background())
	must(t, err)
	if got := billedTotal(t, w); got != "36.40" {
		t.Fatalf("after day 1 billed = %s", got)
	}

	objs.objs[mtd] = zipped(t, "bill.csv", splitByDay(t, "01", "02")) // month-to-date: repeats day 1
	objs.objs["bills/2026-08-01.csv"] = []byte(strings.ReplaceAll(string(splitByDay(t, "01")), "2026-09-", "2026-08-"))
	rep, err := bs.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), day1) || !strings.Contains(err.Error(), mtd) ||
		!strings.Contains(err.Error(), "files overlap; check KEEL_TENCENT_BILL_MODE or the bill types delivered to the prefix") {
		t.Fatalf("err = %v, want an overlap failure naming both files", err)
	}
	if got := sum(t, w, w.tat, "billing_period = '2026-09-01'"); got != "36.40" {
		t.Fatalf("September billed = %s, want the day 1 load kept current (36.40), not 79.20", got)
	}
	if len(rep.Loads) != 1 || !rep.Loads[0].Period.Equal(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("loads %+v, want only August loaded", rep.Loads)
	}
	var n int
	must(t, w.s.InTenant(context.Background(), w.home, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM activities WHERE type = 'keel.cost.bill_files_overlap' AND subject = 'cost_period/tencent/200045645249/2026-09' AND status_id = 2 AND event::text LIKE '%files overlap%'`).Scan(&n)
	}))
	if n != 1 {
		t.Fatalf("overlap activities = %d, want 1", n)
	}
}
