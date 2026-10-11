package cost_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"slices"
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

// oneLine returns the fixture's first row (sub-account 200046202634, 1.20)
// charged over [start, end).
func oneLine(t *testing.T, start, end string) []byte {
	t.Helper()
	recs, err := csv.NewReader(bytes.NewReader(fixture(t))).ReadAll()
	must(t, err)
	row := slices.Clone(recs[1])
	for i, h := range recs[0] {
		switch h {
		case "ChargePeriodStart":
			row[i] = start
		case "ChargePeriodEnd":
			row[i] = end
		}
	}
	var buf bytes.Buffer
	must(t, csv.NewWriter(&buf).WriteAll([][]string{recs[0], row}))
	return buf.Bytes()
}

func TestBillSyncPerDayOverlapMeansTheSameChargeInterval(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string][]byte
		billed  string
		overlap bool
	}{{
		// Adjacent Beijing days whose hourly lines share a UTC date.
		name: "hourly lines on one UTC date, disjoint in time",
		files: map[string][]byte{
			"bills/200045645249-20260901-FOCUS.csv": oneLine(t, "2026-09-01T18:00:00+08:00", "2026-09-01T19:00:00+08:00"),
			"bills/200045645249-20260902-FOCUS.csv": oneLine(t, "2026-09-02T04:00:00+08:00", "2026-09-02T05:00:00+08:00"),
		},
		billed: "2.40",
	}, {
		name: "the same hour in two files",
		files: map[string][]byte{
			"bills/200045645249-20260901-FOCUS.csv": oneLine(t, "2026-09-01T18:00:00+08:00", "2026-09-01T19:00:00+08:00"),
			"bills/200045645249-20260902-FOCUS.csv": oneLine(t, "2026-09-01T10:00:00Z", "2026-09-01T11:00:00Z"),
		},
		overlap: true,
	}, {
		name: "a daily line restated by a later file",
		files: map[string][]byte{
			"bills/2026-09-02.csv":            splitByDay(t, "02"),
			"bills/2026-09-02-correction.csv": splitByDay(t, "02"),
		},
		overlap: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			w := setup(t)
			bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: &memObjects{objs: tc.files}, Provider: "tencent", BillingAccountID: "200045645249",
				Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}
			_, err := bs.Run(context.Background())
			if tc.overlap {
				if err == nil || !strings.Contains(err.Error(), "files overlap") {
					t.Fatalf("err = %v, want an overlap failure", err)
				}
				if got := billedTotal(t, w); got != "0" {
					t.Fatalf("billed = %s, want nothing loaded", got)
				}
				return
			}
			must(t, err)
			if got := sum(t, w, w.tat, "true"); got != tc.billed {
				t.Fatalf("billed = %s, want %s from both files", got, tc.billed)
			}
		})
	}
}

func TestBillSyncBlockedPeriodRaisesOneFindingThenResolves(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	day1 := "bills/200045645249-20260901-by_used_time-FOCUS-Bill Details.zip"
	mtd := "bills/200045645249-20260902-by_used_time-FOCUS-Bill Details.zip"
	objs := &memObjects{objs: map[string][]byte{
		day1: zipped(t, "bill.csv", splitByDay(t, "01")),
		mtd:  zipped(t, "bill.csv", splitByDay(t, "01", "02")),
	}}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) // past Tencent finality: every run retries the period
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return now }}
	const fp = "bill_sync_blocked:tencent/200045645249/2026-09"
	type finding struct {
		kind, severity, status, title string
		team                          *string
		firstSeen                     time.Time
		resolvedAt                    *time.Time
	}
	findings := func() []finding {
		t.Helper()
		var out []finding
		must(t, w.s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT kind, severity, status, title, owner_team_id::text, first_seen_at, resolved_at FROM findings WHERE fingerprint = $1 ORDER BY first_seen_at`, fp)
			if err != nil {
				return err
			}
			out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (finding, error) {
				var f finding
				return f, r.Scan(&f.kind, &f.severity, &f.status, &f.title, &f.team, &f.firstSeen, &f.resolvedAt)
			})
			return err
		}))
		return out
	}
	activities := func() int {
		t.Helper()
		var n int
		must(t, w.s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM activities WHERE type = 'keel.cost.bill_files_overlap'`).Scan(&n)
		}))
		return n
	}

	_, err := bs.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "files overlap") {
		t.Fatalf("first run err = %v, want an overlap failure", err)
	}
	fs := findings()
	if len(fs) != 1 {
		t.Fatalf("findings = %+v, want one", fs)
	}
	f := fs[0]
	if f.kind != "bill_sync_blocked" || f.severity != "high" || f.status != "open" || f.team != nil || !f.firstSeen.Equal(now) ||
		!strings.Contains(f.title, day1) || !strings.Contains(f.title, mtd) || !strings.Contains(f.title, "KEEL_TENCENT_BILL_MODE") || strings.Contains(f.title, "client_payers.mode") {
		t.Fatalf("finding = %+v", f)
	}

	now = now.Add(time.Hour)
	rep, err := bs.Run(ctx)
	if err != nil {
		t.Fatalf("unchanged overlap re-alerted: %v", err)
	}
	if !slices.Equal(rep.Blocked, []string{"2026-09"}) {
		t.Fatalf("blocked = %v, want 2026-09", rep.Blocked)
	}
	if n := activities(); n != 1 {
		t.Fatalf("overlap activities after two runs = %d, want 1", n)
	}
	if fs := findings(); len(fs) != 1 || fs[0].status != "open" {
		t.Fatalf("findings after second run = %+v, want the one still open", fs)
	}

	objs.objs["bills/200045645249-20260903-FOCUS.csv"] = oneLine(t, "2026-09-03T00:00:00Z", "2026-09-04T00:00:00Z")
	if _, err := bs.Run(ctx); err == nil {
		t.Fatal("a changed file set should alert again")
	}
	if n := activities(); n != 2 {
		t.Fatalf("overlap activities after the file set changed = %d, want 2", n)
	}

	delete(objs.objs, mtd)
	now = now.Add(time.Hour)
	rep, err = bs.Run(ctx)
	must(t, err)
	if len(rep.Loads) != 1 || len(rep.Blocked) != 0 {
		t.Fatalf("after removing the month-to-date file %+v", rep)
	}
	fs = findings()
	if len(fs) != 1 || fs[0].status != "resolved" || fs[0].resolvedAt == nil || !fs[0].resolvedAt.Equal(now) {
		t.Fatalf("findings after a good load = %+v, want resolved at %s", fs, now)
	}
}
