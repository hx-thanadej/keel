package cost_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
)

const secret = "SecretKey=AKIDsuper-secret-value"

func statusOf(t *testing.T, w world, tenant, provider, account string) cost.SyncStatus {
	t.Helper()
	all, err := cost.Queries{Store: w.s}.BillSync(context.Background(), tenant)
	must(t, err)
	for _, s := range all {
		if s.Provider == provider && s.BillingAccountID == account {
			return s
		}
	}
	t.Fatalf("no bill sync status for %s %s in tenant %s (have %+v)", provider, account, tenant, all)
	return cost.SyncStatus{}
}

func month(t *testing.T, s cost.SyncStatus, m string) cost.SyncMonth {
	t.Helper()
	for _, x := range s.Months {
		if x.Month == m {
			return x
		}
	}
	t.Fatalf("status has no month %s: %+v", m, s.Months)
	return cost.SyncMonth{}
}

// syncActivities returns the status_detail of every bill sync Activity in tenant, oldest first.
func syncActivities(t *testing.T, w world, tenant string) []string {
	t.Helper()
	var out []string
	must(t, w.s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT event::text FROM activities WHERE type = 'keel.cost.bill_sync_changed' ORDER BY seq`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}))
	return out
}

func noSecret(t *testing.T, w world, tenant string) {
	t.Helper()
	var status string
	must(t, w.s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT coalesce(string_agg(to_jsonb(b)::text, ''), '') FROM bill_sync_status b`).Scan(&status)
	}))
	for _, s := range append(syncActivities(t, w, tenant), status) {
		if strings.Contains(s, "secret") || strings.Contains(s, "AKID") {
			t.Errorf("bill sync status or Activity holds the provider's message: %s", s)
		}
	}
}

func TestBillPullRecordsEachMonthAndOneActivityPerChange(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", september())
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) // 08:00 in Beijing: September is not final yet
	bp := pullFor(w, srv, nil, &now)

	_, err := bp.Run(context.Background())
	must(t, err)
	s := statusOf(t, w, w.home, "tencent", payer)
	if s.Source != "api" || s.State != cost.RunEmpty || !s.CheckedAt.Equal(now) || len(s.Months) != 2 || s.Months[0].Month != "2026-10" {
		t.Fatalf("status %+v, want source api, state empty (October found nothing), checked now, newest month first", s)
	}
	if sep := month(t, s, "2026-09"); sep.State != cost.MonthLoaded || sep.Lines != 302 || sep.Total != "40.00" || sep.Currency != "USD" {
		t.Errorf("September %+v, want loaded with 302 lines, 40.00 USD", sep)
	}
	if oct := month(t, s, "2026-10"); oct.State != cost.MonthEmpty || oct.Lines != 0 {
		t.Errorf("October %+v, want empty", oct)
	}
	if acts := syncActivities(t, w, w.home); len(acts) != 1 || !strings.Contains(acts[0], "October 2026: no costs found") || !strings.Contains(acts[0], "September 2026: 302 lines loaded") {
		t.Fatalf("activities %v, want one describing both months in plain words", acts)
	}

	now = now.Add(time.Hour)
	_, err = bp.Run(context.Background())
	must(t, err)
	s = statusOf(t, w, w.home, "tencent", payer)
	if sep := month(t, s, "2026-09"); sep.State != cost.MonthUnchanged || sep.Lines != 302 || sep.Total != "40.00" || !s.CheckedAt.Equal(now) {
		t.Errorf("rerun September %+v checked %v, want unchanged keeping its lines and total, checked at the rerun", sep, s.CheckedAt)
	}
	if acts := syncActivities(t, w, w.home); len(acts) != 1 {
		t.Errorf("an hourly rerun with nothing new recorded %d Activities, want still 1", len(acts))
	}

	f.set("2026-10", september())
	now = now.Add(time.Hour)
	_, err = bp.Run(context.Background())
	must(t, err)
	s = statusOf(t, w, w.home, "tencent", payer)
	if oct := month(t, s, "2026-10"); s.State != cost.RunOK || oct.State != cost.MonthLoaded || !oct.Since.Equal(now) {
		t.Errorf("status %+v October %+v, want ok and October loaded since this run", s, oct)
	}
	if acts := syncActivities(t, w, w.home); len(acts) != 2 || !strings.Contains(acts[1], "October 2026: 302 lines loaded") {
		t.Errorf("activities %v, want a second one for October's change", acts)
	}
}

func TestBillPullFailedMonthRecordsClassNotMessage(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", september())
	f.failAt = 0
	f.failMsg = "signature mismatch for " + secret
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	if _, err := pullFor(w, srv, nil, &now).Run(context.Background()); err == nil {
		t.Fatal("a failing pull was not reported")
	}
	s := statusOf(t, w, w.home, "tencent", payer)
	sep := month(t, s, "2026-09")
	if s.State != cost.RunFailed || sep.State != cost.MonthFailed || sep.Reason != "provider" || sep.Code != "InternalError" {
		t.Errorf("status %+v September %+v, want failed with class provider and code InternalError", s, sep)
	}
	acts := syncActivities(t, w, w.home)
	if len(acts) != 1 || !strings.Contains(acts[0], "September 2026: the billing service returned an error") {
		t.Errorf("activities %v, want one naming the failure in plain words", acts)
	}
	noSecret(t, w, w.home)
}

func TestBillPullBlockedMonthRecordsReason(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", withUnit(september(), "-"))
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	_, _ = pullFor(w, srv, nil, &now).Run(context.Background())
	s := statusOf(t, w, w.home, "tencent", payer)
	if sep := month(t, s, "2026-09"); s.State != cost.RunBlocked || sep.State != cost.MonthBlocked || sep.Reason != "currency_unknown" {
		t.Errorf("status %+v September %+v, want blocked with reason currency_unknown", s, sep)
	}
}

func TestBillSyncWithoutFilesIsEmptyAndFatalErrorsAreClassified(t *testing.T) {
	w := setup(t)
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	objs := &failingObjects{}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "aws", BillingAccountID: "111122223333",
		Mode: cost.LatestExportFolder, Now: func() time.Time { return now }}
	_, err := bs.Run(context.Background())
	must(t, err)
	s := statusOf(t, w, w.home, "aws", "111122223333")
	if s.Source != "files" || s.State != cost.RunEmpty || s.Reason != "no_bill_files" {
		t.Errorf("status %+v, want files source, empty with no_bill_files", s)
	}

	objs.err = errors.New("list failed: " + secret)
	now = now.Add(time.Hour)
	if _, err := bs.Run(context.Background()); err == nil {
		t.Fatal("a failed listing was not reported")
	}
	s = statusOf(t, w, w.home, "aws", "111122223333")
	if s.State != cost.RunFailed || s.Reason != "internal" || !s.CheckedAt.Equal(now) {
		t.Errorf("status %+v, want failed, class internal, checked at the failing run", s)
	}
	if acts := syncActivities(t, w, w.home); len(acts) != 2 {
		t.Errorf("activities %v, want one for empty and one for failed", acts)
	}
	noSecret(t, w, w.home)
}

type failingObjects struct{ err error }

func (f *failingObjects) List(context.Context, string) ([]string, error) { return nil, f.err }
func (f *failingObjects) Get(context.Context, string) ([]byte, error)    { return nil, f.err }

// TestClientPayerStatusStaysInItsTenant: a client payer's status and its
// Activities land in the client's Tenant; RLS hides them from Keel's home
// Tenant and from other clients.
func TestClientPayerStatusStaysInItsTenant(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	c1 := addClient(t, w, "tencent", "c1", "300000000001", "300000000011", "c1-bills-1250000001")
	c2 := addClient(t, w, "tencent", "c2", "300000000002", "300000000022", "c2-bills-1250000002")
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "tencent", Now: func() time.Time { return now },
		Connect: func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			if p.PayerID == c1.payer {
				return nil, nil, &cost.RoleError{Err: errors.New("AssumeRole refused: " + secret)}
			}
			return &memObjects{objs: map[string][]byte{"focus/2026-09-01.csv": bill(t, p.PayerID, billRow{sub: c2.member, cost: "1.00"})}}, nil, nil
		}}
	_, _ = cs.Run(ctx)

	s1 := statusOf(t, w, c1.id, "tencent", c1.payer)
	if s1.State != cost.RunBlocked || s1.Reason != "role_unusable" || s1.Source != "files" {
		t.Errorf("c1 status %+v, want blocked by role_unusable", s1)
	}
	if s2 := statusOf(t, w, c2.id, "tencent", c2.payer); s2.State != cost.RunOK || month(t, s2, "2026-09").State != cost.MonthLoaded {
		t.Errorf("c2 status %+v, want ok with September loaded", s2)
	}
	for tenant, want := range map[string]int{w.home: 0, c1.id: 1, c2.id: 1} {
		got, err := cost.Queries{Store: w.s}.BillSync(ctx, tenant)
		must(t, err)
		if len(got) != want {
			t.Errorf("tenant %s sees %d statuses %+v, want %d", tenant, len(got), got, want)
		}
	}
	noSecret(t, w, c1.id)

	// Keel's own identity failing blocks every payer, without blaming them.
	cs.Ready = func(context.Context) error { return errors.New("no identity") }
	_, _ = cs.Run(ctx)
	for _, c := range []clientTenant{c1, c2} {
		if s := statusOf(t, w, c.id, "tencent", c.payer); s.State != cost.RunBlocked || s.Reason != "keel_identity" {
			t.Errorf("%s status %+v, want blocked by keel_identity", c.id, s)
		}
	}
}

func TestClientPayerWithoutBucketIsBlocked(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	c1 := addClient(t, w, "tencent", "c1", "300000000001", "300000000011", "")
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "tencent",
		Connect: func(cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) { return &memObjects{}, nil, nil }}
	_, _ = cs.Run(ctx)
	if s := statusOf(t, w, c1.id, "tencent", c1.payer); s.State != cost.RunBlocked || s.Reason != "no_bucket" {
		t.Errorf("status %+v, want blocked by no_bucket", s)
	}
}

// TestBillSyncBlockedMonthStaysBlockedWhenNothingNew: a run with no new
// files revisits no month, so the payer still reads blocked until the
// blocked month loads.
func TestBillSyncBlockedMonthStaysBlockedWhenNothingNew(t *testing.T) {
	w := setup(t)
	objs := &memObjects{objs: map[string][]byte{
		"bills/day1.zip": zipped(t, "bill.csv", splitByDay(t, "01")),
		"bills/mtd.zip":  zipped(t, "bill.csv", splitByDay(t, "01", "02")),
	}}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "tencent", BillingAccountID: payer,
		Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}
	_, _ = bs.Run(context.Background())
	_, _ = bs.Run(context.Background())
	s := statusOf(t, w, w.home, "tencent", payer)
	if sep := month(t, s, "2026-09"); s.State != cost.RunBlocked || sep.State != cost.MonthBlocked || sep.Reason != "files_overlap" {
		t.Errorf("status %+v September %+v, want still blocked by files_overlap", s, sep)
	}
}
