package cost_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/cost"
)

const payer = "200045645249"

type testCreds struct{}

func (testCreds) GetCredential() (common.CredentialIface, error) {
	return common.NewCredential("test-id", "test-key"), nil
}

type detailCall struct {
	Month, Context, PayerUin string
	Offset, Limit            int
}

// fakeBilling is a local stand-in for billing.intl.tencentcloudapi.com: it
// serves DescribeBillDetail in pages and DescribeBillSummaryByPayMode.
type fakeBilling struct {
	mu        sync.Mutex
	months    map[string][]map[string]any // "2026-09" → BillDetail objects
	throttle  int                         // RequestLimitExceeded replies still to give
	failAt    int                         // offset that fails with InternalError; -1 for none
	invoice   string
	calls     []detailCall
	throttled int
}

func newFakeBilling(t *testing.T) (*fakeBilling, *httptest.Server) {
	f := &fakeBilling{months: map[string][]map[string]any{}, failAt: -1}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeBilling) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	reply := func(resp map[string]any) {
		resp["RequestId"] = "req"
		_ = json.NewEncoder(w).Encode(map[string]any{"Response": resp})
	}
	fail := func(code string) {
		reply(map[string]any{"Error": map[string]any{"Code": code, "Message": code}})
	}
	if f.throttle > 0 {
		f.throttle--
		f.throttled++
		fail("RequestLimitExceeded")
		return
	}
	switch r.Header.Get("X-TC-Action") {
	case "DescribeBillDetail":
		var req struct {
			Month, Context, PayerUin string
			Offset, Limit            int
		}
		_ = json.Unmarshal(body, &req)
		f.calls = append(f.calls, detailCall(req))
		if req.Offset == f.failAt {
			fail("InternalError")
			return
		}
		all := f.months[req.Month]
		end := min(req.Offset+req.Limit, len(all))
		page := []map[string]any{}
		if req.Offset < len(all) {
			page = all[req.Offset:end]
		}
		reply(map[string]any{"DetailSet": page, "Total": 7, "Context": fmt.Sprintf("ctx-%d", end)})
	case "DescribeBillSummaryByPayMode":
		reply(map[string]any{"Ready": 1, "SummaryOverview": []map[string]any{{"PayMode": "postPay", "RealTotalCost": f.invoice}}})
	default:
		fail("InvalidAction")
	}
}

func (f *fakeBilling) set(month string, details []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.months[month] = details
}

func (f *fakeBilling) callsFor(month string) []detailCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []detailCall
	for _, c := range f.calls {
		if c.Month == month {
			out = append(out, c)
		}
	}
	return out
}

// detail is one DescribeBillDetail line, shaped as the API documents it
// (https://www.tencentcloud.com/document/api/555/30756).
func detail(owner, resource, service, cost, realCost string, extra map[string]any) map[string]any {
	comp := map[string]any{"ComponentCodeName": "CPU", "ItemCodeName": "Standard S5 CPU", "ItemCode": "v_cvm_cpu",
		"Cost": cost, "RealCost": realCost, "Discount": "1", "VoucherPayAmount": "0", "CashPayAmount": realCost,
		"IncentivePayAmount": "0", "TransferPayAmount": "0", "UsedAmount": "24", "UsedAmountUnit": "Hours", "PriceUnit": "USD/core/hour"}
	d := map[string]any{"BusinessCode": "p_cvm", "BusinessCodeName": service, "ProductCodeName": service + " Standard S5",
		"PayModeName": "Pay-As-You-Go", "ActionType": "postpay_deduct_h", "ActionTypeName": "Pay-as-you-go hourly",
		"RegionId": "23", "RegionName": "Thailand (Bangkok)", "ZoneName": "Bangkok Zone 1",
		"ResourceId": resource, "ResourceName": resource, "PayerUin": payer, "OwnerUin": owner, "OperateUin": owner,
		"FeeBeginTime": "2026-09-01 00:00:00", "FeeEndTime": "2026-09-01 23:59:59", "BillMonth": "2026-09-01 00:00:00",
		"BillId": "bill-" + resource, "Tags": []any{}, "ComponentSet": []any{comp}}
	for k, v := range extra {
		if strings.HasPrefix(k, "c.") {
			comp[strings.TrimPrefix(k, "c.")] = v
		} else {
			d[k] = v
		}
	}
	return d
}

// september is 300 dev lines of 0.10 (30.00), a discounted, voucher-paid
// prod line (list 10.00, billed 8.00) and an unregistered account's 2.00:
// 302 lines, two pages, 40.00 billed.
func september() []map[string]any {
	var out []map[string]any
	for i := range 300 {
		out = append(out, detail("200046202634", fmt.Sprintf("ins-dev%03d", i), "Cloud Virtual Machine CVM", "0.10", "0.10", nil))
	}
	out = append(out,
		detail("200048351622", "ins-prod1", "Cloud Virtual Machine CVM", "10.00", "8.00", map[string]any{
			"Tags": []any{map[string]any{"TagKey": "env", "TagValue": "prod"}}, "DiscountType": "contract",
			"c.Discount": "0.8", "c.VoucherPayAmount": "3.00", "c.CashPayAmount": "5.00"}),
		detail("200099999999", "nat-1", "NAT Gateway", "2.00", "2.00", nil))
	return out
}

func pullFor(w world, srv *httptest.Server, invoice cost.InvoiceSource, now *time.Time) *cost.BillPull {
	return &cost.BillPull{Ingester: &cost.Ingester{Store: w.s}, Provider: "tencent", BillingAccountID: payer,
		Details:  &tencent.BillDetails{Region: "ap-bangkok", Creds: testCreds{}, Endpoint: srv.URL, Backoff: profile.ConstantDurationFunc(0)},
		Invoices: invoice, Now: func() time.Time { return *now }}
}

func loadCount(t *testing.T, w world) (all, current int) {
	t.Helper()
	must(t, w.s.InTenant(context.Background(), w.home, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE superseded_at IS NULL) FROM cost_loads WHERE billing_period = '2026-09-01'`).Scan(&all, &current)
	}))
	return all, current
}

func TestBillPullPagesMapsAndReconciles(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", september())
	f.invoice = "40.00"
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	bp := pullFor(w, srv, tencent.Invoices{Region: "ap-bangkok", Creds: testCreds{}, Endpoint: srv.URL}, &now)

	rep, err := bp.Run(context.Background())
	must(t, err)
	if len(rep.Loads) != 1 || rep.Loads[0].Period.Format("2006-01") != "2026-09" || rep.Loads[0].Final {
		t.Fatalf("report %+v", rep)
	}
	l := rep.Loads[0]
	if l.Reconcile != "ok" || l.Unallocated != 1 {
		t.Errorf("reconcile %q unallocated %d, want ok and the unregistered account's line counted", l.Reconcile, l.Unallocated)
	}
	calls := f.callsFor("2026-09")
	if len(calls) != 2 || calls[0].Offset != 0 || calls[1].Offset != 300 || calls[0].Limit != 300 ||
		calls[0].Context != "" || calls[1].Context != "ctx-300" || calls[0].PayerUin != payer {
		t.Fatalf("pages %+v, want offsets 0 and 300 at the max limit, carrying Context, for the payer", calls)
	}
	if got := billedTotal(t, w); got != "38.00" {
		t.Errorf("TAT billed = %s, want 38.00 (dev 30.00 + prod 8.00 after discount)", got)
	}
	if got := sum(t, w, w.home, "allocation_method = 'unallocated' AND sub_account_id = '200099999999'"); got != "2.00" {
		t.Errorf("unregistered account billed = %s, want 2.00 in the home Tenant", got)
	}
	var list, eff, cur, svc, cat, tags, voucher, cash string
	var start time.Time
	must(t, w.s.InTenant(context.Background(), w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT list_cost::text, effective_cost::text, billing_currency, service_name, service_category,
			tags->>'env', vendor->>'x_VoucherPayAmount', vendor->>'x_CashPayAmount', charge_period_start
			FROM cost_facts WHERE current AND resource_id = 'ins-prod1'`).Scan(&list, &eff, &cur, &svc, &cat, &tags, &voucher, &cash, &start)
	}))
	if list != "10.00" || eff != "8.00" || cur != "USD" || svc != "Cloud Virtual Machine" || cat != "Compute" ||
		tags != "prod" || voucher != "3.00" || cash != "5.00" || !start.Equal(time.Date(2026, 8, 31, 16, 0, 0, 0, time.UTC)) {
		t.Errorf("prod fact list=%s eff=%s cur=%s svc=%q cat=%q env=%s voucher=%s cash=%s start=%s", list, eff, cur, svc, cat, tags, voucher, cash, start)
	}
	if aug := f.callsFor("2026-08"); len(aug) != 1 {
		t.Errorf("August pulled %d times, want once (the previous month is not final yet)", len(aug))
	}
}

func TestBillPullRerunIsIdempotentAndSupersedes(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", september())
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	bp := pullFor(w, srv, nil, &now)

	_, err := bp.Run(context.Background())
	must(t, err)
	rep, err := bp.Run(context.Background())
	must(t, err)
	if all, _ := loadCount(t, w); len(rep.Loads) != 0 || all != 1 {
		t.Fatalf("unchanged rerun made loads %+v (total %d), want none", rep.Loads, all)
	}

	f.set("2026-09", append(september(), detail("200046202634", "ins-dev-new", "Cloud Virtual Machine CVM", "1.00", "1.00", nil)))
	rep, err = bp.Run(context.Background())
	must(t, err)
	all, current := loadCount(t, w)
	if len(rep.Loads) != 1 || all != 2 || current != 1 {
		t.Fatalf("changed bill: loads %+v, %d loads with %d current, want one new load superseding the old", rep.Loads, all, current)
	}
	if got := billedTotal(t, w); got != "39.00" {
		t.Errorf("billed = %s, want 39.00 from the new load alone", got)
	}
}

func TestBillPullFailedPageKeepsPreviousLoad(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", september())
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	bp := pullFor(w, srv, nil, &now)
	_, err := bp.Run(context.Background())
	must(t, err)

	f.set("2026-09", append(september(), detail("200046202634", "ins-dev-new", "Cloud Virtual Machine CVM", "5.00", "5.00", nil)))
	f.failAt = 300
	rep, err := bp.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "InternalError") || len(rep.Loads) != 0 {
		t.Fatalf("run with a failing second page: err %v loads %+v, want the error and no load", err, rep.Loads)
	}
	if all, _ := loadCount(t, w); all != 1 {
		t.Errorf("%d loads, want the first one only", all)
	}
	if got := billedTotal(t, w); got != "38.00" {
		t.Errorf("billed = %s, want the previous load's 38.00", got)
	}
}

func TestBillPullRetriesRateLimit(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", september())
	f.throttle = 3
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	rep, err := pullFor(w, srv, nil, &now).Run(context.Background())
	must(t, err)
	if f.throttled != 3 || len(rep.Loads) != 1 {
		t.Fatalf("throttled %d, loads %+v: want 3 RequestLimitExceeded retried and a load", f.throttled, rep.Loads)
	}
	if got := billedTotal(t, w); got != "38.00" {
		t.Errorf("billed = %s", got)
	}
}

func TestBillPullFinalisesOnceThenStopsPulling(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", september())
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	bp := pullFor(w, srv, nil, &now)
	_, err := bp.Run(context.Background())
	must(t, err)

	// Unchanged data, but September became final: one last, final load.
	now = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	rep, err := bp.Run(context.Background())
	must(t, err)
	if len(rep.Loads) != 1 || !rep.Loads[0].Final {
		t.Fatalf("finalising run %+v", rep)
	}
	before := len(f.callsFor("2026-09"))
	rep, err = bp.Run(context.Background())
	must(t, err)
	if len(rep.Loads) != 0 || len(f.callsFor("2026-09")) != before {
		t.Fatalf("final period pulled again or reloaded: %+v", rep)
	}
}

func TestBillPullResolvesBlockedFinding(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", september())
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	const fp = "bill_sync_blocked:tencent/" + payer + "/2026-09"
	ctx := context.Background()
	must(t, w.s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at)
			VALUES ($1, 'bill_sync_blocked', $2, 'high', 'blocked', '{}', now())`, w.home, fp)
		return err
	}))
	_, err := pullFor(w, srv, nil, &now).Run(ctx)
	must(t, err)
	var status string
	must(t, w.s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM findings WHERE fingerprint = $1`, fp).Scan(&status)
	}))
	if status != "resolved" {
		t.Errorf("blocked finding %s, want resolved by the load", status)
	}
}

func TestBillPullRejectsMixedCurrencies(t *testing.T) {
	w := setup(t)
	f, srv := newFakeBilling(t)
	f.set("2026-09", append(september(), detail("200046202634", "ins-cny", "Cloud Virtual Machine CVM", "1.00", "1.00",
		map[string]any{"c.PriceUnit": "CNY/core/hour"})))
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	rep, err := pullFor(w, srv, nil, &now).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "currenc") || len(rep.Loads) != 0 {
		t.Fatalf("mixed USD and CNY: err %v loads %+v, want an error and no load", err, rep.Loads)
	}
}
