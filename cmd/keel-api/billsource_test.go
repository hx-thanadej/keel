package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestTencentBillSourceIsValidated(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		want string // error substring; "" means sync off
	}{
		{"off by default", map[string]string{}, ""},
		{"unknown source", map[string]string{"KEEL_TENCENT_BILL_SOURCE": "s3", "KEEL_TENCENT_PAYER_UIN": "200045645249"}, "must be cos or api"},
		{"api needs the payer", map[string]string{"KEEL_TENCENT_BILL_SOURCE": "api"}, "KEEL_TENCENT_PAYER_UIN is required"},
		{"api refuses a bucket", map[string]string{"KEEL_TENCENT_BILL_SOURCE": "api", "KEEL_TENCENT_PAYER_UIN": "200045645249", "KEEL_TENCENT_BILL_BUCKET": "b"}, "KEEL_TENCENT_BILL_BUCKET applies only"},
		{"api refuses a file mode", map[string]string{"KEEL_TENCENT_BILL_SOURCE": "api", "KEEL_TENCENT_PAYER_UIN": "200045645249", "KEEL_TENCENT_BILL_MODE": "cumulative"}, "KEEL_TENCENT_BILL_MODE applies only"},
		{"cos needs the payer", map[string]string{"KEEL_TENCENT_BILL_BUCKET": "b"}, "KEEL_TENCENT_PAYER_UIN is required"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range []string{"KEEL_TENCENT_BILL_SOURCE", "KEEL_TENCENT_PAYER_UIN", "KEEL_TENCENT_BILL_BUCKET", "KEEL_TENCENT_BILL_PREFIX", "KEEL_TENCENT_BILL_MODE", "KEEL_TENCENT_BILL_ROLE"} {
				t.Setenv(k, c.env[k])
			}
			run, err := tencentBillRun(nil, staticCreds{id: "base-id"}, "http://127.0.0.1:1")
			switch {
			case c.want == "" && (err != nil || run != nil):
				t.Fatalf("got run %v err %v, want sync off", run != nil, err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("err %v, want %q", err, c.want)
			}
		})
	}
}

// TestTencentBillSourceAPIPullsTheBill drives source api as the binary wires
// it, against a fake billing endpoint, with only the payer configured.
func TestTencentBillSourceAPIPullsTheBill(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	if _, err := st.CreateTenant(ctx, "harmonyx", "HarmonyX", true); err != nil {
		t.Fatal(err)
	}
	var actions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct{ Month, PayerUin string }
		_ = json.Unmarshal(body, &req)
		action := r.Header.Get("X-TC-Action")
		actions = append(actions, action)
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=base-id/") || req.PayerUin != "200045645249" {
			t.Errorf("%s signed %q for payer %q", action, r.Header.Get("Authorization"), req.PayerUin)
		}
		resp := map[string]any{"RequestId": "r"}
		switch action {
		case "DescribeBillDetail":
			resp["DetailSet"] = []any{map[string]any{"PayerUin": "200045645249", "OwnerUin": "200099999999", "BusinessCodeName": "NAT Gateway",
				"ActionType": "postpay_deduct_h", "FeeBeginTime": req.Month + "-01 00:00:00", "FeeEndTime": req.Month + "-01 00:59:59", "BillId": "b1",
				"ComponentSet": []any{map[string]any{"Cost": "2.50", "RealCost": "2.50", "PriceUnit": "USD/GB"}}}}
		case "DescribeBillSummaryByPayMode":
			resp["Ready"], resp["SummaryOverview"] = 0, []any{map[string]any{"RealTotalCost": "2.50"}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Response": resp})
	}))
	defer srv.Close()
	t.Setenv("KEEL_TENCENT_BILL_SOURCE", "api")
	t.Setenv("KEEL_TENCENT_PAYER_UIN", "200045645249")
	for _, k := range []string{"KEEL_TENCENT_BILL_BUCKET", "KEEL_TENCENT_BILL_PREFIX", "KEEL_TENCENT_BILL_MODE", "KEEL_TENCENT_BILL_ROLE"} {
		t.Setenv(k, "")
	}
	run, err := tencentBillRun(st, staticCreds{id: "base-id"}, srv.URL)
	if err != nil || run == nil {
		t.Fatalf("run %v err %v", run != nil, err)
	}
	loads, err := run(ctx)
	if err != nil || len(loads) != 2 {
		t.Fatalf("loads %+v err %v, want the previous and current month", loads, err)
	}
	for _, l := range loads {
		if l.Unallocated != 1 || l.Reconcile != "not_ready" {
			t.Errorf("load %+v, want the unregistered line unallocated and the invoice not ready", l)
		}
	}
	if again, err := run(ctx); err != nil || len(again) != 0 {
		t.Errorf("unchanged rerun loads %+v err %v, want none", again, err)
	}
	if len(actions) == 0 || actions[0] != "DescribeBillDetail" {
		t.Errorf("actions %v", actions)
	}
}
