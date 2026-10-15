package api_test

import (
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// TestBillSyncStatusIsTenantScoped: a Tenant's viewers read their own
// payers' bill sync status and are refused another Tenant's.
func TestBillSyncStatusIsTenantScoped(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	home, _ := s.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	for tenant, payer := range map[string]string{home: "200045645249", tat: "300000000001"} {
		if err := s.InTenant(t.Context(), tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `INSERT INTO bill_sync_status (tenant_id, provider, billing_account_id, source, checked_at, state, since, months)
				VALUES ($1, 'tencent', $2, 'api', now(), 'empty', now(), '{"2026-09": {"month": "2026-09", "state": "empty", "lines": 0}}')`, tenant, payer)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		Cost: &api.CostDeps{Authz: az, Queries: cost.Queries{Store: s}, Ingester: &cost.Ingester{Store: s}}}))
	t.Cleanup(srv.Close)
	c := client{t: t, url: srv.URL}
	viewer := c.as(auth.Principal{Subject: "user:v@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})

	st, body := viewer.do("GET", "/v1/tenants/"+tat+"/bill-sync", nil)
	mustStatus(t, st, 200, body)
	items := body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items %v, want TAT's payer only", items)
	}
	got := items[0].(map[string]any)
	months := got["months"].([]any)
	if got["billing_account_id"] != "300000000001" || got["state"] != "empty" || len(months) != 1 || months[0].(map[string]any)["state"] != "empty" {
		t.Errorf("status %v, want TAT's payer empty for 2026-09", got)
	}
	if _, ok := got["tenant_id"]; ok {
		t.Errorf("status %v carries tenant_id", got)
	}
	st, body = viewer.do("GET", "/v1/tenants/"+home+"/bill-sync", nil)
	mustStatus(t, st, 403, body)
}
