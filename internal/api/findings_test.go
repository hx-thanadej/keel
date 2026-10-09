package api_test

import (
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestFindingsInbox(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	cat := catalog.New(s, az)
	cat.Now = storetest.Clock()
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: cat, Authz: az}))
	t.Cleanup(srv.Close)
	var low, high string
	if err := s.InTenant(t.Context(), tat, func(tx pgx.Tx) error {
		if err := tx.QueryRow(t.Context(), `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, first_seen_at) VALUES ($1, 'cost_anomaly', 'a', 'low', 'Low one', $2) RETURNING id::text`, tat, cat.Now()).Scan(&low); err != nil {
			return err
		}
		return tx.QueryRow(t.Context(), `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, first_seen_at) VALUES ($1, 'cost_anomaly', 'b', 'high', 'High one', $2) RETURNING id::text`, tat, cat.Now()).Scan(&high)
	}); err != nil {
		t.Fatal(err)
	}
	c := client{t: t, url: srv.URL}
	viewer := c.as(auth.Principal{Subject: "user:v@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	eng := c.as(auth.Principal{Subject: "user:e@harmonyx.co", Kind: auth.KindHuman, TenantID: "x", Home: true, Bindings: []auth.Binding{{Role: auth.RoleEngineer, TenantID: tat}}})

	st, body := viewer.do("GET", "/v1/tenants/"+tat+"/findings", nil)
	mustStatus(t, st, 200, body)
	got := items(t, body)
	if len(got) != 2 || got[0]["id"] != high {
		t.Fatalf("inbox not severity-ordered: %v", got)
	}
	st, body = viewer.do("POST", "/v1/tenants/"+tat+"/findings/"+high+"/resolve", map[string]any{"resolution": "x"})
	mustStatus(t, st, 403, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/findings/"+high+"/resolve", map[string]any{})
	mustStatus(t, st, 400, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/findings/"+high+"/resolve", map[string]any{"resolution": "NAT egress was a one-off data migration"})
	mustStatus(t, st, 200, body)
	st, body = eng.do("POST", "/v1/tenants/"+tat+"/findings/"+high+"/resolve", map[string]any{"resolution": "again"})
	mustStatus(t, st, 404, body)
	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/findings?status=resolved", nil)
	mustStatus(t, st, 200, body)
	if r := items(t, body); len(r) != 1 || r[0]["resolution"] != "NAT egress was a one-off data migration" {
		t.Fatalf("resolved %v", r)
	}
	storetest.ClockedFindings(t, s, "cost_anomaly")
	st, body = viewer.do("GET", "/v1/tenants/"+tat+"/findings?status=bogus", nil)
	mustStatus(t, st, 400, body)
	_ = low
}
