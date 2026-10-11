package catalog_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestRoleHealthDerivesFromBillSync(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	az, err := authz.New()
	if err != nil {
		t.Fatal(err)
	}
	c := catalog.New(s, az)
	home, err := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	if err != nil {
		t.Fatal(err)
	}
	tat, err := s.CreateTenant(ctx, "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateTenant(ctx, "other", "Other", false)
	if err != nil {
		t.Fatal(err)
	}
	role := `{"role_arn": "qcs::cam::uin/200000000001:roleName/keel-readonly"}`
	var payer, member, ours, otherAcc string
	assumedAt := time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC)
	loadedAt := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC)
	memberLoadedAt := time.Date(2026, 10, 10, 2, 0, 0, 0, time.UTC)
	var payerLoad, memberLoad string
	if err := s.InTenant(ctx, home, func(tx pgx.Tx) error {
		for ext, id := range map[string]*string{"200000000001": &payerLoad, "keel-payer": &memberLoad} {
			if err := tx.QueryRow(ctx, `INSERT INTO cost_loads (tenant_id, provider, billing_account_id, billing_period, line_count, total_billed, unallocated_billed, currency, touched_tenants)
				VALUES ($1, 'tencent', $2, '2026-10-01', 1, 1, 0, 'USD', ARRAY[$3::uuid]) RETURNING id::text`, home, ext, tat).Scan(id); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		insert := func(ext, name, ownership string, role any, id *string) error {
			return tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, 'tencent', $2, $3, $4, $5) RETURNING id::text`,
				tat, ext, name, ownership, role).Scan(id)
		}
		if err := insert("200000000001", "payer", "client", role, &payer); err != nil {
			return err
		}
		if err := insert("200000000002", "member", "client", role, &member); err != nil {
			return err
		}
		if err := insert("200000000003", "ours", "platform", nil, &ours); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, provider, region) VALUES ($1, $2, 'tencent', 'ap-bangkok')`, payer, tat); err != nil {
			return err
		}
		fact := `INSERT INTO cost_facts (load_id, tenant_id, provider, billing_account_id, sub_account_id, cloud_account_id, allocation_method, billing_period, charge_period_start, charge_period_end, charge_category, billed_cost, billing_currency)
			VALUES ($1, $2, 'tencent', $3, $4, $5, 'account', '2026-10-01', '2026-10-01', '2026-10-02', 'Usage', 1, 'USD')`
		if _, err := tx.Exec(ctx, fact, payerLoad, tat, "200000000001", "200000000002", member); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, fact, memberLoad, tat, "keel-payer", "200000000002", member); err != nil {
			return err
		}
		for load, at := range map[string]time.Time{payerLoad: loadedAt, memberLoad: memberLoadedAt} {
			if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: tat, Source: "keel/cost", Type: "keel.cost.loaded", Subject: "cost_load/" + load,
				Operation: "LoadCosts", Kind: activity.Create, Actor: activity.Actor{Type: activity.ActorKeel, UID: "keel:cost"}, Outcome: activity.Success, Time: at}); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE client_payers SET last_assumed_at = $1`, assumedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail) VALUES
			($1, 'bill_delivery_missing', 'd', 'medium', 'bills not delivered', jsonb_build_object('cloud_account_id', $2::text)),
			($1, 'cost_anomaly', 'x', 'high', 'unrelated', jsonb_build_object('cloud_account_id', $2::text))`, tat, payer)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Another Tenant's Finding naming TAT's payer must not reach TAT, nor TAT's accounts the other Tenant.
	if err := s.InTenant(ctx, other, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, 'tencent', '200000000009', 'theirs', 'client', $2) RETURNING id::text`,
			other, role).Scan(&otherAcc); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail) VALUES ($1, 'client_role_unusable', 'r', 'high', 'forged', jsonb_build_object('cloud_account_id', $2::text))`, other, payer)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	viewer := auth.Principal{Subject: "user:somchai@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}}
	got, err := c.ListRoleHealth(ctx, viewer, tat)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]catalog.RoleHealth{}
	for _, h := range got {
		byID[h.CloudAccountID] = h
	}
	if len(got) != 2 || byID[ours].CloudAccountID != "" {
		t.Fatalf("role health covers %d accounts (platform-owned included: %v), want the 2 client-owned", len(got), byID[ours].CloudAccountID != "")
	}
	p := byID[payer]
	if !p.ClientPayer || p.LastAssumeAt == nil || !p.LastAssumeAt.Equal(assumedAt) || p.LastIngestAt == nil || !p.LastIngestAt.Equal(loadedAt) {
		t.Errorf("payer = %+v, want client payer assumed at %v and ingested at %v", p, assumedAt, loadedAt)
	}
	if len(p.Findings) != 1 || p.Findings[0].Kind != "bill_delivery_missing" {
		t.Errorf("payer findings = %+v, want the open delivery Finding only", p.Findings)
	}
	m := byID[member]
	if m.ClientPayer || m.LastAssumeAt != nil || m.LastIngestAt == nil || !m.LastIngestAt.Equal(memberLoadedAt) || len(m.Findings) != 0 {
		t.Errorf("member = %+v, want no assume, ingest at %v, no Findings", m, memberLoadedAt)
	}

	theirs, err := c.ListRoleHealth(ctx, auth.Principal{Subject: "user:x@other.example", Kind: auth.KindHuman, TenantID: other, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: other}}}, other)
	if err != nil {
		t.Fatal(err)
	}
	if len(theirs) != 1 || theirs[0].CloudAccountID != otherAcc || len(theirs[0].Findings) != 0 {
		t.Errorf("other Tenant role health = %+v, want only its own account and no Finding about TAT's payer", theirs)
	}
	if _, err := c.ListRoleHealth(ctx, auth.Principal{Subject: "user:x@other.example", Kind: auth.KindHuman, TenantID: other, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: other}}}, tat); err == nil {
		t.Error("another Tenant's viewer read TAT's role health")
	}
}

type bucket map[string][]byte

func (b bucket) List(_ context.Context, prefix string) ([]string, error) {
	var out []string
	for k := range b {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (b bucket) Get(_ context.Context, key string) ([]byte, error) { return b[key], nil }

// TestRoleHealthFollowsClientBillSync drives the real client payer sync:
// last_assume_at moves only when Keel assumes the role, never on a manual
// resolve of the role Finding, and a blocked period shows in the client's
// own role health.
func TestRoleHealthFollowsClientBillSync(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	az, err := authz.New()
	if err != nil {
		t.Fatal(err)
	}
	c := catalog.New(s, az)
	if _, err := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true); err != nil {
		t.Fatal(err)
	}
	tat, err := s.CreateTenant(ctx, "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	const uin, member = "200000000001", "200000000002"
	var payer string
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		role := `{"role_arn": "qcs::cam::uin/200000000001:roleName/keel-readonly"}`
		if err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, 'tencent', $2, 'payer', 'client', $3) RETURNING id::text`,
			tat, uin, role).Scan(&payer); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, 'tencent', $2, 'member', 'client', $3)`, tat, member, role); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, provider, bucket, prefix, region, mode) VALUES ($1, $2, 'tencent', 'tat-bills-1250000001', 'focus/', 'ap-bangkok', 'per-day')`, payer, tat)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	line := func(cost string) []byte {
		return []byte("BilledCost,EffectiveCost,BillingAccountId,BillingCurrency,BillingPeriodStart,BillingPeriodEnd,ChargeCategory,ChargePeriodStart,ChargePeriodEnd,ServiceName,SubAccountId,Tags\n" +
			cost + "," + cost + "," + uin + ",USD,2026-09-01T00:00:00Z,2026-10-01T00:00:00Z,Usage,2026-09-01T00:00:00Z,2026-09-02T00:00:00Z,Cloud Virtual Machine," + member + ",{}\n")
	}
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	refused := true
	sync := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: s}, Provider: "tencent", Now: func() time.Time { return now },
		Connect: func(cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			if refused {
				return nil, nil, &cost.RoleError{Err: errors.New("AssumeRole refused")}
			}
			return bucket{"focus/2026-09-01.csv": line("1.00"), "focus/2026-09-01-b.csv": line("1.00")}, nil, nil
		}}
	viewer := auth.Principal{Subject: "user:somchai@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}}
	health := func() catalog.RoleHealth {
		t.Helper()
		got, err := c.ListRoleHealth(ctx, viewer, tat)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range got {
			if h.CloudAccountID == payer {
				return h
			}
		}
		t.Fatal("no role health for the payer")
		return catalog.RoleHealth{}
	}
	kinds := func(h catalog.RoleHealth) []string {
		var out []string
		for _, f := range h.Findings {
			out = append(out, f.Kind)
		}
		return out
	}

	if _, err := sync.Run(ctx); err == nil {
		t.Fatal("a refused role was not reported")
	}
	if h := health(); h.LastAssumeAt != nil || !slices.Equal(kinds(h), []string{"client_role_unusable"}) {
		t.Fatalf("after a refused role: last assume %v, findings %v; want never and the role Finding", h.LastAssumeAt, kinds(h))
	}
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $1, resolution = 'duplicate, closing' WHERE kind = 'client_role_unusable'`, now.Add(time.Minute))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if h := health(); h.LastAssumeAt != nil {
		t.Fatalf("a manual resolve set last assume to %v, want never", h.LastAssumeAt)
	}

	refused = false
	now = now.Add(time.Hour)
	if _, err := sync.Run(ctx); err == nil {
		t.Fatal("overlapping files did not block the period")
	}
	h := health()
	if h.LastAssumeAt == nil || !h.LastAssumeAt.Equal(now) || h.LastIngestAt != nil {
		t.Errorf("after a blocked sync: last assume %v, last ingest %v; want %v and never", h.LastAssumeAt, h.LastIngestAt, now)
	}
	if !slices.Equal(kinds(h), []string{"bill_sync_blocked"}) {
		t.Errorf("after a blocked sync the client sees findings %v, want bill_sync_blocked", kinds(h))
	}
}
