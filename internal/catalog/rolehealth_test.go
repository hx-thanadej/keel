package catalog_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
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
		if _, err := tx.Exec(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, region) VALUES ($1, $2, 'ap-bangkok')`, payer, tat); err != nil {
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
		if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, status, resolved_at, resolution)
			VALUES ($1, 'client_role_unusable', 'role-old', 'high', 'old', jsonb_build_object('cloud_account_id', $2::text), 'resolved', $3, 'role assumed')`, tat, payer, assumedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail) VALUES
			($1, 'bill_delivery_missing', 'd', 'medium', 'bills not delivered', jsonb_build_object('cloud_account_id', $2::text)),
			($1, 'bill_sync_blocked', 'b', 'high', 'sync blocked', jsonb_build_object('provider', 'tencent', 'billing_account', '200000000001')),
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
	if !p.ClientPayer || p.LastAssumeAt == nil || !p.LastAssumeAt.Equal(loadedAt) || p.LastIngestAt == nil || !p.LastIngestAt.Equal(loadedAt) {
		t.Errorf("payer = %+v, want client payer assumed and ingested at %v", p, loadedAt)
	}
	kinds := map[string]bool{}
	for _, f := range p.Findings {
		kinds[f.Kind] = true
	}
	if len(p.Findings) != 2 || !kinds["bill_delivery_missing"] || !kinds["bill_sync_blocked"] {
		t.Errorf("payer findings = %+v, want the open delivery and blocked Findings only", p.Findings)
	}
	m := byID[member]
	if m.ClientPayer || m.LastAssumeAt != nil || m.LastIngestAt == nil || !m.LastIngestAt.Equal(memberLoadedAt) || len(m.Findings) != 0 {
		t.Errorf("member = %+v, want no assume, ingest at %v, no Findings", m, memberLoadedAt)
	}

	// An AssumeRole that resolved the role Finding after the last load is the later proof.
	reassumed := loadedAt.Add(5 * time.Hour)
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET resolved_at = $1 WHERE fingerprint = 'role-old'`, reassumed)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got, err = c.ListRoleHealth(ctx, viewer, tat); err != nil {
		t.Fatal(err)
	}
	for _, h := range got {
		if h.CloudAccountID == payer && (h.LastAssumeAt == nil || !h.LastAssumeAt.Equal(reassumed)) {
			t.Errorf("payer last_assume_at = %v, want the role Finding's resolution %v", h.LastAssumeAt, reassumed)
		}
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
