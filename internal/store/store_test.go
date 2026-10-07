package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// tenantScoped lists every table that must be isolated per Tenant. Adding a
// table to the schema without adding it here fails TestEveryTableIsListed.
var tenantScoped = []string{"tenants", "teams", "projects", "environments", "cloud_accounts", "services", "activities", "identity_providers", "idp_group_roles", "sessions", "activity_digests", "discovered_accounts", "catalog_sync_runs", "activity_exports", "cost_loads", "cost_facts", "cost_source_files", "fx_rates", "budgets", "budget_alerts", "findings", "allocation_rules", "k8s_namespace_scopes", "k8s_namespace_costs", "budget_mirrors"}

type fixture struct {
	tenant, team, project, env, account, service string
}

func seed(t *testing.T, s *store.Store, slug string) fixture {
	t.Helper()
	ctx := context.Background()
	var f fixture
	var err error
	f.tenant, err = s.CreateTenant(ctx, slug, strings.ToUpper(slug), false)
	if err != nil {
		t.Fatalf("create tenant %s: %v", slug, err)
	}
	err = s.InTenant(ctx, f.tenant, func(tx pgx.Tx) error {
		q := func(sql string, dst *string, args ...any) error {
			return tx.QueryRow(ctx, sql, args...).Scan(dst)
		}
		if err := q(`INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, &f.team, f.tenant); err != nil {
			return err
		}
		if err := q(`INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, $3, 'CRM') RETURNING id`, &f.project, f.tenant, f.team, slug+"-crm"); err != nil {
			return err
		}
		if err := q(`INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, &f.env, f.tenant, f.project); err != nil {
			return err
		}
		if err := q(`INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', $3, $4) RETURNING id`,
			&f.account, f.tenant, f.env, "uin-"+slug, slug+"-crm-prod"); err != nil {
			return err
		}
		if err := q(`INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'api', 'API') RETURNING id`, &f.service, f.tenant, f.project, f.team); err != nil {
			return err
		}
		var idp string
		if err := q(`INSERT INTO identity_providers (tenant_id, issuer, client_id, client_secret_ref) VALUES ($1, $2, 'keel', 'SECRET') RETURNING id`, &idp, f.tenant, "https://idp."+slug+".example"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO idp_group_roles (tenant_id, idp_id, group_name, role, target_tenant_id) VALUES ($1, $2, 'viewers', 'tenant_viewer', $1)`, f.tenant, idp); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sessions (id_hash, tenant_id, principal, expires_at) VALUES (sha256($2::bytea), $1, '{}', now() + interval '1 hour')`, f.tenant, slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO catalog_sync_runs (tenant_id, started_at, finished_at, report) VALUES ($1, now(), now(), '{}')`, f.tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO discovered_accounts (tenant_id, provider, external_id, name) VALUES ($1, 'tencent', $2, 'x')`, f.tenant, "d-"+slug); err != nil {
			return err
		}
		var digest string
		if err := q(`INSERT INTO activity_digests (tenant_id, seq_from, seq_to, count, batch_sha256, cutoff, sealed_at, key_id, signature)
			VALUES ($1, 0, 0, 0, '\x00', now(), now(), 'k', '\x00') RETURNING id`, &digest, f.tenant); err != nil {
			return err
		}
		var load string
		if err := q(`INSERT INTO cost_loads (tenant_id, provider, billing_account_id, billing_period, line_count, total_billed, unallocated_billed, currency, touched_tenants)
			VALUES ($1, 'tencent', $2, '2026-09-01', 1, 1, 0, 'USD', ARRAY[$1::uuid]) RETURNING id`, &load, f.tenant, "payer-"+slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO allocation_rules (tenant_id, provider, sub_account_id, kind) VALUES ($1, 'tencent', $2, 'weights')`, f.tenant, "sa-"+slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_namespace_scopes (tenant_id, cluster, namespace, target_tenant_id, project_id) VALUES ($1, $2, 'ns', $1, $3)`, f.tenant, "c-"+slug, f.project); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_namespace_costs (tenant_id, cluster, day, namespace, cost) VALUES ($1, $2, '2026-09-01', 'ns', 1)`, f.tenant, "c-"+slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title) VALUES ($1, 'test', $2, 'low', 'x')`, f.tenant, "fp-"+slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fx_rates (tenant_id, day, currency, per_eur) VALUES ($1, '2026-09-01', $2, 1)`, f.tenant, "X"+slug); err != nil {
			return err
		}
		var budget string
		if err := q(`INSERT INTO budgets (tenant_id, project_id, name, year, amount, currency) VALUES ($1, $2, 'b', 2026, 100, 'USD') RETURNING id`, &budget, f.tenant, f.project); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO budget_mirrors (tenant_id, budget_id, provider, native_id, spec) VALUES ($1, $2, 'tencent', 'n', '{}')`, f.tenant, budget); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO budget_alerts (tenant_id, budget_id, month, pct, basis, value, budget_amount) VALUES ($1, $2, '2026-09-01', 80, 'actual', 1, 1)`, f.tenant, budget); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cost_source_files (tenant_id, provider, billing_account_id, object_key, billing_period, line_count)
			VALUES ($1, 'tencent', 'p', $2, '2026-09-01', 1)`, f.tenant, "k-"+slug); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cost_facts (load_id, tenant_id, provider, billing_account_id, sub_account_id, allocation_method, billing_period,
			charge_period_start, charge_period_end, charge_category, billed_cost, billing_currency)
			VALUES ($1, $2, 'tencent', 'p', 's', 'unallocated', '2026-09-01', now(), now(), 'Usage', 1, 'USD')`, load, f.tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO activity_exports (digest_id, tenant_id, data_key, digest_key) VALUES ($1, $2, 'd', 'g')`, digest, f.tenant); err != nil {
			return err
		}
		_, err := activity.Record(ctx, tx, activity.Activity{
			TenantID: f.tenant, Source: "test", Type: "test.seeded", Operation: "Seed",
			Kind: activity.Create, Actor: activity.Actor{Type: activity.ActorKeel, UID: "keel:test"}, Outcome: activity.Success,
		})
		return err
	})
	if err != nil {
		t.Fatalf("seed %s: %v", slug, err)
	}
	return f
}

func count(t *testing.T, s *store.Store, tenant, table string) int {
	t.Helper()
	var n int
	err := s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), fmt.Sprintf("SELECT count(*) FROM %s", pgx.Identifier{table}.Sanitize())).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestTenantSeesOnlyItsOwnRows(t *testing.T) {
	s := storetest.New(t)
	a := seed(t, s, "tat")
	b := seed(t, s, "acme")

	for _, table := range tenantScoped {
		if got := count(t, s, a.tenant, table); got != 1 {
			t.Errorf("tenant A sees %d rows in %s, want 1", got, table)
		}
		if got := count(t, s, b.tenant, table); got != 1 {
			t.Errorf("tenant B sees %d rows in %s, want 1", got, table)
		}
	}
}

func TestNoTenantContextSeesNothing(t *testing.T) {
	s := storetest.New(t)
	seed(t, s, "tat")
	ctx := context.Background()

	for _, table := range tenantScoped {
		var n int
		err := s.AppPool().QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s", pgx.Identifier{table}.Sanitize())).Scan(&n)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("no tenant context sees %d rows in %s, want 0", n, table)
		}
	}
}

func TestCannotWriteRowsForAnotherTenant(t *testing.T) {
	s := storetest.New(t)
	a := seed(t, s, "tat")
	b := seed(t, s, "acme")
	ctx := context.Background()

	err := s.InTenant(ctx, a.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'evil', 'Evil')`, b.tenant)
		return err
	})
	if !isRLSViolation(err) {
		t.Fatalf("insert into other tenant: err = %v, want RLS violation", err)
	}

	err = s.InTenant(ctx, a.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE projects SET name = 'pwned' WHERE id = $1`, b.project)
		if err == nil && tag.RowsAffected() != 0 {
			return errors.New("updated another tenant's project")
		}
		return err
	})
	if err != nil {
		t.Fatalf("update other tenant: %v", err)
	}

	err = s.InTenant(ctx, a.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE teams SET tenant_id = $1 WHERE id = $2`, b.tenant, a.team)
		return err
	})
	if !isRLSViolation(err) {
		t.Fatalf("moving a row to another tenant: err = %v, want RLS violation", err)
	}
}

func TestChildMustShareParentTenant(t *testing.T) {
	s := storetest.New(t)
	a := seed(t, s, "tat")
	b := seed(t, s, "acme")
	ctx := context.Background()

	// Tenant A tries to attach an Environment to Tenant B's Project.
	err := s.InTenant(ctx, a.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'dev')`, a.tenant, b.project)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("cross-tenant parent: err = %v, want foreign_key_violation", err)
	}
}

func TestOneCloudAccountPerEnvironmentPerProvider(t *testing.T) {
	s := storetest.New(t)
	a := seed(t, s, "tat")
	ctx := context.Background()

	err := s.InTenant(ctx, a.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name)
			VALUES ($1, $2, 'tencent', 'uin-second', 'second')`, a.tenant, a.env)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("second tencent account in one environment: err = %v, want unique_violation", err)
	}
}

func TestAppRoleCannotBypassRLS(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()

	var bypass, super bool
	if err := s.AppPool().QueryRow(ctx, `SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&bypass, &super); err != nil {
		t.Fatal(err)
	}
	if bypass || super {
		t.Fatalf("app role bypassrls=%v superuser=%v, want both false", bypass, super)
	}

	for _, table := range tenantScoped {
		_, err := s.AppPool().Exec(ctx, fmt.Sprintf("ALTER TABLE %s DISABLE ROW LEVEL SECURITY", pgx.Identifier{table}.Sanitize()))
		if err == nil {
			t.Errorf("app role disabled RLS on %s", table)
		}
	}
}

func TestEveryTableIsListed(t *testing.T) {
	s := storetest.New(t)
	rows, err := s.AppPool().Query(context.Background(), `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname NOT LIKE 'goose_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	listed := map[string]bool{}
	for _, table := range tenantScoped {
		listed[table] = true
	}
	for rows.Next() {
		var name string
		var rls, force bool
		if err := rows.Scan(&name, &rls, &force); err != nil {
			t.Fatal(err)
		}
		if !listed[name] {
			t.Errorf("table %s is not in tenantScoped; add it and its RLS policy", name)
		}
		if !rls || !force {
			t.Errorf("table %s: rowsecurity=%v force=%v, want both true", name, rls, force)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestClientIdPCannotGrantRolesElsewhere(t *testing.T) {
	s := storetest.New(t)
	a := seed(t, s, "tat")
	b := seed(t, s, "acme")
	ctx := context.Background()
	err := s.InTenant(ctx, a.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO idp_group_roles (tenant_id, idp_id, group_name, role, target_tenant_id)
			SELECT tenant_id, id, 'sneaky', 'platform_admin', $1 FROM identity_providers`, b.tenant)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("client IdP binding into another tenant: err = %v, want check_violation", err)
	}
}

func TestInTenantRejectsMalformedID(t *testing.T) {
	s := storetest.New(t)
	err := s.InTenant(context.Background(), "not-a-uuid", func(pgx.Tx) error { return nil })
	if err == nil {
		t.Fatal("want error for malformed tenant id")
	}
}

func isRLSViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}

func TestMain(m *testing.M) {
	if os.Getenv(storetest.EnvURL) == "" && os.Getenv("KEEL_REQUIRE_DB") != "" {
		fmt.Fprintf(os.Stderr, "%s must be set when KEEL_REQUIRE_DB is set\n", storetest.EnvURL)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
