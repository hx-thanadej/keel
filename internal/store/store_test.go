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

	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// tenantScoped lists every table that must be isolated per Tenant. Adding a
// table to the schema without adding it here fails TestEveryTableIsListed.
var tenantScoped = []string{"tenants", "teams", "projects", "environments", "cloud_accounts", "services"}

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
		return q(`INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'api', 'API') RETURNING id`, &f.service, f.tenant, f.project, f.team)
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
