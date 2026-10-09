package boundary_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/boundary"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type fakeIAM struct {
	policies   map[string]string
	ids        map[string]int64
	roles      []boundary.Role
	boundaries map[string]int64 // role id → policy
}

func (f *fakeIAM) EnsurePolicy(_ context.Context, name, doc, _ string) (int64, error) {
	if _, ok := f.ids[name]; !ok {
		f.ids[name] = int64(1000 + len(f.ids))
	}
	f.policies[name] = doc
	return f.ids[name], nil
}
func (f *fakeIAM) Roles(context.Context) ([]boundary.Role, error) { return f.roles, nil }
func (f *fakeIAM) RoleBoundary(_ context.Context, id string) (int64, error) {
	return f.boundaries[id], nil
}
func (f *fakeIAM) PutBoundary(_ context.Context, name string, p int64) error {
	for _, r := range f.roles {
		if r.Name == name {
			f.boundaries[r.ID] = p
		}
	}
	return nil
}

func newIAM() *fakeIAM {
	return &fakeIAM{policies: map[string]string{}, ids: map[string]int64{}, boundaries: map[string]int64{},
		roles: []boundary.Role{{ID: "r1", Name: "keel-deploy"}, {ID: "r2", Name: "OrganizationAccessControlRole"}, {ID: "r3", Name: "SLR_TKE", Type: "service_linked"}}}
}

func TestDocumentNeverAllowsIdentityAdministration(t *testing.T) {
	for _, prod := range []bool{false, true} {
		d := boundary.Document(prod)
		if !strings.Contains(d, `{"action":["cam:*","organization:*","cloudaudit:*","sts:AssumeRoleWithSAML"],"effect":"deny"`) {
			t.Fatalf("prod=%v: %s", prod, d)
		}
		if strings.Contains(d, "cvm:TerminateInstances") != prod {
			t.Fatalf("prod=%v destructive deny mismatch", prod)
		}
	}
}

func TestApplyStampsOnlyGovernedRoles(t *testing.T) {
	iam := newIAM()
	res, err := boundary.Apply(context.Background(), iam, true, true)
	if err != nil || len(res.Stamped) != 1 || res.Stamped[0] != "keel-deploy" || iam.boundaries["r2"] != 0 || iam.boundaries["r3"] != 0 {
		t.Fatalf("%+v %v %v", res, err, iam.boundaries)
	}
	if res, _ := boundary.Apply(context.Background(), iam, true, true); len(res.Stamped) != 0 {
		t.Fatal("stamped twice")
	}
}

func TestCheckReportsRolesOutsideTheBoundary(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project, env string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&env); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name, boundary_version) VALUES ($1, $2, 'tencent', '100001', 'p', $3)`, tenant, env, boundary.Version)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	iam := newIAM()
	_, _ = boundary.Apply(ctx, iam, true, true)
	// Someone creates a role in the console, bypassing Keel.
	iam.roles = append(iam.roles, boundary.Role{ID: "r9", Name: "admin-from-console"})
	m := boundary.Manager{Store: s, Provider: "tencent", IAM: func(string) (boundary.IAM, error) { return iam, nil }, Now: storetest.Clock()}
	res, err := m.Check(ctx)
	if err != nil || res.Missing != 1 || iam.boundaries["r9"] != 0 {
		t.Fatalf("%+v %v (must report, not stamp)", res, err)
	}
	count := func() int {
		var n int
		_ = s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE kind = 'permission_boundary' AND status = 'open'`).Scan(&n)
		})
		return n
	}
	if count() != 1 {
		t.Fatal("no Finding for the console role")
	}
	iam.roles = iam.roles[:3]
	if _, err := m.Check(ctx); err != nil || count() != 0 {
		t.Fatalf("not resolved after removal: %v", err)
	}
	storetest.ClockedFindings(t, s, "permission_boundary")
}
