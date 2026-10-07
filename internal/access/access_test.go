package access_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/access"
	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type fakeDir struct {
	mu          sync.Mutex
	configs     map[string]string // name → id
	users       map[string]string // email → id
	assignments map[string]bool   // cfg|account|user
}

func newDir() *fakeDir {
	return &fakeDir{configs: map[string]string{}, users: map[string]string{"eng@harmonyx.co": "u-eng", "lead@harmonyx.co": "u-lead"}, assignments: map[string]bool{}}
}
func (f *fakeDir) EnsureRoleConfiguration(_ context.Context, name, _, _ string, _ int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.configs[name]; !ok {
		f.configs[name] = "rc-" + name
	}
	return f.configs[name], nil
}
func (f *fakeDir) UserID(_ context.Context, email string) (string, bool, error) {
	id, ok := f.users[email]
	return id, ok, nil
}
func (f *fakeDir) Assign(_ context.Context, cfg string, acct int64, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assignments[fmt.Sprintf("%s|%d|%s", cfg, acct, user)] = true
	return nil
}
func (f *fakeDir) Unassign(_ context.Context, cfg string, acct int64, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.assignments, fmt.Sprintf("%s|%d|%s", cfg, acct, user))
	return nil
}
func (f *fakeDir) Assignments(context.Context, int64) ([]access.Assignment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []access.Assignment
	for k := range f.assignments {
		var cfg, user string
		var acct int64
		_, _ = fmt.Sscanf(k, "%s", &cfg)
		out = append(out, access.Assignment{RoleConfiguration: cfg, PrincipalID: user, PrincipalType: "User", RoleName: fmt.Sprint(acct)})
	}
	return out, nil
}

type world struct {
	s                       *store.Store
	tenant, team, dev, prod string
}

func setup(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s}
	w.tenant, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		var project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.tenant).Scan(&w.team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tenant, w.team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'dev') RETURNING id`, w.tenant, project).Scan(&w.dev); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, w.tenant, project).Scan(&w.prod); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', '100002', 'prod'), ($1, $3, 'tencent', '100001', 'dev')`, w.tenant, w.prod, w.dev)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

var (
	lead = activity.Actor{Type: activity.ActorHuman, UID: "user:lead@harmonyx.co"}
	sec  = activity.Actor{Type: activity.ActorHuman, UID: "user:security@harmonyx.co"}
)

func TestRoleEligibility(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	dir := newDir()
	svc, err := access.New(w.s, dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.RequestRole(ctx, w.tenant, w.dev, w.team, "operator", lead)
	if err != nil || r.State != "active" || r.RoleConfiguration == nil || *r.RoleConfiguration != "rc-keel-operator" {
		t.Fatalf("dev operator %+v %v", r, err)
	}
	p, err := svc.RequestRole(ctx, w.tenant, w.prod, w.team, "operator", lead)
	if err != nil || p.State != "requested" || !p.Decision.NeedsApproval {
		t.Fatalf("prod operator %+v %v", p, err)
	}
	if again, _ := svc.RequestRole(ctx, w.tenant, w.prod, w.team, "operator", lead); again.ID != p.ID {
		t.Fatal("duplicate request")
	}
	if _, err := svc.DecideRole(ctx, w.tenant, p.ID, true, lead); !errors.Is(err, access.ErrState) {
		t.Fatalf("self decision: %v", err)
	}
	if p, err = svc.DecideRole(ctx, w.tenant, p.ID, true, sec); err != nil || p.State != "active" || p.RoleConfiguration == nil {
		t.Fatalf("approved %+v %v", p, err)
	}
	if ro, _ := svc.RequestRole(ctx, w.tenant, w.prod, w.team, "read-only", lead); ro.State != "active" {
		t.Fatalf("prod read-only %+v", ro)
	}
	if _, err := svc.RequestRole(ctx, w.tenant, w.prod, w.team, "god-mode", lead); !errors.Is(err, access.ErrInvalid) {
		t.Fatalf("unknown template: %v", err)
	}
}
