package ciidentity_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/ciidentity"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type fakeIAM struct {
	mu        sync.Mutex
	providers map[string]ciidentity.Provider
	roles     map[string]string
	calls     []string
}

func newIAM() *fakeIAM {
	return &fakeIAM{providers: map[string]ciidentity.Provider{}, roles: map[string]string{}}
}
func (f *fakeIAM) OIDCProvider(_ context.Context, n string) (ciidentity.Provider, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.providers[n]
	return p, ok, nil
}
func (f *fakeIAM) CreateOIDCProvider(_ context.Context, n string, p ciidentity.Provider) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "CreateOIDCConfig")
	f.providers[n] = p
	return nil
}
func (f *fakeIAM) UpdateOIDCProvider(_ context.Context, n string, p ciidentity.Provider) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateOIDCConfig")
	f.providers[n] = p
	return nil
}
func (f *fakeIAM) RoleTrust(_ context.Context, n string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.roles[n]
	return t, ok, nil
}
func (f *fakeIAM) CreateRole(_ context.Context, n, trust, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "CreateRole")
	f.roles[n] = trust
	return nil
}
func (f *fakeIAM) UpdateRoleTrust(_ context.Context, n, trust string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "UpdateAssumeRolePolicy")
	f.roles[n] = trust
	return nil
}

const jwks1 = `{"keys":[{"kid":"a","kty":"RSA"},{"kid":"b","kty":"RSA"}]}`
const jwks2 = `{"keys":[{"kid":"b","kty":"RSA"},{"kid":"c","kty":"RSA"}]}`

func TestTrustIsPinnedToIdsAndEnvironment(t *testing.T) {
	subs, err := ciidentity.Subjects([]ciidentity.Binding{{OwnerID: 42, RepoID: 900, Environment: "prod"}, {OwnerID: 42, RepoID: 900, Environment: "prod"}})
	if err != nil || len(subs) != 1 {
		t.Fatal(subs, err)
	}
	tr := ciidentity.Trust("100001", ciidentity.Config{}, subs)
	for _, want := range []string{`"oidc:sub":["repository_owner_id:42:repository_id:900:environment:prod"]`, `"oidc:iss":["https://token.actions.githubusercontent.com"]`,
		`"oidc:aud":["sts.tencentcloudapi.com"]`, `qcs::cam::uin/100001:oidc-provider/github-actions`, `"name/sts:AssumeRoleWithWebIdentity"`} {
		if !strings.Contains(tr, want) {
			t.Fatalf("trust lacks %s: %s", want, tr)
		}
	}
	if empty := ciidentity.Trust("1", ciidentity.Config{}, nil); !strings.Contains(empty, "keel:no-repository-yet") {
		t.Fatal("empty trust must name an impossible subject")
	}
	var many []ciidentity.Binding
	for i := 0; i < 11; i++ {
		many = append(many, ciidentity.Binding{OwnerID: 1, RepoID: int64(i), Environment: "dev"})
	}
	if s, err := ciidentity.Subjects(many); !errors.Is(err, ciidentity.ErrTooManyRepos) || len(s) != 10 {
		t.Fatal(len(s), err)
	}
}

func TestEnsureIsIdempotentAndCreatesNoKeys(t *testing.T) {
	iam := newIAM()
	ctx := context.Background()
	subs := []string{"repository_owner_id:42:repository_id:900:environment:prod"}
	ch, err := ciidentity.Ensure(ctx, iam, "100001", ciidentity.Config{}, jwks1, subs)
	if err != nil || !ch.ProviderCreated || !ch.RoleCreated {
		t.Fatal(ch, err)
	}
	if p := iam.providers["github-actions"]; !p.AutoRotate || p.ClientIDs[0] != "sts.tencentcloudapi.com" {
		t.Fatalf("provider %+v", p)
	}
	if ch, err := ciidentity.Ensure(ctx, iam, "100001", ciidentity.Config{}, jwks1, subs); err != nil || ch != (ciidentity.Change{}) {
		t.Fatalf("second ensure %+v %v", ch, err)
	}
	for _, c := range iam.calls {
		if strings.Contains(c, "AccessKey") {
			t.Fatalf("created a key: %v", iam.calls)
		}
	}
}

type world struct {
	s                                 *store.Store
	tenant, project, team, env, accID string
}

func setup(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s}
	w.tenant, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.tenant).Scan(&w.team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tenant, w.team).Scan(&w.project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, w.tenant, w.project).Scan(&w.env); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository_id, repository_owner_id) VALUES ($1, $2, $3, 'crm-api', 'CRM API', 900, 42)`, w.tenant, w.project, w.team); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name, ci_identity_at) VALUES ($1, $2, 'tencent', '100001', 'p', now()) RETURNING id`, w.tenant, w.env).Scan(&w.accID)
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

func openFinding(t *testing.T, w world) (string, string) {
	t.Helper()
	var sev, team string
	err := w.s.InTenant(context.Background(), w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT severity, owner_team_id::text FROM findings WHERE kind = 'ci_identity' AND status = 'open'`).Scan(&sev, &team)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return sev, team
}

func TestSyncFollowsKeyRotationAndNewRepositories(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	iam := newIAM()
	keys := jwks1
	var fail error
	m := ciidentity.Manager{Store: w.s, Provider: "tencent", IAM: func(string) (ciidentity.IAM, error) { return iam, nil },
		JWKS: func(context.Context) (string, error) { return keys, fail }, Now: storetest.Clock()}
	if res, err := m.Sync(ctx); err != nil || res.Changed != 1 || res.Failed != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	// GitHub rotates its keys.
	keys = jwks2
	if res, err := m.Sync(ctx); err != nil || res.Changed != 1 || !ciidentity.SameKeys(iam.providers["github-actions"].Keys, jwks2) {
		t.Fatalf("keys not synced: %+v", iam.providers)
	}
	// GitHub is unreachable: a high Finding for the owning Team.
	fail = fmt.Errorf("dial tcp: timeout")
	if res, err := m.Sync(ctx); res.Failed != 1 || err != nil {
		t.Fatalf("%+v %v", res, err)
	}
	if sev, team := openFinding(t, w); sev != "high" || team != w.team {
		t.Fatalf("finding %s %s", sev, team)
	}
	fail = nil
	// A second repository joins the Project.
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository_id, repository_owner_id) VALUES ($1, $2, $3, 'crm-web', 'CRM Web', 901, 42)`, w.tenant, w.project, w.team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if res, err := m.Sync(ctx); err != nil || res.Changed != 1 || !strings.Contains(iam.roles["keel-deploy"], "repository_id:901:environment:prod") {
		t.Fatalf("trust %s", iam.roles["keel-deploy"])
	}
	if sev, _ := openFinding(t, w); sev != "" {
		t.Fatal("finding not resolved after a clean sync")
	}
	storetest.ClockedFindings(t, w.s, "ci_identity")
}
