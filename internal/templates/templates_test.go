package templates_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/catalogsync"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
	"github.com/hx-thanadej/keel/internal/templates"
)

type fakeGit struct {
	mu        sync.Mutex
	repos     map[string]*templates.RepoInfo
	heads     map[string]string
	files     map[string]string // full/path
	props     map[string]map[string]string
	scanning  map[string]bool
	teams     map[string]string
	generated int
	emptyFor  int // Repo reports a new repo empty this many times
}

func (f *fakeGit) Repo(_ context.Context, full string) (templates.RepoInfo, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.repos[full]
	if !ok {
		return templates.RepoInfo{}, false, nil
	}
	if r.Empty && f.emptyFor > 0 {
		f.emptyFor--
		return *r, true, nil
	}
	r.Empty = false
	return *r, true, nil
}
func (f *fakeGit) Head(_ context.Context, full, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heads[full], nil
}
func (f *fakeGit) Generate(_ context.Context, template, owner, name, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.generated++
	f.repos[owner+"/"+name] = &templates.RepoInfo{ID: 7000 + int64(f.generated), OwnerID: 42, DefaultBranch: "main", Empty: true}
	return nil
}
func (f *fakeGit) PutFile(_ context.Context, full, _, path, _ string, content []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.files[full+"/"+path] == string(content) {
		return false, nil
	}
	f.files[full+"/"+path] = string(content)
	return true, nil
}
func (f *fakeGit) SetProperties(_ context.Context, _, repo string, props map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.props[repo] = props
	return nil
}
func (f *fakeGit) EnableSecretScanning(_ context.Context, full string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scanning[full] = true
	return nil
}
func (f *fakeGit) GrantTeam(_ context.Context, _, team, full, perm string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.teams[full] = team + ":" + perm
	return nil
}

func newGit() *fakeGit {
	return &fakeGit{repos: map[string]*templates.RepoInfo{"acme/tmpl-go": {ID: 1, OwnerID: 42, DefaultBranch: "main"}},
		heads: map[string]string{"acme/tmpl-go": "1111111111111111111111111111111111111111"}, files: map[string]string{},
		props: map[string]map[string]string{}, scanning: map[string]bool{}, teams: map[string]string{}, emptyFor: 2}
}

type world struct {
	s               *store.Store
	tenant, project string
}

func setup(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s}
	w.tenant, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		var team string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, w.tenant).Scan(&team); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, w.tenant, team).Scan(&w.project)
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

var eng = activity.Actor{Type: activity.ActorHuman, UID: "user:eng@harmonyx.co"}

func creator(w world, g *fakeGit, ref string) templates.Creator {
	return templates.Creator{Store: w.s, Git: g, Org: "acme", ReusableWorkflow: "acme/keel-workflows/.github/workflows/build.yml@abc123", KeelURL: "https://keel.example.com",
		Templates: map[string]templates.Template{"go-service": {Name: "go-service", Repo: "acme/tmpl-go", Ref: ref}}}
}

func TestCreateServiceFromTemplate(t *testing.T) {
	w := setup(t)
	g := newGit()
	c := creator(w, g, "1111111111111111111111111111111111111111")
	e := flow.New(w.s, c.Def())
	flowtest.Start(t, w.s, e)
	ctx := context.Background()

	if _, _, err := c.Request(ctx, e, w.tenant, w.project, "Bad Slug", "", "go-service", "", eng); !errors.Is(err, templates.ErrInvalid) {
		t.Fatalf("bad slug: %v", err)
	}
	f, _, err := c.Request(ctx, e, w.tenant, w.project, "crm-api", "CRM API", "go-service", "prod", eng)
	if err != nil {
		t.Fatal(err)
	}
	f = flowtest.Wait(t, e, w.tenant, f.ID, "succeeded")
	if g.generated != 1 || f.Steps[2].Attempts != 3 {
		t.Fatalf("generated %d ready attempts %d", g.generated, f.Steps[2].Attempts)
	}
	if p := g.props["crm-api"]; p["keel-tenant"] != "tat" || p["keel-project"] != "tat-crm" || p["keel-tier"] != "prod" || !g.scanning["acme/crm-api"] || g.teams["acme/crm-api"] != "crm:push" {
		t.Fatalf("governance props %v scanning %v teams %v", g.props, g.scanning, g.teams)
	}
	// The catalog-info Keel wrote is read back by catalog sync as the same Service.
	comps, err := catalogsync.Parse([]byte(g.files["acme/crm-api/catalog-info.yaml"]))
	if err != nil || len(comps) != 1 || comps[0].Name != "crm-api" || comps[0].Owner != "crm" || comps[0].System != "tat-crm" || comps[0].Tenant != "tat" {
		t.Fatalf("catalog-info %+v %v", comps, err)
	}
	var svcID string
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM services WHERE slug = 'crm-api'`).Scan(&svcID)
	}); err != nil {
		t.Fatal(err)
	}
	if wf := g.files["acme/crm-api/.github/workflows/keel.yml"]; !strings.Contains(wf, "service: "+svcID) || !strings.Contains(wf, "tenant: "+w.tenant) || !strings.Contains(wf, "keel-url: https://keel.example.com") {
		t.Fatalf("workflow inputs:\n%s", wf)
	}
	if !strings.Contains(g.files["acme/crm-api/.github/workflows/keel.yml"], "uses: acme/keel-workflows/.github/workflows/build.yml@abc123") ||
		!strings.Contains(g.files["acme/crm-api/renovate.json"], `"minimumReleaseAge": "3 days"`) ||
		g.files["acme/crm-api/.github/CODEOWNERS"] == "" || g.files["acme/crm-api/docs/decisions/0001-record-architecture-decisions.md"] == "" {
		t.Fatalf("files %v", keys(g.files))
	}
	var tmpl, version string
	var repoID int64
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT template, template_version, repository_id FROM services WHERE slug = 'crm-api'`).Scan(&tmpl, &version, &repoID)
	}); err != nil || tmpl != "go-service" || !strings.HasPrefix(version, "1111") || repoID != 7001 {
		t.Fatalf("service %s %s %d %v", tmpl, version, repoID, err)
	}
	if _, _, err := c.Request(ctx, e, w.tenant, w.project, "crm-api", "", "go-service", "", eng); !errors.Is(err, templates.ErrInvalid) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestMovedTemplateStopsTheFlow(t *testing.T) {
	w := setup(t)
	g := newGit()
	c := creator(w, g, "2222222222222222222222222222222222222222")
	e := flow.New(w.s, c.Def())
	flowtest.Start(t, w.s, e)
	f, _, err := c.Request(context.Background(), e, w.tenant, w.project, "crm-web", "", "go-service", "", eng)
	if err != nil {
		t.Fatal(err)
	}
	f = flowtest.Wait(t, e, w.tenant, f.ID, "failed")
	if f.Error == nil || !strings.Contains(*f.Error, "is pinned at 222222222222") || g.generated != 0 {
		t.Fatalf("%v generated %d", f.Error, g.generated)
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
