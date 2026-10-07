package promotion_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/apply"
	"github.com/hx-thanadej/keel/internal/promotion"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

const kust = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
images:
  # the API image
  - name: ccr.ccs.tencentyun.com/tat/crm-api
    newTag: "1.4.0"
`

func TestPatchKustomization(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	out, changed, err := promotion.PatchKustomization([]byte(kust), []promotion.Image{{Name: "ccr.ccs.tencentyun.com/tat/crm-api", Digest: d}, {Name: "ccr.ccs.tencentyun.com/tat/crm-worker", Digest: d}})
	if err != nil || !changed {
		t.Fatal(err, changed)
	}
	s := string(out)
	if !strings.Contains(s, "# the API image") || strings.Contains(s, "newTag") || strings.Count(s, "digest: "+d) != 2 || !strings.Contains(s, "- ../../base") {
		t.Fatalf("patched:\n%s", s)
	}
	if _, changed, _ := promotion.PatchKustomization(out, []promotion.Image{{Name: "ccr.ccs.tencentyun.com/tat/crm-api", Digest: d}}); changed {
		t.Fatal("second patch changed something")
	}
}

type fakeGit struct {
	mu     sync.Mutex
	files  map[string]string // path on main
	commit map[string]string // branch → content written
	prs    map[string]*apply.PullRequest
}

func (f *fakeGit) DefaultBranch(context.Context, string) (string, error) { return "main", nil }
func (f *fakeGit) File(_ context.Context, repo, path, _ string) ([]byte, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.files[repo+"/"+path]
	if !ok {
		return nil, "", errors.New("404")
	}
	return []byte(c), "sha1", nil
}
func (f *fakeGit) Branch(context.Context, string, string, string) error { return nil }
func (f *fakeGit) Commit(_ context.Context, _, branch, _, _, _ string, content []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commit[branch] = string(content)
	return nil
}
func (f *fakeGit) OpenPR(_ context.Context, repo, head, _, title, _ string) (apply.PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pr := &apply.PullRequest{Number: len(f.prs) + 1, State: "open"}
	pr.HTMLURL = fmt.Sprintf("https://github.com/%s/pull/%d", repo, pr.Number)
	f.prs[pr.HTMLURL] = pr
	return *pr, nil
}
func (f *fakeGit) PR(_ context.Context, url string) (apply.PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.prs[url], nil
}

type fakeArgo struct {
	apps map[string]promotion.AppStatus
}

func (a *fakeArgo) App(_ context.Context, name string) (promotion.AppStatus, error) {
	return a.apps[name], nil
}

type world struct {
	s                                   *store.Store
	tenant, project, service, dev, prod string
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
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name, config_repo) VALUES ($1, $2, 'tat-crm', 'TAT CRM', 'hx/tat-crm-config') RETURNING id`, w.tenant, team).Scan(&w.project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'CRM API') RETURNING id`, w.tenant, w.project, team).Scan(&w.service); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name, promotion_order) VALUES ($1, $2, 'dev', 1) RETURNING id`, w.tenant, w.project).Scan(&w.dev); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name, promotion_order, requires_approval) VALUES ($1, $2, 'prod', 2, true) RETURNING id`, w.tenant, w.project).Scan(&w.prod)
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

var (
	eng      = activity.Actor{Type: activity.ActorHuman, UID: "user:eng@harmonyx.co"}
	approver = activity.Actor{Type: activity.ActorHuman, UID: "user:approver@tat.or.th"}
	digest   = "sha256:" + strings.Repeat("b", 64)
	image    = "ccr.ccs.tencentyun.com/tat/crm-api"
)

func newService(t *testing.T, w world) (*promotion.Service, *fakeGit, *fakeArgo) {
	t.Helper()
	g := &fakeGit{files: map[string]string{
		"hx/tat-crm-config/envs/dev/crm-api/kustomization.yaml":  kust,
		"hx/tat-crm-config/envs/prod/crm-api/kustomization.yaml": kust,
	}, commit: map[string]string{}, prs: map[string]*apply.PullRequest{}}
	a := &fakeArgo{apps: map[string]promotion.AppStatus{}}
	s, err := promotion.New(promotion.Service{Store: w.s, Git: g, Argo: a})
	if err != nil {
		t.Fatal(err)
	}
	return s, g, a
}

func TestReleaseMustBePinnedByDigest(t *testing.T) {
	w := setup(t)
	s, _, _ := newService(t, w)
	if _, err := s.CreateRelease(context.Background(), w.tenant, w.service, "1.5.0", []promotion.Image{{Name: image, Digest: "1.5.0"}}, "abc", eng); !errors.Is(err, promotion.ErrInvalid) {
		t.Fatalf("tag accepted: %v", err)
	}
}

func TestPromotionPathDevThenApprovedProd(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	s, g, argo := newService(t, w)
	rel, err := s.CreateRelease(ctx, w.tenant, w.service, "1.5.0", []promotion.Image{{Name: image, Digest: digest}}, "abc123", eng)
	if err != nil {
		t.Fatal(err)
	}
	// Straight to prod: denied, nothing opened.
	p, err := s.Promote(ctx, w.tenant, rel.ID, w.prod, eng)
	if err != nil || p.State != "denied" || p.Decision.Reasons[0] != "release is not deployed to dev yet" || len(g.prs) != 0 {
		t.Fatalf("prod first: %+v %v", p, err)
	}
	// Dev: PR pins the digest.
	p, err = s.Promote(ctx, w.tenant, rel.ID, w.dev, eng)
	if err != nil || p.State != "pr_open" || p.PRURL == nil {
		t.Fatalf("dev: %+v %v", p, err)
	}
	if again, _ := s.Promote(ctx, w.tenant, rel.ID, w.dev, eng); again.ID != p.ID {
		t.Fatal("second request opened another promotion")
	}
	for _, c := range g.commit {
		if !strings.Contains(c, "digest: "+digest) || strings.Contains(c, "newTag") {
			t.Fatalf("commit %s", c)
		}
	}
	// Not merged yet → nothing moves; merged but Argo still on the old image → merged only.
	if res, err := s.Sync(ctx); err != nil || res != (promotion.SyncResult{}) {
		t.Fatalf("%+v %v", res, err)
	}
	merged := time.Now().Add(-time.Minute)
	g.prs[*p.PRURL].Merged, g.prs[*p.PRURL].MergedAt = true, &merged
	argo.apps["tat-crm-dev-crm-api"] = promotion.AppStatus{Sync: "Synced", Health: "Healthy", Images: []string{image + "@sha256:" + strings.Repeat("0", 64)}}
	if res, err := s.Sync(ctx); err != nil || res.Merged != 1 || res.Deployed != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	argo.apps["tat-crm-dev-crm-api"] = promotion.AppStatus{Sync: "Synced", Health: "Healthy", Images: []string{image + "@" + digest}}
	if res, err := s.Sync(ctx); err != nil || res.Deployed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	var detail string
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT event->'data'->>'status_detail' FROM activities WHERE type = 'keel.deployment.succeeded'`).Scan(&detail)
	}); err != nil || !strings.Contains(detail, "lead time") {
		t.Fatalf("deployment activity %q %v", detail, err)
	}
	// Prod now passes policy but needs a Tenant Approver; the requester cannot approve.
	p, err = s.Promote(ctx, w.tenant, rel.ID, w.prod, eng)
	if err != nil || p.State != "pending_approval" || !p.Decision.Allow {
		t.Fatalf("prod: %+v %v", p, err)
	}
	if _, err := s.Approve(ctx, w.tenant, p.ID, eng); !errors.Is(err, promotion.ErrState) {
		t.Fatalf("self-approval: %v", err)
	}
	p, err = s.Approve(ctx, w.tenant, p.ID, approver)
	if err != nil || p.State != "pr_open" || p.PRURL == nil || *p.ApprovedBy != approver.UID {
		t.Fatalf("approve: %+v %v", p, err)
	}
}

func TestCriticalFindingsAndBudgetBreachBlock(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	s, g, _ := newService(t, w)
	rel, err := s.CreateRelease(ctx, w.tenant, w.service, "2.0.0", []promotion.Image{{Name: image, Digest: digest}}, "", eng)
	if err != nil {
		t.Fatal(err)
	}
	month := time.Date(time.Now().Year(), time.Now().Month(), 1, 0, 0, 0, 0, time.UTC)
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, project_id) VALUES ($1, 'vulnerability', 'cve', 'critical', 'CVE in base image', $2)`, w.tenant, w.project); err != nil {
			return err
		}
		var b string
		if err := tx.QueryRow(ctx, `INSERT INTO budgets (tenant_id, project_id, name, year, amount, currency) VALUES ($1, $2, 'CRM 2026', 2026, 12000, 'USD') RETURNING id`, w.tenant, w.project).Scan(&b); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO budget_alerts (tenant_id, budget_id, month, pct, basis, value, budget_amount) VALUES ($1, $2, $3, 125, 'actual', 1250, 1000)`, w.tenant, b, month)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p, err := s.Promote(ctx, w.tenant, rel.ID, w.dev, eng)
	if err != nil || p.State != "denied" || len(p.Decision.Reasons) != 2 || len(g.prs) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if !strings.HasPrefix(p.Decision.Reasons[0], "1 open critical Findings") || !strings.HasPrefix(p.Decision.Reasons[1], "budget hard-breached: CRM 2026 at 125%") {
		t.Fatalf("reasons %q", p.Decision.Reasons)
	}
}
