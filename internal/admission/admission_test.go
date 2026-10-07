package admission_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/admission"
	"github.com/hx-thanadej/keel/internal/apply"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

var params = admission.Params{Project: "tat-crm", Environment: "prod", Registry: "acme.tencentcloudcr.com", Namespace: "tat-tat-crm",
	BuilderSubject: "https://github.com/acme/keel-workflows/.github/workflows/keel-build.yml@*", Mode: "warn"}

func docs(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out []map[string]any
	for {
		var m map[string]any
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("invalid YAML: %v\n%s", err, b)
		}
		out = append(out, m)
	}
}

func TestRenderWarnThenEnforce(t *testing.T) {
	warn, h1, err := admission.Render(params)
	if err != nil {
		t.Fatal(err)
	}
	ds := docs(t, warn)
	if len(ds) != 3 || ds[0]["kind"] != "ImageValidatingPolicy" || ds[0]["apiVersion"] != "policies.kyverno.io/v1" || ds[1]["kind"] != "ValidatingAdmissionPolicy" || ds[2]["kind"] != "ValidatingAdmissionPolicyBinding" {
		t.Fatalf("documents %v", ds)
	}
	spec := ds[0]["spec"].(map[string]any)
	if fmt.Sprint(spec["validationActions"]) != "[Audit]" || fmt.Sprint(ds[2]["spec"].(map[string]any)["validationActions"]) != "[Warn Audit]" {
		t.Fatalf("warn mode actions %v / %v", spec["validationActions"], ds[2]["spec"])
	}
	refs := spec["matchImageReferences"].([]any)[0].(map[string]any)
	if refs["glob"] != "acme.tencentcloudcr.com/tat-tat-crm/*" {
		t.Fatalf("image glob %v", refs)
	}
	for _, v := range spec["validations"].([]any) {
		if !strings.Contains(v.(map[string]any)["expression"].(string), "attestors.builder") {
			t.Fatal("validation does not use the declared attestor")
		}
	}
	p := params
	p.Mode = "enforce"
	enforce, h2, _ := admission.Render(p)
	ds = docs(t, enforce)
	if fmt.Sprint(ds[0]["spec"].(map[string]any)["validationActions"]) != "[Deny]" || fmt.Sprint(ds[2]["spec"].(map[string]any)["validationActions"]) != "[Deny]" || h1 == h2 {
		t.Fatalf("enforce %v %v", ds[0]["spec"], ds[2]["spec"])
	}
	if strings.Contains(string(warn), "ClusterPolicy") {
		t.Fatal("deprecated Kyverno ClusterPolicy rendered")
	}
	p.Mode = "off"
	if _, _, err := admission.Render(p); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

type fakeGit struct {
	prs   []string
	files map[string]string
}

func (f *fakeGit) DefaultBranch(context.Context, string) (string, error) { return "main", nil }
func (f *fakeGit) File(context.Context, string, string, string) ([]byte, string, error) {
	return nil, "", errors.New("github GET: HTTP 404: Not Found")
}
func (f *fakeGit) Branch(context.Context, string, string, string) error { return nil }
func (f *fakeGit) Commit(_ context.Context, repo, branch, path, sha, _ string, c []byte) error {
	if sha != "" {
		return errors.New("expected a new file")
	}
	f.files[repo+"/"+path+"@"+branch] = string(c)
	return nil
}
func (f *fakeGit) OpenPR(_ context.Context, repo, head, _, _, _ string) (apply.PullRequest, error) {
	u := fmt.Sprintf("https://github.com/%s/pull/%d", repo, len(f.prs)+1)
	f.prs = append(f.prs, head)
	return apply.PullRequest{HTMLURL: u}, nil
}

func TestReconcileDeliversOnlyChanges(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var prod string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name, config_repo, registry_namespace) VALUES ($1, $2, 'tat-crm', 'TAT CRM', 'acme/tat-crm-config', 'tat-tat-crm') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'no-repo', 'No Repo')`, tenant, team); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO environments (tenant_id, project_id, name) SELECT $1, id, 'dev' FROM projects WHERE slug = 'no-repo'`, tenant); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&prod)
	}); err != nil {
		t.Fatal(err)
	}
	g := &fakeGit{files: map[string]string{}}
	svc := admission.Service{Store: s, Git: g, Registry: params.Registry, BuilderSubject: params.BuilderSubject}
	res, err := svc.Reconcile(ctx)
	if err != nil || res.PRs != 1 || res.Skipped != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if res, _ := svc.Reconcile(ctx); res.PRs != 0 {
		t.Fatalf("unchanged policies re-proposed: %+v", res)
	}
	if err := svc.SetMode(ctx, tenant, prod, "enforce", "two weeks in warn without violations", activity.Actor{Type: activity.ActorHuman, UID: "user:sec"}); err != nil {
		t.Fatal(err)
	}
	if res, _ := svc.Reconcile(ctx); res.PRs != 1 {
		t.Fatalf("mode change not delivered: %+v", res)
	}
	var enforced bool
	for k, v := range g.files {
		if strings.HasPrefix(k, "acme/tat-crm-config/envs/prod/keel-admission.yaml@") && strings.Contains(v, "[Deny]") {
			enforced = true
		}
	}
	if !enforced || len(g.prs) != 2 {
		t.Fatalf("files %v prs %v", len(g.files), g.prs)
	}
	if err := svc.SetMode(ctx, tenant, prod, "off", "", activity.Actor{UID: "x"}); !errors.Is(err, admission.ErrInvalid) {
		t.Fatalf("bad mode: %v", err)
	}
}
