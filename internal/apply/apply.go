package apply

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/rightsize"
)

// ErrUnsupported means Keel can't make the change itself; the message says
// what to do by hand.
var ErrUnsupported = errors.New("apply manually")

// Applier opens pull requests for accepted recommendations and marks them
// applied once merged.
type Applier struct {
	Recs rightsize.Service
	Git  GitHub
}

const maxFiles = 500

// Apply opens a pull request for a recommendation (accepting it first if
// still open) and returns the PR URL.
func (a Applier) Apply(ctx context.Context, tenant, id string, by activity.Actor) (string, error) {
	r, err := a.Recs.Get(ctx, tenant, id)
	if err != nil {
		return "", err
	}
	if r.PRURL != nil {
		return *r.PRURL, nil
	}
	if r.State != "open" && r.State != "accepted" {
		return "", rightsize.ErrState
	}
	var c change
	switch {
	case r.ResourceType == "k8s_workload" && r.Action == "resize_requests":
		c, err = a.resizeRequests(ctx, tenant, r)
	case r.ResourceType == "k8s_workload" && r.Action == "schedule":
		c, err = a.offHoursSchedule(ctx, tenant, r)
	default:
		err = fmt.Errorf("%w: Keel opens pull requests for Kubernetes request changes and off-hours schedules; change %s %s by hand", ErrUnsupported, r.ResourceType, r.ResourceID)
	}
	if err != nil {
		return "", err
	}
	if r.State == "open" {
		if _, err := a.Recs.Accept(ctx, tenant, id, by); err != nil {
			return "", err
		}
	}
	branch := c.branch + "-" + id[len(id)-8:]
	if err := a.Git.Branch(ctx, c.repo, c.base, branch); err != nil {
		return "", err
	}
	if err := a.Git.Commit(ctx, c.repo, branch, c.path, c.sha, c.title+"\n\nOpened by Keel from recommendation "+id, c.content); err != nil {
		return "", err
	}
	pr, err := a.Git.OpenPR(ctx, c.repo, branch, c.base, c.title, fmt.Sprintf("Keel rightsizing recommendation `%s`.\n\n", id)+c.body)
	if err != nil {
		return "", err
	}
	if err := a.Recs.SetPR(ctx, tenant, id, pr.HTMLURL, by); err != nil {
		return "", err
	}
	return pr.HTMLURL, nil
}

// change is one file a pull request writes. An empty sha creates the file.
type change struct {
	repo, base, branch string
	path, sha          string
	content            []byte
	title, body        string
}

// target is a Service repository's default branch and its YAML files.
type target struct {
	repo, base string
	files      []string
}

func (a Applier) target(ctx context.Context, tenant string, r rightsize.Recommendation, workload string) (target, error) {
	repoURL, err := a.serviceRepo(ctx, tenant, *r.ProjectID, workload)
	if err != nil {
		return target{}, err
	}
	repo, err := Repo(repoURL)
	if err != nil {
		return target{}, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	base, err := a.Git.defaultBranch(ctx, repo)
	if err != nil {
		return target{}, err
	}
	files, err := a.Git.YAMLFiles(ctx, repo, base)
	if err != nil {
		return target{}, err
	}
	if len(files) > maxFiles {
		files = files[:maxFiles]
	}
	return target{repo: repo, base: base, files: files}, nil
}

// manifest is the one YAML file in the Service repo that declares a
// workload of one of kinds with exactly this name and namespace. A
// manifest without metadata.namespace never matches: the namespace it
// lands in is decided elsewhere (Kustomize, Helm, kubectl -n), so Keel
// can't tell a production copy from a non-production one.
func (a Applier) manifest(ctx context.Context, t target, kinds map[string]bool, workload, namespace string) (manifest, error) {
	var found []manifest
	unnamespaced := false
	for _, f := range t.files {
		src, sha, err := a.Git.File(ctx, t.repo, f, t.base)
		if err != nil {
			return manifest{}, err
		}
		if !strings.Contains(string(src), workload) {
			continue
		}
		docs, err := decodeDocs(src)
		if err != nil {
			continue // unparsable templates (e.g. Helm)
		}
		for _, d := range docs {
			if len(d.Content) == 0 {
				continue
			}
			root, meta := d.Content[0], get(d.Content[0], "metadata")
			kind := scalar(get(root, "kind"))
			if !kinds[kind] || scalar(get(meta, "name")) != workload {
				continue
			}
			switch scalar(get(meta, "namespace")) {
			case namespace:
				found = append(found, manifest{path: f, sha: sha, kind: kind, src: src})
			case "":
				unnamespaced = true
			}
		}
	}
	switch {
	case len(found) > 1:
		paths := make([]string, len(found))
		for i, m := range found {
			paths[i] = m.path
		}
		return manifest{}, fmt.Errorf("%w: %s/%s is declared more than once in %s (%s); change the right one by hand", ErrUnsupported, namespace, workload, t.repo, strings.Join(paths, ", "))
	case len(found) == 1:
		return found[0], nil
	case unnamespaced:
		return manifest{}, fmt.Errorf("%w: %q in %s has no metadata.namespace, so Keel can't tell it is the %s copy; namespaces set by Kustomize or Helm need a manual change", ErrUnsupported, workload, t.repo, namespace)
	}
	return manifest{}, fmt.Errorf("%w: no %s/%s workload in plain YAML in %s (Helm or Kustomize patches need a manual change)", ErrUnsupported, namespace, workload, t.repo)
}

// manifest is a YAML file and the kind of the workload it declares.
type manifest struct {
	path, sha, kind string
	src             []byte
}

func (a Applier) resizeRequests(ctx context.Context, tenant string, r rightsize.Recommendation) (change, error) {
	workload, _ := r.Evidence["workload"].(string)
	namespace, _ := r.Evidence["namespace"].(string)
	container, _ := r.Evidence["container"].(string)
	cpu, _ := r.Recommended["cpu"].(string)
	mem, _ := r.Recommended["memory"].(string)
	if workload == "" || namespace == "" || container == "" || cpu == "" || mem == "" || r.ProjectID == nil {
		return change{}, fmt.Errorf("%w: the recommendation lacks workload/namespace/container details", ErrUnsupported)
	}
	t, err := a.target(ctx, tenant, r, workload)
	if err != nil {
		return change{}, err
	}
	m, err := a.manifest(ctx, t, workloadKinds, workload, namespace)
	if err != nil {
		return change{}, err
	}
	out, ok, err := PatchRequests(m.src, workload, namespace, container, cpu, mem)
	if err != nil || !ok {
		return change{}, fmt.Errorf("%w: %s declares %s/%s but no container %q to patch", ErrUnsupported, m.path, namespace, workload, container)
	}
	c := change{repo: t.repo, base: t.base, branch: "keel/rightsize", path: m.path, sha: m.sha, content: out}
	c.title = fmt.Sprintf("Right-size %s/%s: requests cpu %s, memory %s", workload, container, cpu, mem)
	c.body = fmt.Sprintf("| | current | recommended |\n|---|---|---|\n| cpu request | %v | %s |\n| memory request | %v | %s |\n\n"+
		"**Expected saving:** about %s %s/month (%s cost).\n\n**Evidence:** %v days, %v replica(s), CPU p95 max %v, memory max %v. Confidence %.2f.\n\n"+
		"Merge to apply; Keel marks the recommendation applied and tracks realised savings.",
		r.Current["cpu"], cpu, r.Current["memory"], mem, r.MonthlySavings, r.Currency, r.SavingsBasis,
		r.Evidence["lookback_days"], r.Evidence["replicas"], r.Evidence["cpu_p95_max"], r.Evidence["memory_max"], r.Confidence)
	return c, nil
}

func (a Applier) serviceRepo(ctx context.Context, tenant, project, workload string) (string, error) {
	var repo string
	err := a.Recs.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT repository FROM services WHERE project_id = $1 AND slug = $2 AND repository <> '' AND archived_at IS NULL`, project, workload).Scan(&repo)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: no Service %q with a repository in this Project (add catalog-info.yaml)", ErrUnsupported, workload)
	}
	return repo, err
}

// SyncResult counts a merge-tracking pass.
type SyncResult struct{ Applied, Reopened int }

// Sync marks recommendations applied when their PR merged, and reopens them
// when the PR was closed without merging.
func (a Applier) Sync(ctx context.Context) (SyncResult, error) {
	var res SyncResult
	rows, err := a.Recs.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	keel := activity.Actor{Type: activity.ActorKeel, UID: "keel:apply"}
	for _, t := range tenants {
		recs, err := a.Recs.List(ctx, t, rightsize.Filter{State: "accepted"})
		if err != nil {
			return res, err
		}
		for _, r := range recs {
			if r.PRURL == nil {
				continue
			}
			pr, err := a.Git.PR(ctx, *r.PRURL)
			if err != nil {
				return res, err
			}
			switch {
			case pr.Merged:
				if err := a.Recs.MarkApplied(ctx, t, r.ID, "merged "+*r.PRURL, *r.PRURL, keel); err != nil {
					return res, err
				}
				res.Applied++
			case pr.State == "closed":
				if err := a.Recs.Reopen(ctx, t, r.ID, "pull request closed without merging", keel); err != nil {
					return res, err
				}
				res.Reopened++
			}
		}
	}
	return res, nil
}
