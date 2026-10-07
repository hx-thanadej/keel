// Package promotion moves Releases through Environments by pull request
// (#93, ADR-0008): a Release is a set of image digests for a Service;
// promoting it to an Environment opens a PR in the Project's config
// repository that pins those digests, after a policy decision recorded with
// its reasons. Argo CD applies the merge; Keel only reads its status, so no
// cluster credential leaves the cluster.
package promotion

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/apply"
	"github.com/hx-thanadej/keel/internal/store"
)

//go:embed policy.rego
var policySrc string

var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid")
	ErrState    = errors.New("promotion is not in a state that allows this")
)

var digestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// HardBreachPct: month-to-date actual spend at or above this share of the
// budget blocks promotions.
const HardBreachPct = 120

// Git is the slice of GitHub used to open and follow promotion PRs.
type Git interface {
	DefaultBranch(ctx context.Context, repo string) (string, error)
	File(ctx context.Context, repo, path, ref string) ([]byte, string, error)
	Branch(ctx context.Context, repo, base, branch string) error
	Commit(ctx context.Context, repo, branch, path, sha, message string, content []byte) error
	OpenPR(ctx context.Context, repo, head, base, title, body string) (apply.PullRequest, error)
	PR(ctx context.Context, htmlURL string) (apply.PullRequest, error)
}

// AppStatus is what Keel reads from Argo CD.
type AppStatus struct {
	Sync, Health string
	Images       []string
}

// Argo reads application status.
type Argo interface {
	App(ctx context.Context, name string) (AppStatus, error)
}

// Release is a deployable set of digests.
type Release struct {
	ID        string    `json:"id"`
	ServiceID string    `json:"service_id"`
	Version   string    `json:"version"`
	Images    []Image   `json:"images"`
	CommitSHA string    `json:"commit_sha"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// Decision is the policy's answer.
type Decision struct {
	Allow         bool     `json:"allow"`
	Reasons       []string `json:"reasons"`
	NeedsApproval bool     `json:"needs_approval"`
	Policy        string   `json:"policy"`
}

// Promotion is one Release moving to one Environment.
type Promotion struct {
	ID            string     `json:"id"`
	ReleaseID     string     `json:"release_id"`
	EnvironmentID string     `json:"environment_id"`
	State         string     `json:"state"`
	Decision      Decision   `json:"decision"`
	PRURL         *string    `json:"pr_url"`
	Error         *string    `json:"error"`
	RequestedBy   string     `json:"requested_by"`
	ApprovedBy    *string    `json:"approved_by"`
	RequestedAt   time.Time  `json:"requested_at"`
	MergedAt      *time.Time `json:"merged_at"`
	DeployedAt    *time.Time `json:"deployed_at"`
}

// Service runs promotions.
type Service struct {
	Store *store.Store
	Git   Git  // nil: PRs cannot be opened (promotions stop at the decision)
	Argo  Argo // nil: deployments are not confirmed
	// PathTemplate locates a Service's kustomization in the config repo.
	PathTemplate string // default "envs/{env}/{service}/kustomization.yaml"
	// AppTemplate names the Argo CD application.
	AppTemplate string // default "{project}-{env}-{service}"
	Now         func() time.Time

	query rego.PreparedEvalQuery
}

// New compiles the promotion policy.
func New(s Service) (*Service, error) {
	q, err := rego.New(rego.Query("data.keel.promotion.decision"), rego.Module("policy.rego", policySrc)).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("compile promotion policy: %w", err)
	}
	s.query = q
	if s.PathTemplate == "" {
		s.PathTemplate = "envs/{env}/{service}/kustomization.yaml"
	}
	if s.AppTemplate == "" {
		s.AppTemplate = "{project}-{env}-{service}"
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	return &s, nil
}

func render(tmpl, project, env, service string) string {
	return strings.NewReplacer("{project}", project, "{env}", env, "{service}", service).Replace(tmpl)
}

func record(ctx context.Context, tx pgx.Tx, tenant, typ, op, subject string, kind activity.Kind, outcome activity.Outcome, by activity.Actor, detail string, res ...activity.Resource) error {
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/promotion", Type: typ, Subject: subject, Operation: op,
		Kind: kind, Actor: by, Outcome: outcome, Resources: res, StatusDetail: detail, Why: activity.Why{Reason: detail}})
	return err
}

// CreateRelease records a Release. Every image must be pinned by digest.
func (s *Service) CreateRelease(ctx context.Context, tenant, service, version string, images []Image, commit string, by activity.Actor) (Release, error) {
	if version == "" || len(images) == 0 {
		return Release{}, fmt.Errorf("%w: version and at least one image are required", ErrInvalid)
	}
	for _, img := range images {
		if img.Name == "" || !digestRe.MatchString(img.Digest) {
			return Release{}, fmt.Errorf("%w: image %q must have a sha256 digest, not a tag", ErrInvalid, img.Name)
		}
	}
	var r Release
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		raw, _ := json.Marshal(images)
		err := tx.QueryRow(ctx, `INSERT INTO releases (tenant_id, service_id, version, images, commit_sha, created_by)
			SELECT $1, id, $3, $4, $5, $6 FROM services WHERE id = $2 AND archived_at IS NULL
			RETURNING id::text, service_id::text, version, commit_sha, created_by, created_at`, tenant, service, version, raw, commit, by.UID).
			Scan(&r.ID, &r.ServiceID, &r.Version, &r.CommitSHA, &r.CreatedBy, &r.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			if strings.Contains(err.Error(), "releases_service_id_version_key") {
				return fmt.Errorf("%w: version %s already exists", ErrInvalid, version)
			}
			return err
		}
		r.Images = images
		return record(ctx, tx, tenant, "keel.release.created", "CreateRelease", "release/"+r.ID, activity.Create, activity.Success, by,
			fmt.Sprintf("%s with %d image(s) from %s", version, len(images), orNone(commit)), activity.Resource{Type: "release", UID: r.ID}, activity.Resource{Type: "service", UID: service})
	})
	return r, err
}

func orNone(s string) string {
	if s == "" {
		return "unknown commit"
	}
	return s
}

// facts is everything the policy and the PR need.
type facts struct {
	release                             Release
	serviceSlug, projectID, projectSlug string
	configRepo, envName                 string
	envOrder                            *int
	requiresApproval                    bool
	previous                            map[string]any
	hardBreach                          bool
	breachDetail                        string
	criticalOpen                        int
}

func (s *Service) facts(ctx context.Context, tx pgx.Tx, releaseID, env string) (facts, error) {
	var f facts
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT r.id::text, r.service_id::text, r.version, r.images, r.commit_sha, r.created_by, r.created_at, s.slug, p.id::text, p.slug, p.config_repo
		FROM releases r JOIN services s ON s.id = r.service_id JOIN projects p ON p.id = s.project_id WHERE r.id = $1`, releaseID).
		Scan(&f.release.ID, &f.release.ServiceID, &f.release.Version, &raw, &f.release.CommitSHA, &f.release.CreatedBy, &f.release.CreatedAt, &f.serviceSlug, &f.projectID, &f.projectSlug, &f.configRepo)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, ErrNotFound
	}
	if err != nil {
		return f, err
	}
	_ = json.Unmarshal(raw, &f.release.Images)
	err = tx.QueryRow(ctx, `SELECT name, promotion_order, requires_approval FROM environments WHERE id = $1 AND project_id = $2 AND archived_at IS NULL`, env, f.projectID).
		Scan(&f.envName, &f.envOrder, &f.requiresApproval)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, ErrNotFound
	}
	if err != nil {
		return f, err
	}
	if f.envOrder != nil {
		var prevID, prevName string
		err := tx.QueryRow(ctx, `SELECT id::text, name FROM environments WHERE project_id = $1 AND archived_at IS NULL AND promotion_order < $2 ORDER BY promotion_order DESC LIMIT 1`, f.projectID, *f.envOrder).Scan(&prevID, &prevName)
		if err == nil {
			var deployed bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM promotions WHERE release_id = $1 AND environment_id = $2 AND state = 'deployed')`, releaseID, prevID).Scan(&deployed); err != nil {
				return f, err
			}
			f.previous = map[string]any{"name": prevName, "deployed": deployed}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return f, err
		}
	}
	month := time.Date(s.Now().Year(), s.Now().Month(), 1, 0, 0, 0, 0, time.UTC)
	err = tx.QueryRow(ctx, `SELECT b.name || ' at ' || round(a.pct) || '% of ' || a.budget_amount::text FROM budget_alerts a JOIN budgets b ON b.id = a.budget_id
		WHERE b.project_id = $1 AND (b.environment_id IS NULL OR b.environment_id = $2) AND a.month = $3 AND a.basis = 'actual' AND a.pct >= $4
		ORDER BY a.pct DESC LIMIT 1`, f.projectID, env, month, HardBreachPct).Scan(&f.breachDetail)
	if err == nil {
		f.hardBreach = true
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return f, err
	}
	err = tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE project_id = $1 AND status = 'open' AND severity = 'critical'`, f.projectID).Scan(&f.criticalOpen)
	return f, err
}

func (s *Service) decide(ctx context.Context, f facts, approved bool) (Decision, error) {
	input := map[string]any{
		"release":     map[string]any{"images": f.release.Images},
		"environment": map[string]any{"name": f.envName, "requires_approval": f.requiresApproval},
		"previous":    f.previous,
		"budget":      map[string]any{"hard_breach": f.hardBreach, "detail": f.breachDetail},
		"findings":    map[string]any{"critical_open": f.criticalOpen},
		"approval":    map[string]any{"given": approved},
		"config_repo": f.configRepo,
	}
	rs, err := s.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Decision{}, fmt.Errorf("evaluate promotion policy: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return Decision{}, fmt.Errorf("promotion policy: unexpected result")
	}
	raw, _ := json.Marshal(rs[0].Expressions[0].Value)
	var d Decision
	err = json.Unmarshal(raw, &d)
	if d.Reasons == nil {
		d.Reasons = []string{}
	}
	return d, err
}

const promoCols = `id::text, release_id::text, environment_id::text, state, decision, pr_url, error, requested_by, approved_by, requested_at, merged_at, deployed_at`

func scanPromotion(r pgx.Row) (Promotion, error) {
	var p Promotion
	var raw []byte
	err := r.Scan(&p.ID, &p.ReleaseID, &p.EnvironmentID, &p.State, &raw, &p.PRURL, &p.Error, &p.RequestedBy, &p.ApprovedBy, &p.RequestedAt, &p.MergedAt, &p.DeployedAt)
	if err == nil {
		_ = json.Unmarshal(raw, &p.Decision)
	}
	return p, err
}

// Promote asks to move a Release to an Environment. A denied request is
// recorded with its reasons and opens nothing. Asking again while one is
// active returns it.
func (s *Service) Promote(ctx context.Context, tenant, releaseID, env string, by activity.Actor) (Promotion, error) {
	var p Promotion
	var f facts
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		existing, err := scanPromotion(tx.QueryRow(ctx, `SELECT `+promoCols+` FROM promotions WHERE release_id = $1 AND environment_id = $2 AND state IN ('pending_approval', 'pr_open', 'merged')`, releaseID, env))
		if err == nil {
			p = existing
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if f, err = s.facts(ctx, tx, releaseID, env); err != nil {
			return err
		}
		d, err := s.decide(ctx, f, false)
		if err != nil {
			return err
		}
		state := "pr_open"
		switch {
		case !d.Allow:
			state = "denied"
		case d.NeedsApproval:
			state = "pending_approval"
		}
		raw, _ := json.Marshal(d)
		p, err = scanPromotion(tx.QueryRow(ctx, `INSERT INTO promotions (tenant_id, release_id, environment_id, state, decision, requested_by)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+promoCols, tenant, releaseID, env, state, raw, by.UID))
		if err != nil {
			return err
		}
		outcome, detail := activity.Success, fmt.Sprintf("%s %s → %s: %s", f.serviceSlug, f.release.Version, f.envName, state)
		if !d.Allow {
			outcome, detail = activity.Failure, detail+" ("+strings.Join(d.Reasons, "; ")+")"
		}
		return record(ctx, tx, tenant, "keel.promotion.requested", "RequestPromotion", "promotion/"+p.ID, activity.Create, outcome, by, detail+" ["+d.Policy+"]",
			activity.Resource{Type: "promotion", UID: p.ID}, activity.Resource{Type: "release", UID: releaseID}, activity.Resource{Type: "environment", UID: env})
	})
	if err != nil || p.State != "pr_open" || p.PRURL != nil {
		return p, err
	}
	return s.openPR(ctx, tenant, p, f)
}

// Approve gives a Tenant Approver's (or Platform Admin's) approval and
// re-checks the policy before opening the PR.
func (s *Service) Approve(ctx context.Context, tenant, id string, by activity.Actor) (Promotion, error) {
	var p Promotion
	var f facts
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		cur, err := scanPromotion(tx.QueryRow(ctx, `SELECT `+promoCols+` FROM promotions WHERE id = $1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if cur.State != "pending_approval" {
			return ErrState
		}
		if cur.RequestedBy == by.UID {
			return fmt.Errorf("%w: the requester cannot approve their own promotion", ErrState)
		}
		if f, err = s.facts(ctx, tx, cur.ReleaseID, cur.EnvironmentID); err != nil {
			return err
		}
		d, err := s.decide(ctx, f, true)
		if err != nil {
			return err
		}
		state := "pr_open"
		if !d.Allow {
			state = "denied"
		}
		raw, _ := json.Marshal(d)
		p, err = scanPromotion(tx.QueryRow(ctx, `UPDATE promotions SET state = $2, decision = $3, approved_by = $4, approved_at = now(), updated_at = now() WHERE id = $1 RETURNING `+promoCols,
			id, state, raw, by.UID))
		if err != nil {
			return err
		}
		return record(ctx, tx, tenant, "keel.promotion.approved", "ApprovePromotion", "promotion/"+id, activity.Update, activity.Success, by,
			fmt.Sprintf("%s %s → %s approved; policy: %s", f.serviceSlug, f.release.Version, f.envName, state), activity.Resource{Type: "promotion", UID: id})
	})
	if err != nil || p.State != "pr_open" {
		return p, err
	}
	return s.openPR(ctx, tenant, p, f)
}

func (s *Service) openPR(ctx context.Context, tenant string, p Promotion, f facts) (Promotion, error) {
	url, err := s.pullRequest(ctx, p, f)
	return p, s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var e error
		if err != nil {
			p, e = scanPromotion(tx.QueryRow(ctx, `UPDATE promotions SET state = 'failed', error = $2, updated_at = now() WHERE id = $1 RETURNING `+promoCols, p.ID, err.Error()))
			if e != nil {
				return e
			}
			return record(ctx, tx, tenant, "keel.promotion.failed", "OpenPromotionPR", "promotion/"+p.ID, activity.Update, activity.Failure, keelActor, err.Error(), activity.Resource{Type: "promotion", UID: p.ID})
		}
		p, e = scanPromotion(tx.QueryRow(ctx, `UPDATE promotions SET pr_url = $2, pr_opened_at = now(), updated_at = now() WHERE id = $1 RETURNING `+promoCols, p.ID, url))
		if e != nil {
			return e
		}
		return record(ctx, tx, tenant, "keel.promotion.pr_opened", "OpenPromotionPR", "promotion/"+p.ID, activity.Update, activity.Success, keelActor, url, activity.Resource{Type: "promotion", UID: p.ID})
	})
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:promotion"}

var unsafeRef = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (s *Service) pullRequest(ctx context.Context, p Promotion, f facts) (string, error) {
	if s.Git == nil {
		return "", errors.New("promotion pull requests are not configured (KEEL_GITHUB_WRITE_TOKEN)")
	}
	repo, path := f.configRepo, render(s.PathTemplate, f.projectSlug, f.envName, f.serviceSlug)
	base, err := s.Git.DefaultBranch(ctx, repo)
	if err != nil {
		return "", err
	}
	src, sha, err := s.Git.File(ctx, repo, path, base)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	out, changed, err := PatchKustomization(src, f.release.Images)
	if err != nil {
		return "", err
	}
	if !changed {
		return "", fmt.Errorf("%s already pins these digests", path)
	}
	branch := unsafeRef.ReplaceAllString(fmt.Sprintf("keel/promote-%s-%s-%s-%s", f.serviceSlug, f.release.Version, f.envName, p.ID[len(p.ID)-8:]), "-")
	if err := s.Git.Branch(ctx, repo, base, branch); err != nil {
		return "", err
	}
	msg := fmt.Sprintf("Promote %s %s to %s", f.serviceSlug, f.release.Version, f.envName)
	if err := s.Git.Commit(ctx, repo, branch, path, sha, msg, out); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Keel promotion `%s` of release `%s`.\n\n| Image | Digest |\n|---|---|\n", p.ID, f.release.Version)
	for _, img := range f.release.Images {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", img.Name, img.Digest)
	}
	fmt.Fprintf(&b, "\nPolicy `%s`: allowed.\n", p.Decision.Policy)
	if p.Decision.NeedsApproval || p.ApprovedBy != nil {
		fmt.Fprintf(&b, "Approved by `%s`.\n", deref(p.ApprovedBy))
	}
	pr, err := s.Git.OpenPR(ctx, repo, branch, base, msg, b.String())
	return pr.HTMLURL, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// List returns promotions, newest first, optionally for one release.
func (s *Service) List(ctx context.Context, tenant, release string) ([]Promotion, error) {
	var out []Promotion
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+promoCols+` FROM promotions WHERE ($1 = '' OR release_id::text = $1) ORDER BY requested_at DESC LIMIT 200`, release)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Promotion, error) { return scanPromotion(r) })
		return err
	})
	return out, err
}

// Releases lists a Service's releases (or all), newest first.
func (s *Service) Releases(ctx context.Context, tenant, service string) ([]Release, error) {
	var out []Release
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, service_id::text, version, images, commit_sha, created_by, created_at FROM releases
			WHERE ($1 = '' OR service_id::text = $1) ORDER BY created_at DESC LIMIT 200`, service)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Release, error) {
			var x Release
			var raw []byte
			err := r.Scan(&x.ID, &x.ServiceID, &x.Version, &raw, &x.CommitSHA, &x.CreatedBy, &x.CreatedAt)
			_ = json.Unmarshal(raw, &x.Images)
			return x, err
		})
		return err
	})
	return out, err
}
