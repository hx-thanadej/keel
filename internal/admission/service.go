package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/apply"
	"github.com/hx-thanadej/keel/internal/store"
)

// Git is what delivering policies needs.
type Git interface {
	DefaultBranch(ctx context.Context, repo string) (string, error)
	File(ctx context.Context, repo, path, ref string) ([]byte, string, error)
	Branch(ctx context.Context, repo, base, branch string) error
	Commit(ctx context.Context, repo, branch, path, sha, message string, content []byte) error
	OpenPR(ctx context.Context, repo, head, base, title, body string) (apply.PullRequest, error)
}

// Service renders and delivers admission policies.
type Service struct {
	Store          *store.Store
	Git            Git
	Registry       string // TCR domain
	BuilderSubject string
	RekorURL       string
	PathTemplate   string // default "envs/{env}/keel-admission.yaml"
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:admission"}

// ErrInvalid is a bad request.
var ErrInvalid = errors.New("invalid")

// SetMode switches an Environment between warn and enforce; the next
// reconcile delivers it.
func (s Service) SetMode(ctx context.Context, tenant, env, mode, why string, by activity.Actor) error {
	if mode != "warn" && mode != "enforce" {
		return fmt.Errorf("%w: mode must be warn or enforce", ErrInvalid)
	}
	return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE environments SET admission_mode = $2 WHERE id = $1 AND archived_at IS NULL`, env, mode)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/admission", Type: "keel.admission.mode_changed", Subject: "environment/" + env,
			Operation: "SetAdmissionMode", Kind: activity.Update, Actor: by, Outcome: activity.Success,
			Resources: []activity.Resource{{Type: "environment", UID: env}}, StatusDetail: "admission " + mode, Why: activity.Why{Reason: why}})
		return err
	})
}

type target struct {
	id, project, env, repo, namespace, mode, hash string
}

// ReconcileResult counts what a run did.
type ReconcileResult struct {
	Environments int `json:"environments"`
	PRs          int `json:"prs"`
	Skipped      int `json:"skipped"`
}

// Reconcile renders every Environment's policies and opens a pull request
// in the Project's config repository where they differ from what was last
// delivered.
func (s Service) Reconcile(ctx context.Context) (ReconcileResult, error) {
	var res ReconcileResult
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, tenant := range tenants {
		var ts []target
		if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT e.id::text, p.slug, e.name, p.config_repo, p.registry_namespace, e.admission_mode, e.admission_hash
				FROM environments e JOIN projects p ON p.id = e.project_id
				WHERE e.archived_at IS NULL AND p.archived_at IS NULL`)
			if err != nil {
				return err
			}
			ts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (target, error) {
				var t target
				err := r.Scan(&t.id, &t.project, &t.env, &t.repo, &t.namespace, &t.mode, &t.hash)
				return t, err
			})
			return err
		}); err != nil {
			return res, err
		}
		for _, t := range ts {
			res.Environments++
			if t.repo == "" || t.namespace == "" {
				res.Skipped++ // nothing to protect yet, or nowhere to deliver
				continue
			}
			doc, hash, err := Render(Params{Project: t.project, Environment: t.env, Registry: s.Registry, Namespace: t.namespace, BuilderSubject: s.BuilderSubject, Mode: t.mode, RekorURL: s.RekorURL})
			if err != nil {
				return res, err
			}
			if hash == t.hash {
				continue
			}
			url, err := s.deliver(ctx, t, doc, hash)
			if err != nil {
				return res, fmt.Errorf("%s/%s: %w", t.project, t.env, err)
			}
			res.PRs++
			if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `UPDATE environments SET admission_hash = $2, admission_pr_url = $3 WHERE id = $1`, t.id, hash, url); err != nil {
					return err
				}
				_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/admission", Type: "keel.admission.proposed", Subject: "environment/" + t.id,
					Operation: "ProposeAdmissionPolicies", Kind: activity.Update, Actor: keelActor, Outcome: activity.Success,
					Resources:    []activity.Resource{{Type: "environment", UID: t.id}},
					StatusDetail: fmt.Sprintf("%s (%s, %s) → %s", Version, t.mode, hash, url), Why: activity.Why{PR: url}})
				return err
			}); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

func (s Service) deliver(ctx context.Context, t target, doc []byte, hash string) (string, error) {
	if s.Git == nil {
		return "", errors.New("admission delivery needs KEEL_GITHUB_WRITE_TOKEN")
	}
	tmpl := s.PathTemplate
	if tmpl == "" {
		tmpl = "envs/{env}/keel-admission.yaml"
	}
	path := strings.NewReplacer("{project}", t.project, "{env}", t.env).Replace(tmpl)
	base, err := s.Git.DefaultBranch(ctx, t.repo)
	if err != nil {
		return "", err
	}
	_, sha, err := s.Git.File(ctx, t.repo, path, base)
	if err != nil && !strings.Contains(err.Error(), "HTTP 404") {
		return "", err
	}
	branch := "keel/admission-" + t.env + "-" + hash
	if err := s.Git.Branch(ctx, t.repo, base, branch); err != nil {
		return "", err
	}
	msg := fmt.Sprintf("Keel admission policies for %s (%s)", t.env, t.mode)
	if err := s.Git.Commit(ctx, t.repo, branch, path, sha, msg, doc); err != nil {
		return "", err
	}
	body := fmt.Sprintf("Rendered by Keel (`%s`, hash `%s`).\n\nMode **%s**: %s\n\n- Kyverno `ImageValidatingPolicy`: images from `%s/%s` must be signed by `%s` with SLSA provenance.\n- `ValidatingAdmissionPolicy`: digest references only, from that namespace.\n",
		Version, hash, t.mode, map[string]string{"warn": "violations are reported (Audit/Warn), nothing is blocked yet.", "enforce": "violations are denied."}[t.mode],
		s.Registry, t.namespace, s.BuilderSubject)
	pr, err := s.Git.OpenPR(ctx, t.repo, branch, base, msg, body)
	return pr.HTMLURL, err
}
