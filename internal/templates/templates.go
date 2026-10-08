// Package templates creates governed Services from versioned templates (#92):
// a repository generated from a template repository pinned by commit, Keel's
// governed files (catalog-info.yaml, CODEOWNERS, pinned reusable workflow,
// Renovate with a minimum release age, MADR decisions folder), custom
// properties and secret scanning, then the Service in the Catalog. It runs as
// a durable flow; every step is idempotent.
package templates

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/store"
)

// Kind is the flow kind.
const Kind = "create_service"

var (
	ErrUnknownTemplate = errors.New("unknown template")
	ErrInvalid         = errors.New("invalid")
	ErrNotFound        = errors.New("not found")
	errNotReady        = errors.New("repository not ready yet")
)

// Template is a template repository pinned to a commit.
type Template struct {
	Name        string `json:"name"`
	Repo        string `json:"repo"` // owner/name
	Ref         string `json:"ref"`  // commit sha the template must be at
	Description string `json:"description"`
}

// RepoInfo is a repository's identity.
type RepoInfo struct {
	ID, OwnerID   int64
	DefaultBranch string
	Empty         bool
}

// Git is what creating a repository needs from GitHub.
type Git interface {
	Repo(ctx context.Context, full string) (RepoInfo, bool, error)
	Head(ctx context.Context, full, branch string) (string, error)
	Generate(ctx context.Context, template, owner, name, description string) error
	PutFile(ctx context.Context, full, branch, path, message string, content []byte) (bool, error)
	SetProperties(ctx context.Context, org, repo string, props map[string]string) error
	EnableSecretScanning(ctx context.Context, full string) error
	GrantTeam(ctx context.Context, org, team, full, permission string) error
}

// Creator builds the flow.
type Creator struct {
	Store            *store.Store
	Git              Git
	Org              string // GitHub organisation that owns new repositories
	Templates        map[string]Template
	ReusableWorkflow string
	KeelURL          string
	AgeProd          string
	AgeNonProd       string
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:templates"}

// Def returns the flow definition.
func (c Creator) Def() flow.Def {
	return flow.Def{Kind: Kind, Steps: []flow.Step{
		{Name: "template", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			t, ok := c.Templates[r.Str("template")]
			if !ok {
				return nil, flow.Permanent(fmt.Errorf("%w: %s", ErrUnknownTemplate, r.Str("template")))
			}
			info, found, err := c.Git.Repo(ctx, t.Repo)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, flow.Permanent(fmt.Errorf("template repository %s not found", t.Repo))
			}
			head, err := c.Git.Head(ctx, t.Repo, info.DefaultBranch)
			if err != nil {
				return nil, err
			}
			if t.Ref != "" && head != t.Ref {
				return nil, flow.Permanent(fmt.Errorf("template %s moved to %.12s but is pinned at %.12s; review and update the pin", t.Name, head, t.Ref))
			}
			return map[string]any{"repo": t.Repo, "version": head}, nil
		}},
		{Name: "repo", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			full := c.Org + "/" + r.Str("service_slug")
			_, found, err := c.Git.Repo(ctx, full)
			if err != nil {
				return nil, err
			}
			created := false
			if !found {
				if err := c.Git.Generate(ctx, r.Out("template", "repo"), c.Org, r.Str("service_slug"), r.Str("title")); err != nil {
					return nil, err
				}
				created = true
			}
			return map[string]any{"full_name": full, "created": created}, nil
		}},
		{Name: "ready", MaxAttempts: 20, Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			info, found, err := c.Git.Repo(ctx, r.Out("repo", "full_name"))
			if err != nil {
				return nil, err
			}
			if !found || info.Empty || info.DefaultBranch == "" {
				return nil, errNotReady // generation is asynchronous
			}
			return map[string]any{"repository_id": fmt.Sprint(info.ID), "owner_id": fmt.Sprint(info.OwnerID), "branch": info.DefaultBranch}, nil
		}},
		{Name: "register", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			id, err := c.register(ctx, r)
			return map[string]any{"service_id": id}, err
		}},
		{Name: "files", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			files := Files(Params{Tenant: r.Str("tenant_slug"), Project: r.Str("project_slug"), Team: r.Str("team_slug"), Service: r.Str("service_slug"),
				Title: r.Str("title"), Org: c.Org, Template: r.Str("template"), TemplateVersion: r.Out("template", "version"), ReusableWorkflow: c.ReusableWorkflow,
				KeelURL: c.KeelURL, TenantID: r.Tenant, ServiceID: r.Out("register", "service_id"), AgeProd: c.AgeProd, AgeNonProd: c.AgeNonProd})
			written := 0
			for _, path := range sortedKeys(files) {
				changed, err := c.Git.PutFile(ctx, r.Out("repo", "full_name"), r.Out("ready", "branch"), path, "chore: Keel governed files ("+path+")", files[path])
				if err != nil {
					return nil, fmt.Errorf("%s: %w", path, err)
				}
				if changed {
					written++
				}
			}
			return map[string]any{"written": written}, nil
		}},
		{Name: "governance", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			full := r.Out("repo", "full_name")
			if err := c.Git.SetProperties(ctx, c.Org, r.Str("service_slug"), map[string]string{
				"keel-tenant": r.Str("tenant_slug"), "keel-project": r.Str("project_slug"), "keel-tier": r.Str("tier")}); err != nil {
				return nil, fmt.Errorf("custom properties: %w", err)
			}
			if err := c.Git.EnableSecretScanning(ctx, full); err != nil {
				return nil, fmt.Errorf("secret scanning: %w", err)
			}
			if err := c.Git.GrantTeam(ctx, c.Org, r.Str("team_slug"), full, "push"); err != nil {
				return nil, fmt.Errorf("team access: %w", err)
			}
			return nil, nil
		}},
	}}
}

func (c Creator) register(ctx context.Context, r *flow.Run) (string, error) {
	var id string
	err := c.Store.InTenant(ctx, r.Tenant, func(tx pgx.Tx) error {
		repoURL := "https://github.com/" + r.Out("repo", "full_name")
		err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository, lifecycle, type, repository_id, repository_owner_id, template, template_version)
			VALUES ($1, $2, $3, $4, $5, $6, 'experimental', 'service', $7::bigint, $8::bigint, $9, $10)
			ON CONFLICT (project_id, slug) DO UPDATE SET repository = excluded.repository, repository_id = excluded.repository_id,
			    repository_owner_id = excluded.repository_owner_id
			RETURNING id::text`, r.Tenant, r.Str("project_id"), r.Str("team_id"), r.Str("service_slug"), r.Str("title"), repoURL,
			r.Out("ready", "repository_id"), r.Out("ready", "owner_id"), r.Str("template"), r.Out("template", "version")).Scan(&id)
		if err != nil {
			return err
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: r.Tenant, Source: "keel/templates", Type: "keel.service.created", Subject: "service/" + id,
			Operation: "CreateService", Kind: activity.Create, Actor: keelActor, Outcome: activity.Success,
			Resources:    []activity.Resource{{Type: "service", UID: id, OwnerTeam: r.Str("team_id")}},
			StatusDetail: fmt.Sprintf("%s from template %s@%.12s", repoURL, r.Str("template"), r.Out("template", "version")),
			Why:          activity.Why{Reason: "flow " + r.ID}})
		return err
	})
	return id, err
}

// Request starts creating a Service in a Project, owned by the Project's Team.
func (c Creator) Request(ctx context.Context, e *flow.Engine, tenant, project, slug, title, template, tier string, by activity.Actor) (flow.Flow, bool, error) {
	if !slugRe.MatchString(slug) {
		return flow.Flow{}, false, fmt.Errorf("%w: slug must be lowercase letters, digits and dashes", ErrInvalid)
	}
	if _, ok := c.Templates[template]; !ok {
		return flow.Flow{}, false, fmt.Errorf("%w: %s", ErrUnknownTemplate, template)
	}
	if tier == "" {
		tier = "nonprod"
	}
	if tier != "prod" && tier != "nonprod" && tier != "sandbox" {
		return flow.Flow{}, false, fmt.Errorf("%w: tier must be prod, nonprod or sandbox", ErrInvalid)
	}
	if title == "" {
		title = slug
	}
	input := map[string]any{"service_slug": slug, "title": title, "template": template, "tier": tier, "project_id": project}
	err := c.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var tslug, pslug, team, teamSlug string
		var exists bool
		err := tx.QueryRow(ctx, `SELECT t.slug, p.slug, p.team_id::text, tm.slug, EXISTS (SELECT 1 FROM services s WHERE s.project_id = p.id AND s.slug = $2)
			FROM projects p JOIN tenants t ON t.id = p.tenant_id JOIN teams tm ON tm.id = p.team_id WHERE p.id = $1 AND p.archived_at IS NULL`, project, slug).
			Scan(&tslug, &pslug, &team, &teamSlug, &exists)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%w: service %s already exists in this project", ErrInvalid, slug)
		}
		input["tenant_slug"], input["project_slug"], input["team_id"], input["team_slug"] = tslug, pslug, team, teamSlug
		return nil
	})
	if err != nil {
		return flow.Flow{}, false, err
	}
	return e.Start(ctx, tenant, Kind, "service/"+c.Org+"/"+slug, input, by)
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
