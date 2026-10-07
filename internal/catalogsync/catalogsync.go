// Package catalogsync keeps Services in step with Backstage-compatible
// catalog-info.yaml files in source repositories (#27, ADR-0004).
//
// Mapping: Component → Service; metadata.name → Service slug; spec.system →
// Project slug; spec.owner → Team slug (the Tenant's own Team first, then the
// home Tenant's, since home Teams deliver for clients); the
// keel.dev/tenant annotation names the Tenant.
package catalogsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// TenantAnnotation names the Tenant a Component belongs to.
const TenantAnnotation = "keel.dev/tenant"

// Component is the part of a Backstage Component descriptor Keel uses.
type Component struct {
	Name, Title, Tenant, Owner, System, Lifecycle, Type string
}

type entity struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string            `yaml:"name"`
		Title       string            `yaml:"title"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec struct {
		Type      string `yaml:"type"`
		Lifecycle string `yaml:"lifecycle"`
		Owner     string `yaml:"owner"`
		System    string `yaml:"system"`
	} `yaml:"spec"`
}

// Parse reads every Component from a (multi-document) descriptor file.
func Parse(b []byte) ([]Component, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out []Component
	for {
		var e entity
		err := dec.Decode(&e)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if e.Kind != "Component" {
			continue
		}
		owner := e.Spec.Owner
		if i := strings.Index(owner, ":"); i >= 0 {
			owner = owner[i+1:] // "group:crm" → "crm"; namespaces ignored
		}
		if i := strings.LastIndex(owner, "/"); i >= 0 {
			owner = owner[i+1:]
		}
		title := e.Metadata.Title
		if title == "" {
			title = e.Metadata.Name
		}
		out = append(out, Component{Name: e.Metadata.Name, Title: title, Tenant: e.Metadata.Annotations[TenantAnnotation],
			Owner: owner, System: e.Spec.System, Lifecycle: e.Spec.Lifecycle, Type: e.Spec.Type})
	}
}

// Repo is a source repository.
type Repo struct {
	FullName string `json:"full_name"`
	URL      string `json:"html_url"`
	Archived bool   `json:"archived"`
}

// Source lists repositories and reads files from them.
type Source interface {
	ListRepos(ctx context.Context) ([]Repo, error)
	// ReadFile returns found=false when the file does not exist.
	ReadFile(ctx context.Context, repo Repo, path string) (data []byte, found bool, err error)
}

// Problem is something an owner must fix.
type Problem struct {
	Repo    string `json:"repo"`
	Problem string `json:"problem"`
}

// Report summarises one sync run.
type Report struct {
	Repos     int       `json:"repos"`
	Upserted  int       `json:"upserted"`
	Unchanged int       `json:"unchanged"`
	Problems  []Problem `json:"problems"`
}

// Syncer runs the sync as Keel itself.
type Syncer struct {
	Store  *store.Store
	Source Source
}

var actor = activity.Actor{Type: activity.ActorKeel, UID: "keel:catalog-sync"}

// Run syncs every non-archived repository once.
func (s *Syncer) Run(ctx context.Context) (Report, error) {
	started := time.Now()
	rep := Report{Problems: []Problem{}}
	repos, err := s.Source.ListRepos(ctx)
	if err != nil {
		return rep, fmt.Errorf("list repos: %w", err)
	}
	for _, r := range repos {
		if r.Archived {
			continue
		}
		rep.Repos++
		data, found, err := s.Source.ReadFile(ctx, r, "catalog-info.yaml")
		switch {
		case err != nil:
			rep.problem(r, "could not read catalog-info.yaml: "+err.Error())
			continue
		case !found:
			rep.problem(r, "no catalog-info.yaml: the repository has no owner in Keel")
			continue
		}
		comps, err := Parse(data)
		if err != nil {
			rep.problem(r, "invalid catalog-info.yaml: "+err.Error())
			continue
		}
		for _, c := range comps {
			if msg := s.upsert(ctx, r, c, &rep); msg != "" {
				rep.problem(r, fmt.Sprintf("component %q: %s", c.Name, msg))
			}
		}
	}
	return rep, s.saveReport(ctx, started, rep)
}

func (r *Report) problem(repo Repo, msg string) {
	r.Problems = append(r.Problems, Problem{Repo: repo.FullName, Problem: msg})
}

func (s *Syncer) upsert(ctx context.Context, r Repo, c Component, rep *Report) string {
	switch {
	case c.Owner == "":
		return "no owner (spec.owner is required)"
	case c.Tenant == "":
		return "no " + TenantAnnotation + " annotation"
	case c.System == "":
		return "no system (spec.system names the Project)"
	}
	pool := s.Store.AppPool()
	var tenant, home *string
	if err := pool.QueryRow(ctx, `SELECT tenant_id_by_slug($1)::text, home_tenant_id()::text`, c.Tenant).Scan(&tenant, &home); err != nil {
		return "lookup failed: " + err.Error()
	}
	if tenant == nil {
		return fmt.Sprintf("unknown tenant %q", c.Tenant)
	}
	team, err := s.team(ctx, *tenant, home, c.Owner)
	if err != nil {
		return err.Error()
	}
	var msg string
	err = s.Store.InTenant(ctx, *tenant, func(tx pgx.Tx) error {
		var project string
		if err := tx.QueryRow(ctx, `SELECT id FROM projects WHERE slug = $1 AND archived_at IS NULL`, c.System).Scan(&project); err != nil {
			msg = fmt.Sprintf("unknown project %q in tenant %q", c.System, c.Tenant)
			return nil
		}
		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository, lifecycle, type)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (project_id, slug) DO UPDATE
			SET team_id = excluded.team_id, name = excluded.name, repository = excluded.repository,
			    lifecycle = excluded.lifecycle, type = excluded.type
			WHERE (services.team_id, services.name, services.repository, services.lifecycle, services.type)
			      IS DISTINCT FROM (excluded.team_id, excluded.name, excluded.repository, excluded.lifecycle, excluded.type)
			RETURNING id::text`,
			*tenant, project, team, c.Name, c.Title, r.URL, c.Lifecycle, c.Type).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			rep.Unchanged++
			return nil
		}
		if err != nil {
			return err
		}
		rep.Upserted++
		_, err = activity.Record(ctx, tx, activity.Activity{
			TenantID: *tenant, Source: "keel/catalog-sync", Type: "keel.service.synced", Subject: "service/" + id,
			Operation: "SyncService", Kind: activity.Update, Actor: actor,
			Resources: []activity.Resource{{Type: "service", UID: id, OwnerTeam: team}},
			Why:       activity.Why{Reason: "catalog-info.yaml in " + r.FullName}, Outcome: activity.Success,
		})
		return err
	})
	if err != nil {
		return "write failed: " + err.Error()
	}
	return msg
}

// team finds the owner Team in the Component's Tenant, else in the home Tenant.
func (s *Syncer) team(ctx context.Context, tenant string, home *string, slug string) (string, error) {
	for _, t := range []*string{&tenant, home} {
		if t == nil {
			continue
		}
		var id string
		err := s.Store.InTenant(ctx, *t, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT id::text FROM teams WHERE slug = $1`, slug).Scan(&id)
		})
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}
	return "", fmt.Errorf("unknown owner team %q", slug)
}

func (s *Syncer) saveReport(ctx context.Context, started time.Time, rep Report) error {
	var home *string
	if err := s.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil || home == nil {
		return errors.New("no home tenant to store the sync report in")
	}
	raw, _ := json.Marshal(rep)
	return s.Store.InTenant(ctx, *home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO catalog_sync_runs (tenant_id, started_at, finished_at, report) VALUES ($1, $2, now(), $3)`, *home, started, raw)
		return err
	})
}

// Every runs the sync on an interval until ctx ends, logging problems.
func (s *Syncer) Every(ctx context.Context, d time.Duration) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		rep, err := s.Run(ctx)
		if err != nil {
			slog.Error("catalog sync failed", "err", err)
		} else {
			slog.Info("catalog sync", "repos", rep.Repos, "upserted", rep.Upserted, "unchanged", rep.Unchanged, "problems", len(rep.Problems))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
