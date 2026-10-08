package decisions

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// Dir is where Service Templates put decisions.
const Dir = "docs/decisions"

// Source reads repositories.
type Source interface {
	// List returns the markdown file paths in dir (empty if it does not exist).
	List(ctx context.Context, repo, dir string) ([]string, error)
	Read(ctx context.Context, repo, path string) ([]byte, error)
}

// Indexer refreshes the index.
type Indexer struct {
	Store  *store.Store
	Source Source
}

// Result counts what a run did.
type Result struct {
	Services int `json:"services"`
	Records  int `json:"records"`
	Changed  int `json:"changed"`
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:decisions"}

// Run indexes every Service with a GitHub repository.
func (ix Indexer) Run(ctx context.Context) (Result, error) {
	var res Result
	rows, err := ix.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, tenant := range tenants {
		type svc struct{ id, repo string }
		var list []svc
		if err := ix.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT id::text, repository FROM services WHERE archived_at IS NULL AND repository LIKE 'https://github.com/%'`)
			if err != nil {
				return err
			}
			list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (svc, error) {
				var x svc
				err := r.Scan(&x.id, &x.repo)
				x.repo = strings.TrimSuffix(strings.TrimPrefix(x.repo, "https://github.com/"), "/")
				return x, err
			})
			return err
		}); err != nil {
			return res, err
		}
		for _, sv := range list {
			res.Services++
			paths, err := ix.Source.List(ctx, sv.repo, Dir)
			if err != nil {
				return res, fmt.Errorf("%s: %w", sv.repo, err)
			}
			var recs []Record
			for _, p := range paths {
				if !strings.HasSuffix(p, ".md") || strings.HasSuffix(strings.ToLower(p), "readme.md") || strings.Contains(p, "template") {
					continue
				}
				raw, err := ix.Source.Read(ctx, sv.repo, p)
				if err != nil {
					return res, fmt.Errorf("%s/%s: %w", sv.repo, p, err)
				}
				recs = append(recs, Parse(p, raw))
			}
			res.Records += len(recs)
			if err := ix.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
				for _, r := range recs {
					url := "https://github.com/" + sv.repo + "/blob/HEAD/" + r.Path
					var prev *string
					err := tx.QueryRow(ctx, `SELECT status FROM decision_records WHERE service_id = $1 AND path = $2`, sv.id, r.Path).Scan(&prev)
					if err != nil && err != pgx.ErrNoRows {
						return err
					}
					if _, err := tx.Exec(ctx, `INSERT INTO decision_records (tenant_id, service_id, path, number, title, status, decided_on, superseded_by, url)
						VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
						ON CONFLICT (service_id, path) DO UPDATE SET number = excluded.number, title = excluded.title, status = excluded.status,
						    decided_on = excluded.decided_on, superseded_by = excluded.superseded_by, url = excluded.url, indexed_at = now()`,
						tenant, sv.id, r.Path, r.Number, r.Title, r.Status, r.Date, r.SupersededBy, url); err != nil {
						return err
					}
					typ, detail := "", ""
					switch {
					case prev == nil:
						typ, detail = "keel.decision.recorded", fmt.Sprintf("%s (%s)", r.Title, r.Status)
					case *prev != r.Status:
						typ, detail = "keel.decision.status_changed", fmt.Sprintf("%s: %s → %s", r.Title, *prev, r.Status)
					}
					if typ == "" {
						continue
					}
					res.Changed++
					if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/decisions", Type: typ, Subject: "service/" + sv.id,
						Operation: "IndexDecision", Kind: activity.Update, Actor: keelActor, Outcome: activity.Success,
						Resources: []activity.Resource{{Type: "service", UID: sv.id}}, StatusDetail: detail, Why: activity.Why{PR: url}}); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// Entry is one indexed record.
type Entry struct {
	ServiceID    string `json:"service_id"`
	Service      string `json:"service"`
	Path         string `json:"path"`
	Number       *int   `json:"number"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	Date         string `json:"date"`
	SupersededBy string `json:"superseded_by"`
	URL          string `json:"url"`
}

// Search finds records by title words, optionally for one Service.
func Search(ctx context.Context, st *store.Store, tenant, q, service string) ([]Entry, error) {
	var out []Entry
	err := st.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.service_id::text, s.slug, d.path, d.number, d.title, d.status, d.decided_on, d.superseded_by, d.url
			FROM decision_records d JOIN services s ON s.id = d.service_id
			WHERE ($1 = '' OR lower(d.title) LIKE '%' || lower($1) || '%') AND ($2 = '' OR d.service_id::text = $2)
			ORDER BY s.slug, d.number NULLS LAST, d.path LIMIT 500`, q, service)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Entry])
		return err
	})
	return out, err
}
