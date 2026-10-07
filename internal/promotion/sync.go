package promotion

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
)

// SyncResult counts what a run moved.
type SyncResult struct {
	Merged   int `json:"merged"`
	Closed   int `json:"closed"`
	Deployed int `json:"deployed"`
}

type active struct {
	id, state, prURL, release, env, envName, service, serviceID, project string
	requestedAt                                                          time.Time
	mergedAt                                                             *time.Time
	releasedAt                                                           time.Time
	images                                                               []Image
}

// Sync follows open promotion PRs and, once merged, the Argo CD application
// until it runs the release's digests.
func (s *Service) Sync(ctx context.Context) (SyncResult, error) {
	var res SyncResult
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, tenant := range tenants {
		var list []active
		if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT pr.id::text, pr.state, coalesce(pr.pr_url, ''), r.id::text, e.id::text, e.name, s.slug, s.id::text, p.slug, pr.requested_at, pr.merged_at, r.created_at, r.images
				FROM promotions pr JOIN releases r ON r.id = pr.release_id JOIN environments e ON e.id = pr.environment_id
				JOIN services s ON s.id = r.service_id JOIN projects p ON p.id = s.project_id
				WHERE pr.state IN ('pr_open', 'merged')`)
			if err != nil {
				return err
			}
			list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (active, error) {
				var a active
				var raw []byte
				err := r.Scan(&a.id, &a.state, &a.prURL, &a.release, &a.env, &a.envName, &a.service, &a.serviceID, &a.project, &a.requestedAt, &a.mergedAt, &a.releasedAt, &raw)
				_ = json.Unmarshal(raw, &a.images)
				return a, err
			})
			return err
		}); err != nil {
			return res, err
		}
		for _, a := range list {
			if err := s.advance(ctx, tenant, a, &res); err != nil {
				return res, fmt.Errorf("promotion %s: %w", a.id, err)
			}
		}
	}
	return res, nil
}

func (s *Service) advance(ctx context.Context, tenant string, a active, res *SyncResult) error {
	if a.state == "pr_open" {
		if s.Git == nil || a.prURL == "" {
			return nil
		}
		pr, err := s.Git.PR(ctx, a.prURL)
		if err != nil {
			return err
		}
		switch {
		case pr.Merged:
			at := s.Now()
			if pr.MergedAt != nil {
				at = *pr.MergedAt
			}
			a.mergedAt, a.state = &at, "merged"
			res.Merged++
			if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `UPDATE promotions SET state = 'merged', merged_at = $2, updated_at = now() WHERE id = $1`, a.id, at); err != nil {
					return err
				}
				return record(ctx, tx, tenant, "keel.promotion.merged", "MergePromotionPR", "promotion/"+a.id, activity.Update, activity.Success, keelActor, a.prURL, activity.Resource{Type: "promotion", UID: a.id})
			}); err != nil {
				return err
			}
		case pr.State == "closed":
			res.Closed++
			return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `UPDATE promotions SET state = 'closed', updated_at = now() WHERE id = $1`, a.id); err != nil {
					return err
				}
				return record(ctx, tx, tenant, "keel.promotion.closed", "ClosePromotionPR", "promotion/"+a.id, activity.Update, activity.Failure, keelActor, "pull request closed without merging", activity.Resource{Type: "promotion", UID: a.id})
			})
		default:
			return nil
		}
	}
	if a.state != "merged" || s.Argo == nil {
		return nil
	}
	app := render(s.AppTemplate, a.project, a.envName, a.service)
	st, err := s.Argo.App(ctx, app)
	if err != nil {
		return err
	}
	if st.Sync != "Synced" || st.Health != "Healthy" || !runs(st.Images, a.images) {
		return nil
	}
	now := s.Now()
	res.Deployed++
	return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE promotions SET state = 'deployed', deployed_at = $2, updated_at = now() WHERE id = $1`, a.id, now); err != nil {
			return err
		}
		// Lead time is measured from the Release (built commit) to running in the Environment (DORA, M6).
		detail := fmt.Sprintf("%s %s running in %s (Argo CD %s Synced/Healthy); lead time %s, merge→running %s",
			a.service, a.release, a.envName, app, now.Sub(a.releasedAt).Round(time.Second), now.Sub(*a.mergedAt).Round(time.Second))
		_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/promotion", Type: "keel.deployment.succeeded", Subject: "promotion/" + a.id,
			Operation: "Deploy", Kind: activity.Update, Actor: keelActor, Outcome: activity.Success, StatusDetail: detail,
			Resources: []activity.Resource{{Type: "promotion", UID: a.id}, {Type: "release", UID: a.release}, {Type: "service", UID: a.serviceID}, {Type: "environment", UID: a.env}},
			Why:       activity.Why{PR: a.prURL, Reason: "promotion " + a.id}})
		return err
	})
}

// runs reports whether every release digest appears in the app's images.
func runs(appImages []string, images []Image) bool {
	for _, img := range images {
		found := false
		for _, a := range appImages {
			if strings.HasSuffix(a, "@"+img.Digest) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return len(images) > 0
}
