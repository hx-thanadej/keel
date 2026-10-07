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
	Failed   int `json:"failed"`
}

// FailureWatch: a deployment Argo CD reports Degraded within this time is
// marked failed (DORA change fail rate, #148).
const FailureWatch = 24 * time.Hour

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
		if err := s.watchFailures(ctx, tenant, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// watchFailures marks recent deployments failed when Argo CD reports their
// application Degraded.
func (s *Service) watchFailures(ctx context.Context, tenant string, res *SyncResult) error {
	if s.Argo == nil {
		return nil
	}
	type recent struct{ id, app string }
	var list []recent
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT p.id::text, pr.slug, e.name, sv.slug FROM promotions p JOIN environments e ON e.id = p.environment_id
			JOIN releases r ON r.id = p.release_id JOIN services sv ON sv.id = r.service_id JOIN projects pr ON pr.id = sv.project_id
			WHERE p.state = 'deployed' AND p.failed_at IS NULL AND p.deployed_at > $1`, s.Now().Add(-FailureWatch))
		if err != nil {
			return err
		}
		list, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (recent, error) {
			var x recent
			var project, env, svc string
			err := r.Scan(&x.id, &project, &env, &svc)
			x.app = render(s.AppTemplate, project, env, svc)
			return x, err
		})
		return err
	}); err != nil {
		return err
	}
	for _, d := range list {
		st, err := s.Argo.App(ctx, d.app)
		if err != nil {
			return err
		}
		if st.Health != "Degraded" {
			continue
		}
		res.Failed++
		if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE promotions SET failed_at = $2, failure_reason = $3 WHERE id = $1 AND failed_at IS NULL`, d.id, s.Now(), "Argo CD reports "+d.app+" Degraded")
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			return record(ctx, tx, tenant, "keel.deployment.failed", "MarkDeploymentFailed", "promotion/"+d.id, activity.Update, activity.Failure, keelActor,
				"Argo CD reports "+d.app+" Degraded", activity.Resource{Type: "promotion", UID: d.id})
		}); err != nil {
			return err
		}
	}
	return nil
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
