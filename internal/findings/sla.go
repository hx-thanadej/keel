// Package findings holds cross-cutting rules for the Findings inbox (#107):
// every Finding has an owner, a severity and a due date from the Tenant's
// SLA; overdue and unowned Findings are made visible.
package findings

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:findings"}

// SLA runs the daily due-date checks.
type SLA struct {
	Store *store.Store
	Now   func() time.Time // defaults to time.Now
}

func (s SLA) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Result counts what a run found.
type Result struct {
	Dated   int `json:"dated"`
	Overdue int `json:"overdue"`
	Unowned int `json:"unowned"`
}

// Run checks every Tenant.
func (s SLA) Run(ctx context.Context) (Result, error) {
	var res Result
	now := s.now()
	var home *string
	if err := s.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil {
		return res, err
	}
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	type count struct {
		slug string
		n    int
	}
	unowned := map[string]count{}
	for _, tenant := range tenants {
		err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			// Findings from before SLAs existed: touching severity fires the trigger that dates them.
			tag, err := tx.Exec(ctx, `UPDATE findings SET severity = severity WHERE status = 'open' AND due_at IS NULL`)
			if err != nil {
				return err
			}
			res.Dated += int(tag.RowsAffected())
			rows, err := tx.Query(ctx, `UPDATE findings SET overdue_at = $1 WHERE status = 'open' AND due_at < $1 AND overdue_at IS NULL
				RETURNING id::text, severity, title, coalesce(owner_team_id::text, ''), due_at::date::text`, now)
			if err != nil {
				return err
			}
			type over struct{ id, severity, title, team, due string }
			late, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (over, error) {
				var o over
				err := r.Scan(&o.id, &o.severity, &o.title, &o.team, &o.due)
				return o, err
			})
			if err != nil {
				return err
			}
			for _, o := range late {
				res.Overdue++
				if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/findings", Type: "keel.finding.overdue", Subject: "finding/" + o.id,
					Operation: "FlagOverdue", Kind: activity.Update, Actor: keelActor, Outcome: activity.Failure,
					Resources:    []activity.Resource{{Type: "finding", UID: o.id, OwnerTeam: o.team}},
					StatusDetail: fmt.Sprintf("%s Finding past its due date %s: %s", o.severity, o.due, o.title)}); err != nil {
					return err
				}
			}
			var c count
			if err := tx.QueryRow(ctx, `SELECT (SELECT slug FROM tenants WHERE id = $1), count(*) FROM findings
				WHERE status = 'open' AND owner_team_id IS NULL AND kind <> 'unowned_findings'`, tenant).Scan(&c.slug, &c.n); err != nil {
				return err
			}
			unowned[tenant] = c
			res.Unowned += c.n
			return nil
		})
		if err != nil {
			return res, fmt.Errorf("tenant %s: %w", tenant, err)
		}
	}
	if home == nil {
		return res, nil
	}
	// Unowned Findings are the platform team's to route.
	return res, s.Store.InTenant(ctx, *home, func(tx pgx.Tx) error {
		for tenant, c := range unowned {
			fp := "unowned_findings:" + tenant
			if c.n == 0 {
				if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = 'every Finding has an owner'
					WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, fp, now); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at)
				VALUES ($1, 'unowned_findings', $2, 'medium', $3, jsonb_build_object('tenant', $4::text, 'count', $5::int), $6)
				ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now(), detail = excluded.detail`,
				*home, fp, fmt.Sprintf("%d Findings in Tenant %s have no owning Team", c.n, c.slug), c.slug, c.n, now); err != nil {
				return err
			}
		}
		return nil
	})
}
