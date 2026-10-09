package landingzone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/store"
)

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:landing-zone"}

// Step is the vending step that applies the baseline to the new account.
func Step(st *store.Store, org Org, b Baseline) flow.Step {
	return flow.Step{Name: "landing_zone", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
		account := r.Out("account", "account_id")
		if err := catalog.RequirePlatformOwned(ctx, st, r.Tenant, r.Out("register", "cloud_account_id"), "ApplyLandingZone", keelActor); err != nil {
			return nil, flow.Permanent(err)
		}
		if err := Apply(ctx, org, b, account); err != nil {
			return nil, err
		}
		err := st.InTenant(ctx, r.Tenant, func(tx pgx.Tx) error {
			return markApplied(ctx, tx, r.Tenant, r.Out("register", "cloud_account_id"), account, b, "applied by vending flow "+r.ID)
		})
		return map[string]any{"version": b.Version, "hash": b.Hash()}, err
	}}
}

func markApplied(ctx context.Context, tx pgx.Tx, tenant, cloudAccount, external string, b Baseline, why string) error {
	if _, err := tx.Exec(ctx, `UPDATE cloud_accounts SET baseline_version = $2, baseline_applied_at = now() WHERE id = $1`, cloudAccount, b.Version); err != nil {
		return err
	}
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/landing-zone", Type: "keel.landing_zone.applied", Subject: "cloud_account/" + cloudAccount,
		Operation: "ApplyLandingZone", Kind: activity.Update, Actor: keelActor, Outcome: activity.Success,
		Resources:    []activity.Resource{{Type: "cloud_account", UID: cloudAccount}},
		StatusDetail: fmt.Sprintf("%s (%s) on %s", b.Version, b.Hash(), external), Why: activity.Why{Reason: why}})
	return err
}

// Watcher checks every baselined account daily (#89).
type Watcher struct {
	Store    *store.Store
	Provider string
	Org      Org
	Baseline Baseline
	// Remediate re-applies the baseline when it drifted or is outdated.
	Remediate bool
	Now       func() time.Time // defaults to time.Now
}

func (w Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// WatchResult counts what a run found.
type WatchResult struct {
	Accounts   int `json:"accounts"`
	Drifted    int `json:"drifted"`
	Remediated int `json:"remediated"`
}

type baselined struct {
	id, external, version string
	env, project          *string
}

// Run checks every Tenant.
func (w Watcher) Run(ctx context.Context) (WatchResult, error) {
	var res WatchResult
	rows, err := w.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, tenant := range tenants {
		var accounts []baselined
		err := w.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT a.id::text, a.external_id, a.baseline_version, a.environment_id::text, e.project_id::text
				FROM cloud_accounts a LEFT JOIN environments e ON e.id = a.environment_id
				WHERE a.provider = $1 AND a.archived_at IS NULL AND a.baseline_version IS NOT NULL`, w.Provider)
			if err != nil {
				return err
			}
			accounts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (baselined, error) {
				var b baselined
				err := r.Scan(&b.id, &b.external, &b.version, &b.env, &b.project)
				return b, err
			})
			return err
		})
		if err != nil {
			return res, err
		}
		for _, a := range accounts {
			res.Accounts++
			drift, err := Check(ctx, w.Org, w.Baseline, a.external)
			if err != nil {
				return res, fmt.Errorf("check %s: %w", a.external, err)
			}
			if a.version != w.Baseline.Version {
				drift = append(drift, Drift{Policy: "*", Problem: "outdated:" + a.version})
			}
			if len(drift) > 0 {
				res.Drifted++
			}
			remediated, err := w.remediate(ctx, tenant, a, drift)
			if err != nil {
				return res, err
			}
			if remediated {
				res.Remediated++
			}
			if err := w.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
				return w.record(ctx, tx, tenant, a, drift, remediated)
			}); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// remediate re-applies the baseline to a drifted account unless remediation
// is off or the account is client-owned, where drift is only reported.
func (w Watcher) remediate(ctx context.Context, tenant string, a baselined, drift []Drift) (bool, error) {
	if len(drift) == 0 || !w.Remediate {
		return false, nil
	}
	err := catalog.RequirePlatformOwned(ctx, w.Store, tenant, a.id, "RemediateLandingZone", keelActor)
	if errors.Is(err, catalog.ErrClientOwned) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := Apply(ctx, w.Org, w.Baseline, a.external); err != nil {
		return false, fmt.Errorf("remediate %s: %w", a.external, err)
	}
	return true, nil
}

func (w Watcher) record(ctx context.Context, tx pgx.Tx, tenant string, a baselined, drift []Drift, remediated bool) error {
	now := w.now()
	prefix := "landing_zone:" + a.external + ":"
	open := map[string]bool{}
	for _, d := range drift {
		fp := prefix + d.Policy + ":" + strings.SplitN(d.Problem, ":", 2)[0]
		open[fp] = true
		title := fmt.Sprintf("Cloud Account %s drifted from %s: %s %s", a.external, w.Baseline.Version, d.Policy, strings.ReplaceAll(d.Problem, "_", " "))
		detail, _ := json.Marshal(map[string]any{"account": a.external, "policy": d.Policy, "problem": d.Problem, "baseline": w.Baseline.Version, "remediated": remediated})
		if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, environment_id, owner_team_id, first_seen_at)
			VALUES ($1, 'landing_zone_drift', $2, 'high', $3, $4, $5, $6, (SELECT team_id FROM projects WHERE id = $5), $7)
			ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now(), detail = excluded.detail`,
			tenant, fp, title, detail, a.project, a.env, now); err != nil {
			return err
		}
	}
	// Resolve what is no longer drifting, and what Keel just restored.
	rows, err := tx.Query(ctx, `SELECT fingerprint FROM findings WHERE kind = 'landing_zone_drift' AND status = 'open' AND fingerprint LIKE $1`, prefix+"%")
	if err != nil {
		return err
	}
	fps, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, fp := range fps {
		why := ""
		switch {
		case remediated:
			why = "restored by Keel"
		case !open[fp]:
			why = "no longer drifting"
		default:
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $3, resolution = $2 WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, fp, why, now); err != nil {
			return err
		}
	}
	if remediated {
		return markApplied(ctx, tx, tenant, a.id, a.external, w.Baseline, fmt.Sprintf("remediated %d drifted settings", len(drift)))
	}
	return nil
}
