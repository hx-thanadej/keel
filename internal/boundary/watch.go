package boundary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/store"
)

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:boundary"}

// Manager applies boundaries in vending and checks them daily.
type Manager struct {
	Store    *store.Store
	Provider string
	IAM      func(account string) (IAM, error)
	Now      func() time.Time // defaults to time.Now
}

func (m Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func isProd(env string) bool { return env == "prod" || env == "production" || env == "prd" }

// Step is the vending step: on a new account every role is Keel's, so all
// get the boundary.
func (m Manager) Step() flow.Step {
	return flow.Step{Name: "boundary", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
		if err := catalog.RequirePlatformOwned(ctx, m.Store, r.Tenant, r.Out("register", "cloud_account_id"), "ApplyBoundary", keelActor); err != nil {
			return nil, flow.Permanent(err)
		}
		iam, err := m.IAM(r.Out("account", "account_id"))
		if err != nil {
			return nil, err
		}
		res, err := Apply(ctx, iam, isProd(r.Str("environment_name")), true)
		if err != nil {
			return nil, err
		}
		return map[string]any{"policy_id": res.PolicyID, "stamped": res.Stamped}, m.Store.InTenant(ctx, r.Tenant, func(tx pgx.Tx) error {
			return record(ctx, tx, r.Tenant, r.Out("register", "cloud_account_id"), fmt.Sprintf("%s on %s; stamped %v", Version, r.Out("account", "account_id"), res.Stamped))
		})
	}}
}

func record(ctx context.Context, tx pgx.Tx, tenant, account, detail string) error {
	if _, err := tx.Exec(ctx, `UPDATE cloud_accounts SET boundary_version = $2 WHERE id = $1`, account, Version); err != nil {
		return err
	}
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/boundary", Type: "keel.boundary.applied", Subject: "cloud_account/" + account,
		Operation: "ApplyBoundary", Kind: activity.Update, Actor: keelActor, Outcome: activity.Success,
		Resources: []activity.Resource{{Type: "cloud_account", UID: account}}, StatusDetail: detail})
	return err
}

// CheckResult counts what a run found.
type CheckResult struct {
	Accounts int `json:"accounts"`
	Missing  int `json:"missing"`
}

type account struct{ id, external, env, envID, project string }

// Check ensures the current boundary in every Keel account and reports roles
// without it as Findings (it never stamps existing roles: that could break a
// running workload; the owner fixes it or Keel's role requests replace it).
func (m Manager) Check(ctx context.Context) (CheckResult, error) {
	var res CheckResult
	rows, err := m.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, tenant := range tenants {
		var accounts []account
		if err := m.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT a.id::text, a.external_id, e.name, e.id::text, e.project_id::text FROM cloud_accounts a JOIN environments e ON e.id = a.environment_id
				WHERE a.provider = $1 AND a.archived_at IS NULL AND a.boundary_version IS NOT NULL`, m.Provider)
			if err != nil {
				return err
			}
			accounts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (account, error) {
				var a account
				err := r.Scan(&a.id, &a.external, &a.env, &a.envID, &a.project)
				return a, err
			})
			return err
		}); err != nil {
			return res, err
		}
		for _, a := range accounts {
			// Apply ensures the boundary policy even when it stamps nothing,
			// and boundaries in a client organisation stay with the client.
			err := catalog.RequirePlatformOwned(ctx, m.Store, tenant, a.id, "CheckBoundary", keelActor)
			if errors.Is(err, catalog.ErrClientOwned) {
				continue
			}
			if err != nil {
				return res, err
			}
			res.Accounts++
			iam, err := m.IAM(a.external)
			if err != nil {
				return res, err
			}
			out, err := Apply(ctx, iam, isProd(a.env), false)
			if err != nil {
				return res, fmt.Errorf("%s: %w", a.external, err)
			}
			res.Missing += len(out.Missing)
			if err := m.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error { return findings(ctx, tx, tenant, a, out.Missing, m.now()) }); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// findings raises a Finding per role missing the boundary and resolves the
// rest, at the given time.
func findings(ctx context.Context, tx pgx.Tx, tenant string, a account, missing []string, at time.Time) error {
	prefix := "boundary:" + a.external + ":"
	open := map[string]bool{}
	for _, role := range missing {
		fp := prefix + role
		open[fp] = true
		detail, _ := json.Marshal(map[string]any{"account": a.external, "role": role, "boundary": Version})
		if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, environment_id, owner_team_id, first_seen_at)
			VALUES ($1, 'permission_boundary', $2, 'high', $3, $4, $5, $6, (SELECT team_id FROM projects WHERE id = $5), $7)
			ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now()`,
			tenant, fp, fmt.Sprintf("Role %s in %s has no Permission Boundary (created outside Keel)", role, a.external), detail, a.project, a.envID, at); err != nil {
			return err
		}
	}
	rows, err := tx.Query(ctx, `SELECT fingerprint FROM findings WHERE kind = 'permission_boundary' AND status = 'open' AND fingerprint LIKE $1`, prefix+"%")
	if err != nil {
		return err
	}
	fps, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, fp := range fps {
		if !open[fp] {
			if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = 'role now within the boundary or removed'
				WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, fp, at); err != nil {
				return err
			}
		}
	}
	return nil
}
