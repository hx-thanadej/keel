package ciidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/store"
)

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:ci-identity"}

// Manager creates and keeps CI identities in step with GitHub and the Catalog.
type Manager struct {
	Store    *store.Store
	Provider string // "tencent"
	Config   Config
	IAM      func(account string) (IAM, error)
	JWKS     func(context.Context) (string, error)
	Now      func() time.Time // defaults to time.Now
}

func (m Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// bindings lists the repositories of the Environment's Project.
func bindings(ctx context.Context, tx pgx.Tx, env string) ([]Binding, error) {
	rows, err := tx.Query(ctx, `SELECT s.repository_owner_id, s.repository_id, e.name FROM services s
		JOIN environments e ON e.project_id = s.project_id
		WHERE e.id = $1 AND s.archived_at IS NULL AND s.repository_id IS NOT NULL AND s.repository_owner_id IS NOT NULL
		ORDER BY s.repository_id`, env)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Binding, error) {
		var b Binding
		err := r.Scan(&b.OwnerID, &b.RepoID, &b.Environment)
		return b, err
	})
}

// Step is the vending step that creates the account's CI identity.
func (m Manager) Step() flow.Step {
	return flow.Step{Name: "ci_identity", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
		account := r.Out("account", "account_id")
		ch, subjects, err := m.ensure(ctx, r.Tenant, r.Out("register", "cloud_account_id"), r.Str("environment_id"), account)
		if err != nil && !errors.Is(err, ErrTooManyRepos) {
			return nil, err
		}
		c := m.Config.withDefaults()
		return map[string]any{"role": c.RoleName, "provider": c.ProviderName, "subjects": len(subjects), "provider_created": ch.ProviderCreated, "role_created": ch.RoleCreated}, nil
	}}
}

func (m Manager) ensure(ctx context.Context, tenant, cloudAccount, env, account string) (Change, []string, error) {
	var bs []Binding
	if err := m.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		bs, err = bindings(ctx, tx, env)
		return err
	}); err != nil {
		return Change{}, nil, err
	}
	subjects, tooMany := Subjects(bs)
	jwks, err := m.JWKS(ctx)
	if err != nil {
		return Change{}, nil, fmt.Errorf("github jwks: %w", err)
	}
	iam, err := m.IAM(account)
	if err != nil {
		return Change{}, nil, err
	}
	ch, err := Ensure(ctx, iam, account, m.Config, jwks, subjects)
	if err != nil {
		return ch, subjects, err
	}
	err = m.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE cloud_accounts SET ci_identity_at = coalesce(ci_identity_at, now()) WHERE id = $1`, cloudAccount); err != nil {
			return err
		}
		var what []string
		if ch.ProviderCreated {
			what = append(what, "identity provider created")
		}
		if ch.KeysUpdated {
			what = append(what, "signing keys updated")
		}
		if ch.RoleCreated {
			what = append(what, "deploy role created")
		}
		if ch.TrustUpdated {
			what = append(what, "role trust updated")
		}
		if len(what) == 0 {
			return nil
		}
		_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/ci-identity", Type: "keel.ci_identity.changed", Subject: "cloud_account/" + cloudAccount,
			Operation: "EnsureCIIdentity", Kind: activity.Update, Actor: keelActor, Outcome: activity.Success,
			Resources:    []activity.Resource{{Type: "cloud_account", UID: cloudAccount}},
			StatusDetail: fmt.Sprintf("%s on %s; trusts %d subject(s)", strings.Join(what, ", "), account, len(subjects)),
			Why:          activity.Why{Reason: "keyless CI (ADR-0007)"}})
		return err
	})
	if err != nil {
		return ch, subjects, err
	}
	return ch, subjects, tooMany
}

// SyncResult counts what a run did.
type SyncResult struct {
	Accounts int `json:"accounts"`
	Changed  int `json:"changed"`
	Failed   int `json:"failed"`
}

type identified struct{ id, external, env string }

// Sync re-checks every account with a CI identity: keys against GitHub's
// JWKS, trust against the Catalog's repositories. Failures become Findings.
func (m Manager) Sync(ctx context.Context) (SyncResult, error) {
	var res SyncResult
	rows, err := m.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, tenant := range tenants {
		var accounts []identified
		if err := m.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT id::text, external_id, environment_id::text FROM cloud_accounts
				WHERE provider = $1 AND archived_at IS NULL AND ci_identity_at IS NOT NULL AND environment_id IS NOT NULL`, m.Provider)
			if err != nil {
				return err
			}
			accounts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (identified, error) {
				var a identified
				err := r.Scan(&a.id, &a.external, &a.env)
				return a, err
			})
			return err
		}); err != nil {
			return res, err
		}
		for _, a := range accounts {
			res.Accounts++
			ch, _, err := m.ensure(ctx, tenant, a.id, a.env, a.external)
			if ch != (Change{}) {
				res.Changed++
			}
			if err != nil {
				res.Failed++
			}
			if ferr := m.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error { return finding(ctx, tx, tenant, a, err, m.now()) }); ferr != nil {
				return res, ferr
			}
		}
	}
	return res, nil
}

// finding raises (or resolves) the account's CI identity Finding at the given time.
func finding(ctx context.Context, tx pgx.Tx, tenant string, a identified, err error, at time.Time) error {
	fp := "ci_identity:" + a.external
	if err == nil {
		_, e := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = 'CI identity in sync'
			WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, fp, at)
		return e
	}
	severity, title := "high", fmt.Sprintf("CI identity on %s could not be kept in sync: deployments may fail", a.external)
	if errors.Is(err, ErrTooManyRepos) {
		severity, title = "medium", fmt.Sprintf("More than %d repositories deploy to %s; only the first %d can assume the deploy role", MaxSubjects, a.external, MaxSubjects)
	}
	detail, _ := json.Marshal(map[string]any{"account": a.external, "error": err.Error()})
	_, e := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, environment_id, owner_team_id, first_seen_at)
		SELECT $1, 'ci_identity', $2, $3, $4, $5, e.project_id, e.id, p.team_id, $7 FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.id = $6
		ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now(), detail = excluded.detail, severity = excluded.severity`,
		tenant, fp, severity, title, detail, a.env, at)
	return e
}
