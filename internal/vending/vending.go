// Package vending creates an Environment's Cloud Account end to end (#88,
// ADR-0002): a member account in the Tenant's organisation unit, registered in
// the Catalog, then whatever baseline steps later milestones add (Landing
// Zone, CI identity, registry). It runs as a durable flow, so every step is
// idempotent and recorded.
package vending

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/store"
)

// Kind is the flow kind for vending one Environment with a provider.
func Kind(provider string) string { return "vend_environment_" + provider }

var (
	ErrAlreadyVended = errors.New("environment already has a cloud account for this provider")
	ErrNotFound      = errors.New("environment not found")
)

// Org is the provider's organisation API (account factory).
type Org interface {
	Provider() string
	// EnsureUnit returns the id of the unit named name under the root,
	// creating it if missing.
	EnsureUnit(ctx context.Context, name string) (string, error)
	// FindAccount looks a member account up by its exact name.
	FindAccount(ctx context.Context, name string) (id string, found bool, err error)
	CreateAccount(ctx context.Context, name, unit string, tags map[string]string) (string, error)
	// AccountReady reports whether a new account can be configured yet.
	AccountReady(ctx context.Context, id string) (bool, error)
}

// ErrNotReady makes the "ready" step retry with backoff.
var ErrNotReady = errors.New("account not ready yet")

// Vendor builds the vending flow.
type Vendor struct {
	Store *store.Store
	Org   Org
	// Baseline steps run after the account is registered; each sees outputs
	// "account" → {"account_id"} and "unit" → {"unit_id"}.
	Baseline []flow.Step
}

// MaxNameLen is Tencent's member-name limit (25 characters).
const MaxNameLen = 25

// AccountName is "<tenant>-<project>-<env>", shortened with a stable hash
// suffix when it would exceed max characters.
func AccountName(tenant, project, env string, max int) string {
	n := tenant + "-" + project + "-" + env
	if len(n) <= max {
		return n
	}
	sum := sha256.Sum256([]byte(n))
	h := hex.EncodeToString(sum[:])[:6]
	return strings.TrimRight(n[:max-7], "-") + "-" + h
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:vending"}

// Def returns the flow definition.
func (v Vendor) Def() flow.Def {
	steps := []flow.Step{
		{Name: "unit", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			id, err := v.Org.EnsureUnit(ctx, r.Str("tenant_slug"))
			if err != nil {
				return nil, err
			}
			return map[string]any{"unit_id": id}, nil
		}},
		{Name: "account", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			name := r.Str("account_name")
			if id, found, err := v.Org.FindAccount(ctx, name); err != nil {
				return nil, err
			} else if found {
				return map[string]any{"account_id": id, "created": false}, nil
			}
			id, err := v.Org.CreateAccount(ctx, name, r.Out("unit", "unit_id"), map[string]string{
				"keel-tenant": r.Str("tenant_slug"), "keel-project": r.Str("project_slug"), "keel-env": r.Str("environment_name")})
			if err != nil {
				return nil, err
			}
			return map[string]any{"account_id": id, "created": true}, nil
		}},
		{Name: "ready", MaxAttempts: 20, Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			ok, err := v.Org.AccountReady(ctx, r.Out("account", "account_id"))
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, ErrNotReady
			}
			return nil, nil
		}},
		{Name: "register", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
			id, err := v.register(ctx, r)
			if err != nil {
				return nil, err
			}
			return map[string]any{"cloud_account_id": id}, nil
		}, Undo: func(ctx context.Context, r *flow.Run) error {
			// The provider account itself is never closed automatically:
			// closing is irreversible and has a waiting period. Archive the
			// Catalog entry so the Environment can be vended again.
			return v.Store.InTenant(ctx, r.Tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE cloud_accounts SET archived_at = now() WHERE id = $1 AND archived_at IS NULL`, r.Out("register", "cloud_account_id"))
				return err
			})
		}},
	}
	return flow.Def{Kind: Kind(v.Org.Provider()), Steps: append(steps, v.Baseline...)}
}

func (v Vendor) register(ctx context.Context, r *flow.Run) (string, error) {
	var id string
	err := v.Store.InTenant(ctx, r.Tenant, func(tx pgx.Tx) error {
		external := r.Out("account", "account_id")
		err := tx.QueryRow(ctx, `SELECT id::text FROM cloud_accounts WHERE provider = $1 AND external_id = $2`, v.Org.Provider(), external).Scan(&id)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, $3, $4, $5) RETURNING id::text`,
			r.Tenant, r.Str("environment_id"), v.Org.Provider(), external, r.Str("account_name")).Scan(&id); err != nil {
			return err
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: r.Tenant, Source: "keel/vending", Type: "keel.cloud_account.created", Subject: "cloud_account/" + id,
			Operation: "VendCloudAccount", Kind: activity.Create, Actor: keelActor, Outcome: activity.Success,
			Resources:    []activity.Resource{{Type: "cloud_account", UID: id}, {Type: "environment", UID: r.Str("environment_id")}},
			StatusDetail: fmt.Sprintf("%s account %s (%s)", v.Org.Provider(), external, r.Str("account_name")), Why: activity.Why{Reason: "vending flow " + r.ID}})
		return err
	})
	return id, err
}

// Request starts vending one Environment. It refuses if the Environment
// already has an account with this provider; asking while a run is in
// progress returns that run.
func (v Vendor) Request(ctx context.Context, e *flow.Engine, tenant, project, env string, by activity.Actor) (flow.Flow, bool, error) {
	subject := "environment/" + env + "/" + v.Org.Provider()
	if active, err := e.List(ctx, tenant, Kind(v.Org.Provider()), subject); err != nil {
		return flow.Flow{}, false, err
	} else {
		for _, f := range active {
			if f.State == "running" || f.State == "failed" || f.State == "cancelling" {
				f, err := e.Get(ctx, tenant, f.ID)
				return f, false, err
			}
		}
	}
	input := map[string]any{"environment_id": env, "project_id": project, "provider": v.Org.Provider()}
	err := v.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var tslug, pslug, ename string
		var has bool
		err := tx.QueryRow(ctx, `SELECT t.slug, p.slug, e.name,
				EXISTS (SELECT 1 FROM cloud_accounts a WHERE a.environment_id = e.id AND a.provider = $3 AND a.archived_at IS NULL)
			FROM environments e JOIN projects p ON p.id = e.project_id JOIN tenants t ON t.id = e.tenant_id
			WHERE e.id = $1 AND p.id = $2 AND e.archived_at IS NULL`, env, project, v.Org.Provider()).Scan(&tslug, &pslug, &ename, &has)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if has {
			return ErrAlreadyVended
		}
		input["tenant_slug"], input["project_slug"], input["environment_name"] = tslug, pslug, ename
		input["account_name"] = AccountName(tslug, pslug, ename, MaxNameLen)
		return nil
	})
	if err != nil {
		return flow.Flow{}, false, err
	}
	return e.Start(ctx, tenant, Kind(v.Org.Provider()), subject, input, by)
}
