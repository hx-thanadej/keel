// Package registry gives every Project a namespace in the regional container
// registry (#94, ADR-0008): images are pulled inside the region instead of
// across it from ghcr.io, tags are immutable and old images expire. It also
// reports the Project's network egress before and after the switch.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/store"
)

// Registry is the provider's container registry.
type Registry interface {
	// EnsureNamespace creates a private namespace with scan-on-push.
	EnsureNamespace(ctx context.Context, name string) (id int64, created bool, err error)
	// EnsureImmutableTags makes every tag in the namespace immutable.
	EnsureImmutableTags(ctx context.Context, name string) (bool, error)
	// EnsureRetention keeps the newest keep images per repository.
	EnsureRetention(ctx context.Context, name string, id int64, keep int) (bool, error)
}

// MaxNameLen is TCR's namespace name limit.
const MaxNameLen = 30

// NamespaceName is "<tenant>-<project>", lowercase, shortened with a stable
// hash when longer than TCR allows.
func NamespaceName(tenant, project string) string {
	n := strings.ToLower(tenant + "-" + project)
	if len(n) <= MaxNameLen {
		return n
	}
	sum := sha256.Sum256([]byte(n))
	return strings.TrimRight(n[:MaxNameLen-7], "-_") + "-" + hex.EncodeToString(sum[:])[:6]
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:registry"}

// Step is the vending step: the Project's namespace (shared by its
// Environments, so later Environments find it already there).
func Step(st *store.Store, reg Registry, keep int) flow.Step {
	return flow.Step{Name: "registry", Do: func(ctx context.Context, r *flow.Run) (map[string]any, error) {
		name := NamespaceName(r.Str("tenant_slug"), r.Str("project_slug"))
		id, created, err := reg.EnsureNamespace(ctx, name)
		if err != nil {
			return nil, err
		}
		if _, err := reg.EnsureImmutableTags(ctx, name); err != nil {
			return nil, err
		}
		if _, err := reg.EnsureRetention(ctx, name, id, keep); err != nil {
			return nil, err
		}
		err = st.InTenant(ctx, r.Tenant, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE projects SET registry_namespace = $2, registry_created_at = now() WHERE id = $1 AND registry_namespace = ''`, r.Str("project_id"), name)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			_, err = activity.Record(ctx, tx, activity.Activity{TenantID: r.Tenant, Source: "keel/registry", Type: "keel.registry.namespace_created", Subject: "project/" + r.Str("project_id"),
				Operation: "EnsureRegistryNamespace", Kind: activity.Create, Actor: keelActor, Outcome: activity.Success,
				Resources:    []activity.Resource{{Type: "project", UID: r.Str("project_id")}},
				StatusDetail: fmt.Sprintf("namespace %s (immutable tags, keep %d per repository, scan on push)", name, keep)})
			return err
		})
		return map[string]any{"namespace": name, "created": created}, err
	}}
}

// Egress compares a Project's daily network spend before and after its
// namespace was created.
type Egress struct {
	Namespace string     `json:"namespace"`
	Since     *time.Time `json:"since"`
	Days      int        `json:"days"`
	Currency  string     `json:"currency"`
	Before    string     `json:"before_daily"`
	After     string     `json:"after_daily"`
	AfterDays int        `json:"after_days"`
}

// ErrNotFound means the Project does not exist.
var ErrNotFound = errors.New("project not found")

// Report returns the egress comparison over `days` either side.
func Report(ctx context.Context, st *store.Store, tenant, project string, days int, now time.Time) (Egress, error) {
	out := Egress{Days: days}
	err := st.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT p.registry_namespace, p.registry_created_at, t.currency FROM projects p JOIN tenants t ON t.id = p.tenant_id WHERE p.id = $1`, project).
			Scan(&out.Namespace, &out.Since, &out.Currency)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil || out.Since == nil {
			return err
		}
		day := out.Since.UTC().Truncate(24 * time.Hour)
		end := day.AddDate(0, 0, days)
		if today := now.UTC().Truncate(24 * time.Hour); today.Before(end) {
			end = today
		}
		out.AfterDays = int(end.Sub(day).Hours() / 24)
		return tx.QueryRow(ctx, `
			WITH d AS (
				SELECT sum(fx_convert(coalesce(effective_cost, billed_cost), billing_currency, $5, (charge_period_start AT TIME ZONE 'UTC')::date)) AS amt,
				       charge_period_start >= $3 AS after
				FROM cost_facts WHERE current AND project_id = $1 AND service_category = 'Networking'
				  AND charge_period_start >= $2 AND charge_period_start < $4
				GROUP BY 2)
			SELECT (coalesce((SELECT amt FROM d WHERE NOT after), 0) / $6)::numeric(18,2)::text,
			       (coalesce((SELECT amt FROM d WHERE after), 0) / greatest($7, 1))::numeric(18,2)::text`,
			project, day.AddDate(0, 0, -days), day, end, out.Currency, days, out.AfterDays).Scan(&out.Before, &out.After)
	})
	return out, err
}
