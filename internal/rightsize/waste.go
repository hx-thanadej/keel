package rightsize

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// WasteItem is a resource that costs money without doing work (CONTEXT.md: Waste).
type WasteItem struct {
	ResourceID   string
	ResourceType string // disk | eip | clb | vm
	Kind         string // unattached_disk | unbound_eip | empty_clb | stopped_paying | idle_vm
	Detail       map[string]any
}

// WasteScanner finds waste in one account.
type WasteScanner interface {
	Scan(ctx context.Context) ([]WasteItem, error)
}

// Cleaner deletes waste; for disks it snapshots first and returns the snapshot id.
type Cleaner interface {
	Delete(ctx context.Context, it WasteItem) (snapshot string, err error)
}

// WasteEngine raises Waste as delete/stop recommendations priced at the
// resource's actual cost, and (only when every gate allows) cleans it up:
// global switch on, Environment opted in, not production, open for the grace
// period, never dismissed (#72).
type WasteEngine struct {
	Service        Service
	Scanner        func(account string) (WasteScanner, Cleaner, error)
	Now            func() time.Time
	GraceDays      int
	CleanupEnabled bool
}

// WasteResult counts a run.
type WasteResult struct {
	Raised, Kept, Deleted int
	Errors                []string
}

var wasteActions = map[string]string{
	"unattached_disk": "delete", "unbound_eip": "delete", "empty_clb": "delete", "stopped_paying": "delete", "idle_vm": "stop",
}

var wasteActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:waste-cleanup"}

var cleanable = map[string]bool{"unattached_disk": true, "unbound_eip": true}

const idleCPUPct = 2.0

// Run scans every Tenant's Tencent accounts.
func (e WasteEngine) Run(ctx context.Context) (WasteResult, error) {
	var res WasteResult
	rows, err := e.Service.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, t := range tenants {
		if err := e.tenant(ctx, t, &res); err != nil {
			return res, fmt.Errorf("tenant %s: %w", t, err)
		}
	}
	return res, nil
}

type acct struct {
	id, external  string
	env, project  *string
	prod, optedIn bool
}

func (e WasteEngine) tenant(ctx context.Context, tenant string, res *WasteResult) error {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	at := now().UTC()
	var currency string
	var accounts []acct
	err := e.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT currency FROM tenants WHERE id = $1`, tenant).Scan(&currency); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT a.id::text, a.external_id, a.environment_id::text, e.project_id::text, coalesce(e.name IN ('prod', 'production', 'prd'), false), coalesce(e.waste_cleanup, false)
			FROM cloud_accounts a LEFT JOIN environments e ON e.id = a.environment_id WHERE a.provider = 'tencent' AND a.archived_at IS NULL`)
		if err != nil {
			return err
		}
		accounts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (acct, error) {
			var a acct
			err := r.Scan(&a.id, &a.external, &a.env, &a.project, &a.prod, &a.optedIn)
			return a, err
		})
		return err
	})
	if err != nil {
		return err
	}

	monthly := func(resource string) (string, error) {
		var v *string
		err := e.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT round(sum(fx_convert(coalesce(effective_cost, billed_cost), billing_currency, $4, (charge_period_start AT TIME ZONE 'UTC')::date))
					/ greatest(1, count(DISTINCT (charge_period_start AT TIME ZONE 'UTC')::date)) * 30, 2)::text
				FROM cost_facts WHERE current AND resource_id = $1 AND charge_period_start >= $2 AND charge_period_start < $3`,
				resource, at.AddDate(0, 0, -30), at, currency).Scan(&v)
		})
		if v == nil {
			return "0.00", err
		}
		r, _ := new(big.Rat).SetString(*v)
		return r.FloatString(2), err
	}
	raise := func(a acct, it WasteItem) error {
		savings, err := monthly(it.ResourceID)
		if err != nil {
			return err
		}
		detail := map[string]any{"kind": it.Kind, "method": "detected by Keel; savings = the resource's last-30-day effective cost"}
		for k, v := range it.Detail {
			detail[k] = v
		}
		r := Recommendation{Source: "engine:waste", Provider: "tencent", AccountID: a.external, ResourceID: it.ResourceID, ResourceType: it.ResourceType,
			ProjectID: a.project, EnvironmentID: a.env, Action: wasteActions[it.Kind],
			Current: map[string]any{"state": it.Kind}, Recommended: map[string]any{"action": wasteActions[it.Kind]}, Evidence: detail,
			MonthlySavings: savings, Currency: currency, SavingsBasis: "effective", Confidence: 0.9,
			Risk: map[string]any{"reversible": it.ResourceType == "disk", "data_loss": it.ResourceType == "disk"}, ObservedAt: at}
		_, changed, err := e.Service.Upsert(ctx, tenant, r)
		if changed {
			res.Raised++
		} else if err == nil {
			res.Kept++
		}
		return err
	}

	cleaners := map[string]Cleaner{}
	for _, a := range accounts {
		scanner, cleaner, err := e.Scanner(a.external)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("account %s: %v", a.external, err))
			continue
		}
		cleaners[a.external] = cleaner
		items, err := scanner.Scan(ctx)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("account %s: %v", a.external, err))
			continue
		}
		for _, it := range items {
			if err := raise(a, it); err != nil {
				return err
			}
		}
	}

	// Idle VMs: p95 CPU below 2% on every one of the last 14+ days.
	var idle []struct {
		id           string
		env, project *string
	}
	err = e.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT resource_id, max(environment_id::text), max(project_id::text) FROM utilisation_daily
			WHERE provider = 'tencent' AND resource_type = 'vm' AND metric = 'cpu_pct' AND day >= $1 AND day < $2
			GROUP BY resource_id HAVING count(*) >= $3 AND max(p95) < $4`, at.AddDate(0, 0, -minHistory-7), at, minHistory, idleCPUPct)
		if err != nil {
			return err
		}
		for rows.Next() {
			var x struct {
				id           string
				env, project *string
			}
			if err := rows.Scan(&x.id, &x.env, &x.project); err != nil {
				rows.Close()
				return err
			}
			idle = append(idle, x)
		}
		rows.Close()
		return nil
	})
	if err != nil {
		return err
	}
	for _, x := range idle {
		a := acct{env: x.env, project: x.project}
		for _, ac := range accounts {
			if ac.env != nil && x.env != nil && *ac.env == *x.env {
				a.external = ac.external
			}
		}
		if err := raise(a, WasteItem{ResourceID: x.id, ResourceType: "vm", Kind: "idle_vm", Detail: map[string]any{"cpu_p95_below_pct": idleCPUPct, "days": minHistory}}); err != nil {
			return err
		}
	}

	if !e.CleanupEnabled {
		return nil
	}
	// Cleanup: every gate must hold.
	eligibleEnv := map[string]string{} // env → account
	for _, a := range accounts {
		if a.env == nil || !a.optedIn || a.prod {
			continue
		}
		err := catalog.RequirePlatformOwned(ctx, e.Service.Store, tenant, a.id, "CleanUpWaste", wasteActor)
		if errors.Is(err, catalog.ErrClientOwned) {
			continue
		}
		if err != nil {
			return err
		}
		eligibleEnv[*a.env] = a.external
	}
	open, err := e.Service.List(ctx, tenant, Filter{State: "open"})
	if err != nil {
		return err
	}
	for _, r := range open {
		kind, _ := r.Evidence["kind"].(string)
		if r.Source != "engine:waste" || !cleanable[kind] || r.EnvironmentID == nil {
			continue
		}
		account, ok := eligibleEnv[*r.EnvironmentID]
		if !ok || at.Sub(r.GeneratedAt) < time.Duration(e.GraceDays)*24*time.Hour {
			continue
		}
		cleaner := cleaners[account]
		if cleaner == nil {
			continue
		}
		snap, err := cleaner.Delete(ctx, WasteItem{ResourceID: r.ResourceID, ResourceType: r.ResourceType, Kind: kind})
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("delete %s: %v", r.ResourceID, err))
			continue
		}
		note := fmt.Sprintf("deleted by Keel after %d days", e.GraceDays)
		if snap != "" {
			note += "; snapshot " + snap
		}
		if err := e.Service.MarkApplied(ctx, tenant, r.ID, note, "", wasteActor); err != nil && !errors.Is(err, ErrState) {
			return err
		}
		res.Deleted++
	}
	return nil
}
