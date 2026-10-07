package cost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// ErrPeriodFinal means the billing period already has a final load.
var ErrPeriodFinal = errors.New("billing period is final; no further loads accepted")

// Load is one ingest of a provider billing account's period.
type Load struct {
	Provider         string
	BillingAccountID string
	BillingPeriod    time.Time // first day of the month, UTC
	Source           string
	Final            bool
	Lines            []Line
}

// LoadResult summarises a load.
type LoadResult struct {
	LoadID      string
	Lines       int
	Allocated   int
	Unallocated int
}

// Ingester writes loads. It runs as Keel itself, not as a user.
type Ingester struct {
	Store *store.Store
}

type owner struct {
	tenant, account, env, project *string
}

var actor = activity.Actor{Type: activity.ActorKeel, UID: "keel:cost-ingest"}

// Load attributes lines to Tenants by Cloud Account and makes them current,
// superseding earlier loads of the same period.
func (in *Ingester) Load(ctx context.Context, l Load) (LoadResult, error) {
	period := time.Date(l.BillingPeriod.Year(), l.BillingPeriod.Month(), 1, 0, 0, 0, 0, time.UTC)
	pool := in.Store.AppPool()
	var home *string
	if err := pool.QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil || home == nil {
		return LoadResult{}, errors.New("cost ingest needs a home tenant")
	}

	// Who owns each sub account?
	subs := map[string]bool{}
	for _, ln := range l.Lines {
		subs[ln.SubAccountID] = true
	}
	ids := make([]string, 0, len(subs))
	for s := range subs {
		ids = append(ids, s)
	}
	owners := map[string]owner{}
	rows, err := pool.Query(ctx, `SELECT external_id, tenant_id::text, cloud_account_id::text, environment_id::text, project_id::text FROM account_owners($1, $2)`, l.Provider, ids)
	if err != nil {
		return LoadResult{}, err
	}
	for rows.Next() {
		var ext string
		var o owner
		if err := rows.Scan(&ext, &o.tenant, &o.account, &o.env, &o.project); err != nil {
			rows.Close()
			return LoadResult{}, err
		}
		owners[ext] = o
	}
	rows.Close()

	// Group lines by Tenant and total them.
	byTenant := map[string][]int{}
	total, unalloc := new(big.Rat), new(big.Rat)
	res := LoadResult{Lines: len(l.Lines)}
	currency := ""
	for i, ln := range l.Lines {
		amt, _ := new(big.Rat).SetString(ln.BilledCost)
		total.Add(total, amt)
		currency = ln.BillingCurrency
		if o, ok := owners[ln.SubAccountID]; ok {
			byTenant[*o.tenant] = append(byTenant[*o.tenant], i)
			res.Allocated++
		} else {
			byTenant[*home] = append(byTenant[*home], i)
			unalloc.Add(unalloc, amt)
			res.Unallocated++
		}
	}
	touched := make([]string, 0, len(byTenant))
	for t := range byTenant {
		touched = append(touched, t)
	}
	slices.Sort(touched)

	// 1. Register the load (home Tenant), refusing if the period is final.
	var previous []string
	err = in.Store.InTenant(ctx, *home, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('keel.cost.' || $1 || '.' || $2 || '.' || $3))`, l.Provider, l.BillingAccountID, period.Format("2006-01")); err != nil {
			return err
		}
		var final bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cost_loads WHERE provider = $1 AND billing_account_id = $2 AND billing_period = $3 AND is_final)`,
			l.Provider, l.BillingAccountID, period).Scan(&final); err != nil {
			return err
		}
		if final {
			return ErrPeriodFinal
		}
		prevRows, err := tx.Query(ctx, `SELECT DISTINCT unnest(touched_tenants)::text FROM cost_loads WHERE provider = $1 AND billing_account_id = $2 AND billing_period = $3 AND superseded_at IS NULL`,
			l.Provider, l.BillingAccountID, period)
		if err != nil {
			return err
		}
		previous, err = pgx.CollectRows(prevRows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO cost_loads (tenant_id, provider, billing_account_id, billing_period, source, is_final, line_count, total_billed, unallocated_billed, currency, touched_tenants)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8::numeric, $9::numeric, $10, $11::uuid[]) RETURNING id::text`,
			*home, l.Provider, l.BillingAccountID, period, l.Source, l.Final, len(l.Lines), total.FloatString(6), unalloc.FloatString(6), currency, touched).Scan(&res.LoadID)
	})
	if err != nil {
		return LoadResult{}, err
	}

	// 2. Write facts per Tenant, not yet current.
	for tenant, idx := range byTenant {
		err := in.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			b := &pgx.Batch{}
			for _, i := range idx {
				ln := l.Lines[i]
				method := "unallocated"
				var o owner
				if ow, ok := owners[ln.SubAccountID]; ok {
					o, method = ow, "account"
				}
				tags, _ := json.Marshal(ln.Tags)
				vendor, _ := json.Marshal(ln.Vendor)
				b.Queue(`INSERT INTO cost_facts (load_id, tenant_id, provider, billing_account_id, sub_account_id, cloud_account_id, project_id, environment_id,
					allocation_method, billing_period, charge_period_start, charge_period_end, charge_category, charge_class, charge_frequency,
					service_category, service_name, service_subcategory, sku_id, region_id, availability_zone, resource_id, resource_name, resource_type,
					pricing_quantity, pricing_unit, consumed_quantity, consumed_unit, list_cost, billed_cost, effective_cost, contracted_cost, billing_currency,
					commitment_discount_id, commitment_discount_type, commitment_discount_status, tags, vendor)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,
					        nullif($25,'')::numeric,$26,nullif($27,'')::numeric,$28,nullif($29,'')::numeric,$30::numeric,nullif($31,'')::numeric,nullif($32,'')::numeric,$33,
					        $34,$35,$36,$37,$38)`,
					res.LoadID, tenant, l.Provider, l.BillingAccountID, ln.SubAccountID, o.account, o.project, o.env,
					method, period, ln.ChargePeriodStart, ln.ChargePeriodEnd, ln.ChargeCategory, ln.ChargeClass, ln.ChargeFrequency,
					ln.ServiceCategory, ln.ServiceName, ln.ServiceSubcat, ln.SkuID, ln.RegionID, ln.AvailabilityZone, ln.ResourceID, ln.ResourceName, ln.ResourceType,
					ln.PricingQuantity, ln.PricingUnit, ln.ConsumedQuantity, ln.ConsumedUnit, ln.ListCost, ln.BilledCost, ln.EffectiveCost, ln.ContractedCost, ln.BillingCurrency,
					ln.CommitmentDiscountID, ln.CommitmentDiscountType, ln.CommitmentDiscountStatus, tags, vendor)
			}
			return tx.SendBatch(ctx, b).Close()
		})
		if err != nil {
			return LoadResult{}, fmt.Errorf("write facts for tenant %s: %w", tenant, err)
		}
	}

	// 3. Flip: this load current, earlier ones not, Tenant by Tenant.
	for _, tenant := range union(previous, touched) {
		err := in.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE cost_facts SET current = (load_id = $4)
				WHERE provider = $1 AND billing_account_id = $2 AND billing_period = $3 AND (current OR load_id = $4)`,
				l.Provider, l.BillingAccountID, period, res.LoadID)
			if err != nil {
				return err
			}
			_, err = activity.Record(ctx, tx, activity.Activity{
				TenantID: tenant, Source: "keel/cost", Type: "keel.cost.loaded", Subject: "cost_load/" + res.LoadID,
				Operation: "LoadCosts", Kind: activity.Create, Actor: actor, Outcome: activity.Success,
				StatusDetail: fmt.Sprintf("%s %s %s final=%v", l.Provider, l.BillingAccountID, period.Format("2006-01"), l.Final),
			})
			return err
		})
		if err != nil {
			return LoadResult{}, fmt.Errorf("activate load for tenant %s: %w", tenant, err)
		}
	}
	err = in.Store.InTenant(ctx, *home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE cost_loads SET superseded_at = now()
			WHERE provider = $1 AND billing_account_id = $2 AND billing_period = $3 AND superseded_at IS NULL AND id <> $4`,
			l.Provider, l.BillingAccountID, period, res.LoadID)
		return err
	})
	return res, err
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
