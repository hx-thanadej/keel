package clientreads

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/utilisation"
)

// CVMRightsizing recommends sizes for a client payer's own CVM instances,
// for providers without a native size recommender (Tencent, ADR-0013). It
// reads Cloud Monitor and the instances' types through the payer's
// read-only role, stores the utilisation in the payer's Tenant and runs
// Keel's VM engine there. Member accounts are not read: Keel holds no
// session in them.
type CVMRightsizing struct {
	Store     *store.Store
	Tenant    string
	Payer     string // the payer account; only its instances are read
	Region    string
	Monitor   utilisation.MonitorAPI
	Inventory rightsize.Inventory
	Catalog   rightsize.Catalog
	Now       func() time.Time
}

// backfill is how many past days are collected when missing; the last
// settle days are collected on every run, as late samples arrive.
const backfill, settle = 14, 2

// Recommendations collects the payer's CVM utilisation for every missing
// day of the last two weeks, then evaluates the Tenant.
func (c CVMRightsizing) Recommendations(ctx context.Context) ([]rightsize.Recommendation, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	n := now().UTC()
	today := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
	type inst struct{ project, env *string }
	insts := map[string]inst{}
	have := map[time.Time]bool{}
	err := c.Store.InTenant(ctx, c.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (resource_id) resource_id, project_id::text, environment_id::text FROM cost_facts
			WHERE current AND provider = 'tencent' AND service_name = 'Cloud Virtual Machine' AND resource_id LIKE 'ins-%'
			  AND sub_account_id = $1 AND charge_period_start >= $2
			ORDER BY resource_id, charge_period_start DESC`, c.Payer, today.AddDate(0, 0, -7))
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			var x inst
			if err := rows.Scan(&id, &x.project, &x.env); err != nil {
				rows.Close()
				return err
			}
			insts[id] = x
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		ids := make([]string, 0, len(insts))
		for id := range insts {
			ids = append(ids, id)
		}
		rows, err = tx.Query(ctx, `SELECT day FROM utilisation_daily WHERE provider = 'tencent' AND resource_type = 'vm' AND metric = 'cpu_pct'
			AND resource_id = ANY ($1) AND day >= $2 GROUP BY day HAVING count(*) = cardinality($1::text[])`, ids, today.AddDate(0, 0, -backfill))
		if err != nil {
			return err
		}
		days, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
		for _, d := range days {
			have[d.UTC()] = true
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(insts) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(insts))
	for id := range insts {
		ids = append(ids, id)
	}
	cvm := utilisation.TencentCVM{API: c.Monitor}
	var failed []error
	for i := backfill; i >= 1; i-- {
		day := today.AddDate(0, 0, -i)
		if have[day] && i > settle {
			continue
		}
		sums, err := cvm.Day(ctx, ids, day)
		if err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", day.Format(time.DateOnly), err))
			continue
		}
		byScope := map[inst][]utilisation.Summary{}
		for _, s := range sums {
			x := insts[s.ResourceID]
			byScope[x] = append(byScope[x], s)
		}
		for x, ss := range byScope {
			if err := (utilisation.Store{Store: c.Store}).Save(ctx, c.Tenant, x.project, x.env, ss); err != nil {
				return nil, err
			}
		}
	}
	if err := errors.Join(failed...); err != nil {
		return nil, fmt.Errorf("GetMonitorData: %w", err)
	}
	payerOnly := func(account string) rightsize.Inventory {
		if account == c.Payer {
			return c.Inventory
		}
		return noInventory{}
	}
	return rightsize.VMEngine{Service: rightsize.Service{Store: c.Store}, Catalog: c.Catalog, Inventory: payerOnly, Region: c.Region, Now: c.Now, Client: true}.Recommend(ctx, c.Tenant)
}

// noInventory knows no instance type, so the engine skips instances in
// accounts Keel cannot read.
type noInventory struct{}

func (noInventory) InstanceTypes(context.Context, string, []string) (map[string]string, error) {
	return nil, nil
}
