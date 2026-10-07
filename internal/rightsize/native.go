package rightsize

import (
	"context"
	"errors"
	"math/big"

	"github.com/jackc/pgx/v5"
)

// ImportResult counts an import.
type ImportResult struct {
	Raised, Kept, Unowned int
}

// Import stores provider recommendations (AWS Cost Optimization Hub, …):
// each is attributed to the Tenant/Project/Environment owning its account
// and its savings converted to that Tenant's currency (#71). Recommendations
// for accounts Keel doesn't know land in the home Tenant.
func (s Service) Import(ctx context.Context, recs []Recommendation) (ImportResult, error) {
	var res ImportResult
	pool := s.Store.AppPool()
	var home *string
	if err := pool.QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil || home == nil {
		return res, errors.New("import: no home tenant")
	}
	for _, r := range recs {
		if r.MonthlySavings == "" {
			continue
		}
		tenant := *home
		var t, project, env *string
		err := pool.QueryRow(ctx, `SELECT tenant_id::text, project_id::text, environment_id::text FROM account_owners($1, ARRAY[$2])`, r.Provider, r.AccountID).Scan(&t, &project, &env)
		switch {
		case err == nil && t != nil:
			tenant, r.ProjectID, r.EnvironmentID = *t, project, env
		case errors.Is(err, pgx.ErrNoRows):
			res.Unowned++
		case err != nil:
			return res, err
		}
		// Convert savings into the Tenant's currency at today's rate.
		var currency string
		var converted *string
		err = s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT currency, round(fx_convert($1::numeric, $2, currency, current_date), 2)::text FROM tenants WHERE id = $3`,
				r.MonthlySavings, r.Currency, tenant).Scan(&currency, &converted)
		})
		if err != nil {
			return res, err
		}
		if converted != nil {
			if v, ok := new(big.Rat).SetString(*converted); ok {
				r.MonthlySavings, r.Currency = v.FloatString(2), currency
			}
		}
		_, changed, err := s.Upsert(ctx, tenant, r)
		if err != nil {
			return res, err
		}
		if changed {
			res.Raised++
		} else {
			res.Kept++
		}
	}
	return res, nil
}
