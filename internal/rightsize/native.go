package rightsize

import (
	"context"
	"errors"
	"maps"
	"math/big"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
)

// ImportResult counts an import.
type ImportResult struct {
	Raised, Kept, Unowned int
	// Dropped counts a client payer's recommendations for accounts that are
	// not its Tenant's client-owned accounts (ImportForClient).
	Dropped int
	// Withdrawn counts open advice a complete listing no longer holds.
	Withdrawn int
}

// keelOrigin marks advice from Keel's own provider listing; a client
// payer's advice is marked with clientOrigin(payer). One listing withdraws
// only advice of its own origin, so one payer's listing never withdraws
// another's, or Keel's.
const keelOrigin = "keel"

func clientOrigin(payer string) string { return "client:" + payer }

// withOrigin returns r with its Evidence marked as coming from origin.
func withOrigin(r Recommendation, origin string) Recommendation {
	r.Evidence = maps.Clone(r.Evidence)
	if r.Evidence == nil {
		r.Evidence = map[string]any{}
	}
	r.Evidence["origin"] = origin
	return r
}

// ImportListing reads Keel's own listing of source and imports it. A
// listing that fails, even after some pages, imports and withdraws
// nothing. A complete one also withdraws, in every Tenant, the open advice
// of source it no longer holds.
func (s Service) ImportListing(ctx context.Context, source string, list func(context.Context) ([]Recommendation, error)) (ImportResult, error) {
	recs, err := list(ctx)
	if err != nil {
		return ImportResult{}, err
	}
	res, err := s.Import(ctx, recs)
	if err != nil {
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
	for _, t := range tenants {
		n, err := s.withdraw(ctx, t, source, keelOrigin, recs)
		res.Withdrawn += n
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// WithdrawForClient withdraws, in tenant, the open advice of source read
// through payer that listed, a complete listing of source through payer
// (every page, no error), no longer holds.
func (s Service) WithdrawForClient(ctx context.Context, tenant, payer, source string, listed []Recommendation) (int, error) {
	return s.withdraw(ctx, tenant, source, clientOrigin(payer), listed)
}

// withdraw supersedes tenant's open advice of source and origin whose
// fingerprint listed does not hold, and resolves its Finding. Accepted
// advice is left to its pull request.
func (s Service) withdraw(ctx context.Context, tenant, source, origin string, listed []Recommendation) (int, error) {
	seen := make([]string, 0, len(listed))
	for _, r := range listed {
		seen = append(seen, Fingerprint(r.Provider, r.ResourceID, r.Action))
	}
	why := "no longer reported by " + source
	now := s.now()
	n := 0
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE recommendations SET state = 'superseded', decision_reason = $4, updated_at = now()
			WHERE state = 'open' AND source = $1 AND evidence->>'origin' = $2 AND NOT (fingerprint = ANY ($3))
			RETURNING id::text, coalesce(finding_id::text, '')`, source, origin, seen, why)
		if err != nil {
			return err
		}
		type gone struct{ id, finding string }
		withdrawn, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (gone, error) {
			var g gone
			return g, r.Scan(&g.id, &g.finding)
		})
		if err != nil {
			return err
		}
		for _, g := range withdrawn {
			if err := resolveFinding(ctx, tx, g.finding, why, now); err != nil {
				return err
			}
			if err := record(ctx, tx, tenant, g.id, "keel.recommendation.withdrawn", "WithdrawRecommendation", activity.Update, keelActor, why); err != nil {
				return err
			}
		}
		n = len(withdrawn)
		return nil
	})
	return n, err
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
		if err := s.importOne(ctx, tenant, withOrigin(r, keelOrigin), &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// ImportForClient stores recommendations read through a client payer's
// read-only role (ADR-0018) in that payer's Tenant only. A recommendation
// is kept only when its account is one of tenant's client-owned accounts;
// any other, including an unregistered account or another Tenant's, is
// dropped and counted, never sent to the home Tenant. Each is marked as
// read through payer, for WithdrawForClient.
func (s Service) ImportForClient(ctx context.Context, tenant, payer string, recs []Recommendation) (ImportResult, error) {
	var res ImportResult
	pool := s.Store.AppPool()
	for _, r := range recs {
		if r.MonthlySavings == "" {
			continue
		}
		var t, project, env *string
		var client bool
		err := pool.QueryRow(ctx, `SELECT tenant_id::text, project_id::text, environment_id::text, ownership = 'client' FROM account_owners($1, ARRAY[$2])`,
			r.Provider, r.AccountID).Scan(&t, &project, &env, &client)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (!client || t == nil || *t != tenant)) {
			res.Dropped++
			continue
		}
		if err != nil {
			return res, err
		}
		r.ProjectID, r.EnvironmentID = project, env
		if err := s.importOne(ctx, tenant, withOrigin(r, clientOrigin(payer)), &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// importOne converts r's savings into tenant's currency at today's rate and
// stores it in tenant.
func (s Service) importOne(ctx context.Context, tenant string, r Recommendation, res *ImportResult) error {
	var currency string
	var converted *string
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT currency, round(fx_convert($1::numeric, $2, currency, current_date), 2)::text FROM tenants WHERE id = $3`,
			r.MonthlySavings, r.Currency, tenant).Scan(&currency, &converted)
	})
	if err != nil {
		return err
	}
	if converted != nil {
		if v, ok := new(big.Rat).SetString(*converted); ok {
			r.MonthlySavings, r.Currency = v.FloatString(2), currency
		}
	}
	_, changed, err := s.Upsert(ctx, tenant, r)
	if err != nil {
		return err
	}
	if changed {
		res.Raised++
	} else {
		res.Kept++
	}
	return nil
}
