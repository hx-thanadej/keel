package cost

import (
	"context"
	"encoding/json"
	"maps"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ScopeTag is the one cost-allocation tag Keel reads: "<tenant>/<project>/<env>"
// (env optional). One key, because Tencent allows only 15 allocation tag keys.
const ScopeTag = "keel-scope"

type fact struct {
	line   Line
	tenant string
	owner  owner // account, environment, project as stored
	method string
}

type nsScope struct {
	tenant, project string
	env             *string
}

type allocator struct {
	home     string
	rules    map[string]Rule // provider|sub|service ("" = any service)
	scopes   map[string]*nsScope
	nsScopes map[string]map[string]nsScope               // cluster → namespace → scope
	nsCosts  map[string]map[time.Time]map[string]float64 // cluster → day → namespace → cost
	lookup   func(path string) *nsScope
}

func (in *Ingester) allocator(ctx context.Context, provider, home string) (*allocator, error) {
	a := &allocator{home: home, rules: map[string]Rule{}, scopes: map[string]*nsScope{},
		nsScopes: map[string]map[string]nsScope{}, nsCosts: map[string]map[time.Time]map[string]float64{}}
	err := in.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, provider, sub_account_id, coalesce(service_name, ''), kind, shares, coalesce(cluster, '')
			FROM allocation_rules WHERE archived_at IS NULL AND provider = $1`, provider)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r Rule
			var shares []byte
			if err := rows.Scan(&r.ID, &r.Provider, &r.SubAccountID, &r.ServiceName, &r.Kind, &shares, &r.Cluster); err != nil {
				rows.Close()
				return err
			}
			_ = json.Unmarshal(shares, &r.Shares)
			a.rules[r.SubAccountID+"|"+r.ServiceName] = r
		}
		rows.Close()
		rows, err = tx.Query(ctx, `SELECT cluster, namespace, target_tenant_id::text, project_id::text, environment_id::text FROM k8s_namespace_scopes`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var cluster, ns string
			var sc nsScope
			if err := rows.Scan(&cluster, &ns, &sc.tenant, &sc.project, &sc.env); err != nil {
				rows.Close()
				return err
			}
			if a.nsScopes[cluster] == nil {
				a.nsScopes[cluster] = map[string]nsScope{}
			}
			a.nsScopes[cluster][ns] = sc
		}
		rows.Close()
		rows, err = tx.Query(ctx, `SELECT cluster, day, namespace, cost FROM k8s_namespace_costs WHERE day >= now() - interval '400 days'`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var cluster, ns string
			var day time.Time
			var c float64
			if err := rows.Scan(&cluster, &day, &ns, &c); err != nil {
				rows.Close()
				return err
			}
			day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
			if a.nsCosts[cluster] == nil {
				a.nsCosts[cluster] = map[time.Time]map[string]float64{}
			}
			if a.nsCosts[cluster][day] == nil {
				a.nsCosts[cluster][day] = map[string]float64{}
			}
			a.nsCosts[cluster][day][ns] = c
		}
		rows.Close()
		return nil
	})
	a.lookup = func(path string) *nsScope {
		if sc, ok := a.scopes[path]; ok {
			return sc
		}
		parts := strings.SplitN(path, "/", 3)
		var sc *nsScope
		if len(parts) >= 2 {
			env := ""
			if len(parts) == 3 {
				env = parts[2]
			}
			var s nsScope
			if err := in.Store.AppPool().QueryRow(ctx, `SELECT tenant_id::text, project_id::text, environment_id::text FROM scope_by_path($1, $2, $3)`,
				parts[0], parts[1], env).Scan(&s.tenant, &s.project, &s.env); err == nil {
				sc = &s
			}
		}
		a.scopes[path] = sc
		return sc
	}
	return a, err
}

func (a *allocator) allocate(ln Line, owners map[string]owner) []fact {
	o, known := owners[ln.SubAccountID]
	// 1. A client account attributes everything in it.
	if known && o.env != nil {
		return []fact{{line: ln, tenant: *o.tenant, owner: o, method: "account"}}
	}
	// 2. keel-scope tag.
	if path := ln.Tags[ScopeTag]; path != "" {
		if sc := a.lookup(path); sc != nil {
			return []fact{{line: ln, tenant: sc.tenant, owner: owner{account: o.account, project: &sc.project, env: sc.env}, method: "tag"}}
		}
	}
	base := fact{line: ln, tenant: a.home, method: "unallocated"}
	if known {
		base = fact{line: ln, tenant: *o.tenant, owner: o, method: "account"} // platform-owned account
	}
	// 3. A rule for this account (and service).
	r, ok := a.rules[ln.SubAccountID+"|"+ln.ServiceName]
	if !ok {
		r, ok = a.rules[ln.SubAccountID+"|"]
	}
	if !ok {
		return []fact{base}
	}
	type target struct {
		weight *big.Rat
		sc     *nsScope // nil = stays with base (unmapped namespaces)
	}
	var targets []target
	method := "rule"
	switch r.Kind {
	case "weights":
		for _, s := range r.Shares {
			w, _ := new(big.Rat).SetString(s.Weight)
			targets = append(targets, target{weight: w, sc: &nsScope{tenant: s.TenantID, project: s.ProjectID, env: s.EnvironmentID}})
		}
	case "k8s":
		method = "k8s"
		day := time.Date(ln.ChargePeriodStart.Year(), ln.ChargePeriodStart.Month(), ln.ChargePeriodStart.Day(), 0, 0, 0, 0, time.UTC)
		costs := a.nsCosts[r.Cluster][day]
		if len(costs) == 0 {
			return []fact{base} // no share data yet; a later reload will split it
		}
		for _, ns := range sortedKeys(costs) {
			if costs[ns] <= 0 {
				continue
			}
			t := target{weight: new(big.Rat).SetFloat64(costs[ns])}
			if sc, ok := a.nsScopes[r.Cluster][ns]; ok {
				t.sc = &sc
			}
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return []fact{base}
	}
	sumW := new(big.Rat)
	for _, t := range targets {
		sumW.Add(sumW, t.weight)
	}
	fracs := make([]*big.Rat, len(targets))
	for i, t := range targets {
		fracs[i] = new(big.Rat).Quo(t.weight, sumW)
	}
	parts := splitLine(ln, fracs)
	out := make([]fact, len(targets))
	for i, t := range targets {
		parts[i].Vendor = maps.Clone(ln.Vendor)
		parts[i].Vendor["x_AllocationRule"] = r.ID
		parts[i].Vendor["x_AllocationShare"] = fracs[i].FloatString(6)
		if t.sc == nil {
			f := base
			f.line, f.method = parts[i], method
			if !known {
				f.method = "unallocated"
			}
			out[i] = f
			continue
		}
		out[i] = fact{line: parts[i], tenant: t.sc.tenant, owner: owner{account: o.account, project: &t.sc.project, env: t.sc.env}, method: method}
	}
	return out
}

// splitLine divides a line's money by fractions (summing to 1), rounding to
// 6 decimals with the remainder on the last part so totals stay exact.
func splitLine(ln Line, fracs []*big.Rat) []Line {
	out := make([]Line, len(fracs))
	for i := range out {
		out[i] = ln
	}
	for _, field := range []func(*Line) *string{
		func(l *Line) *string { return &l.BilledCost },
		func(l *Line) *string { return &l.EffectiveCost },
		func(l *Line) *string { return &l.ListCost },
		func(l *Line) *string { return &l.ContractedCost },
		func(l *Line) *string { return &l.PricingQuantity },
		func(l *Line) *string { return &l.ConsumedQuantity },
	} {
		v := *field(&ln)
		total, ok := new(big.Rat).SetString(v)
		if v == "" || !ok {
			continue
		}
		rest := new(big.Rat).Set(total)
		for i, f := range fracs {
			part := new(big.Rat).Mul(total, f)
			s := part.FloatString(6)
			if i == len(fracs)-1 {
				s = rest.FloatString(6)
			} else {
				r, _ := new(big.Rat).SetString(s)
				rest.Sub(rest, r)
			}
			*field(&out[i]) = s
		}
	}
	return out
}

func sortedKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
