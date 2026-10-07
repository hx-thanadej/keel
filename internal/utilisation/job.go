package utilisation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Cluster is a Kubernetes cluster to collect from. DefaultScope
// ("<tenant>/<project>/<env>") attributes namespaces that have no explicit
// mapping (a dedicated cluster); shared clusters rely on namespace mappings.
type Cluster struct {
	Prometheus   Prometheus
	DefaultScope string
}

// Job collects yesterday's utilisation everywhere, daily.
type Job struct {
	Store    Store
	Clusters []Cluster
	// CVM returns a collector for a member account (nil = skip CVM).
	CVM func(account string) (*TencentCVM, error)
}

type scope struct {
	tenant       string
	project, env *string
}

// Run collects the given UTC day.
func (j Job) Run(ctx context.Context, day time.Time) error {
	day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
	var errs []error
	for _, c := range j.Clusters {
		if err := j.cluster(ctx, c, day); err != nil {
			errs = append(errs, fmt.Errorf("cluster %s: %w", c.Prometheus.Cluster, err))
		}
	}
	if j.CVM != nil {
		if err := j.cvm(ctx, day); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (j Job) home(ctx context.Context) (string, error) {
	var home *string
	if err := j.Store.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil || home == nil {
		return "", errors.New("utilisation: no home tenant")
	}
	return *home, nil
}

func (j Job) cluster(ctx context.Context, c Cluster, day time.Time) error {
	sums, err := c.Prometheus.Day(ctx, day)
	if err != nil {
		return err
	}
	home, err := j.home(ctx)
	if err != nil {
		return err
	}
	// Namespace → scope from the shared-cost mappings (#35).
	mapped := map[string]scope{}
	err = j.Store.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT namespace, target_tenant_id::text, project_id::text, environment_id::text FROM k8s_namespace_scopes WHERE cluster = $1`, c.Prometheus.Cluster)
		if err != nil {
			return err
		}
		for rows.Next() {
			var ns string
			var s scope
			if err := rows.Scan(&ns, &s.tenant, &s.project, &s.env); err != nil {
				rows.Close()
				return err
			}
			mapped[ns] = s
		}
		rows.Close()
		return nil
	})
	if err != nil {
		return err
	}
	var def *scope
	if c.DefaultScope != "" {
		parts := strings.SplitN(c.DefaultScope, "/", 3)
		if len(parts) == 3 {
			var s scope
			if err := j.Store.Store.AppPool().QueryRow(ctx, `SELECT tenant_id::text, project_id::text, environment_id::text FROM scope_by_path($1, $2, $3)`,
				parts[0], parts[1], parts[2]).Scan(&s.tenant, &s.project, &s.env); err == nil {
				def = &s
			}
		}
	}
	type group struct {
		s    scope
		sums []Summary
	}
	groups := map[string]*group{}
	for _, x := range sums {
		s, ok := mapped[x.Namespace]
		if !ok && def != nil {
			s, ok = *def, true
		}
		if !ok {
			s = scope{tenant: home} // unattributed: kept in the home Tenant
		}
		k := s.tenant + "|" + deref(s.project) + "|" + deref(s.env)
		if groups[k] == nil {
			groups[k] = &group{s: s}
		}
		groups[k].sums = append(groups[k].sums, x)
	}
	for _, g := range groups {
		if err := j.Store.Save(ctx, g.s.tenant, g.s.project, g.s.env, g.sums); err != nil {
			return err
		}
	}
	return nil
}

// cvm collects every CVM instance that appeared in a Tenant's cost facts in
// the last 7 days, per member account.
func (j Job) cvm(ctx context.Context, day time.Time) error {
	rows, err := j.Store.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		type inst struct {
			id, account  string
			project, env *string
		}
		var insts []inst
		err := j.Store.Store.InTenant(ctx, t, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT DISTINCT resource_id, sub_account_id, project_id::text, environment_id::text FROM cost_facts
				WHERE current AND provider = 'tencent' AND service_name = 'Cloud Virtual Machine' AND resource_id LIKE 'ins-%'
				  AND charge_period_start >= $1::date - 7 AND charge_period_start < $1::date + 1`, day)
			if err != nil {
				return err
			}
			for rows.Next() {
				var x inst
				if err := rows.Scan(&x.id, &x.account, &x.project, &x.env); err != nil {
					rows.Close()
					return err
				}
				insts = append(insts, x)
			}
			rows.Close()
			return nil
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		byAcct := map[string][]inst{}
		for _, x := range insts {
			byAcct[x.account] = append(byAcct[x.account], x)
		}
		for acct, xs := range byAcct {
			col, err := j.CVM(acct)
			if err != nil {
				errs = append(errs, fmt.Errorf("account %s: %w", acct, err))
				continue
			}
			ids := make([]string, len(xs))
			scopeOf := map[string]inst{}
			for i, x := range xs {
				ids[i] = x.id
				scopeOf[x.id] = x
			}
			sums, err := col.Day(ctx, ids, day)
			if err != nil {
				errs = append(errs, fmt.Errorf("account %s: %w", acct, err))
				continue
			}
			byScope := map[string][]Summary{}
			for _, s := range sums {
				x := scopeOf[s.ResourceID]
				k := deref(x.project) + "|" + deref(x.env)
				byScope[k] = append(byScope[k], s)
			}
			for _, ss := range byScope {
				x := scopeOf[ss[0].ResourceID]
				if err := j.Store.Save(ctx, t, x.project, x.env, ss); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
