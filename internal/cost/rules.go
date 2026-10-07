package cost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hx-thanadej/keel/internal/store"
)

// Errors for rule management.
var (
	ErrInvalidRule = errors.New("invalid allocation rule")
	ErrRuleExists  = errors.New("an allocation rule already exists for this account and service")
)

// Share is one recipient of a weights rule.
type Share struct {
	TenantID      string  `json:"tenant_id,omitempty"` // resolved from the Project
	ProjectID     string  `json:"project_id"`
	EnvironmentID *string `json:"environment_id,omitempty"`
	Weight        string  `json:"weight"`
}

// Rule splits a shared account's cost (#35).
type Rule struct {
	ID           string  `json:"id"`
	Provider     string  `json:"provider"`
	SubAccountID string  `json:"sub_account_id"`
	ServiceName  string  `json:"service_name,omitempty"` // "" = every service
	Kind         string  `json:"kind"`                   // weights | k8s
	Shares       []Share `json:"shares,omitempty"`
	Cluster      string  `json:"cluster,omitempty"`
}

// Rules manages allocation rules and Kubernetes namespace data in the home Tenant.
type Rules struct {
	Store *store.Store
}

// Create validates and stores a rule, resolving each share's Tenant.
func (r Rules) Create(ctx context.Context, home string, in Rule) (Rule, error) {
	if in.Provider == "" || in.SubAccountID == "" {
		return Rule{}, fmt.Errorf("%w: provider and sub_account_id are required", ErrInvalidRule)
	}
	switch in.Kind {
	case "weights":
		if len(in.Shares) == 0 || in.Cluster != "" {
			return Rule{}, fmt.Errorf("%w: weights rules need shares and no cluster", ErrInvalidRule)
		}
		for i, s := range in.Shares {
			w, ok := new(big.Rat).SetString(s.Weight)
			if !ok || w.Sign() <= 0 {
				return Rule{}, fmt.Errorf("%w: weights must be positive", ErrInvalidRule)
			}
			tenant, err := r.owner(ctx, s.ProjectID, s.EnvironmentID)
			if err != nil {
				return Rule{}, err
			}
			in.Shares[i].TenantID = tenant
		}
	case "k8s":
		if in.Cluster == "" || len(in.Shares) != 0 {
			return Rule{}, fmt.Errorf("%w: k8s rules need a cluster and no shares", ErrInvalidRule)
		}
	default:
		return Rule{}, fmt.Errorf("%w: kind is weights or k8s", ErrInvalidRule)
	}
	shares, _ := json.Marshal(in.Shares)
	if in.Shares == nil {
		shares = []byte("[]")
	}
	var svc, cluster *string
	if in.ServiceName != "" {
		svc = &in.ServiceName
	}
	if in.Cluster != "" {
		cluster = &in.Cluster
	}
	err := r.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO allocation_rules (tenant_id, provider, sub_account_id, service_name, kind, shares, cluster)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id::text`, home, in.Provider, in.SubAccountID, svc, in.Kind, shares, cluster).Scan(&in.ID)
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return Rule{}, ErrRuleExists
	}
	return in, err
}

func (r Rules) owner(ctx context.Context, project string, env *string) (string, error) {
	var tenant string
	var envOK bool
	err := r.Store.AppPool().QueryRow(ctx, `SELECT tenant_id::text, env_ok FROM project_owner($1::uuid, $2::uuid)`, project, env).Scan(&tenant, &envOK)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !envOK) {
		return "", fmt.Errorf("%w: unknown project or environment %s", ErrInvalidRule, project)
	}
	return tenant, err
}

// List returns active rules.
func (r Rules) List(ctx context.Context, home string) ([]Rule, error) {
	var out []Rule
	err := r.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, provider, sub_account_id, coalesce(service_name, ''), kind, shares, coalesce(cluster, '')
			FROM allocation_rules WHERE archived_at IS NULL ORDER BY provider, sub_account_id, service_name NULLS LAST`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Rule, error) {
			var x Rule
			var shares []byte
			err := row.Scan(&x.ID, &x.Provider, &x.SubAccountID, &x.ServiceName, &x.Kind, &shares, &x.Cluster)
			if err == nil {
				err = json.Unmarshal(shares, &x.Shares)
			}
			return x, err
		})
		return err
	})
	return out, err
}

// Archive retires a rule; later loads stop applying it.
func (r Rules) Archive(ctx context.Context, home, id string) error {
	return r.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE allocation_rules SET archived_at = now() WHERE id = $1 AND archived_at IS NULL`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return err
	})
}

// MapNamespace assigns a cluster namespace to a Project (and optionally Environment).
func (r Rules) MapNamespace(ctx context.Context, home, cluster, namespace, project string, env *string) error {
	tenant, err := r.owner(ctx, project, env)
	if err != nil {
		return err
	}
	return r.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO k8s_namespace_scopes (tenant_id, cluster, namespace, target_tenant_id, project_id, environment_id)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (cluster, namespace) DO UPDATE SET target_tenant_id = excluded.target_tenant_id, project_id = excluded.project_id, environment_id = excluded.environment_id`,
			home, cluster, namespace, tenant, project, env)
		return err
	})
}

// SaveNamespaceCosts stores one day's per-namespace cost for a cluster (from OpenCost).
func (r Rules) SaveNamespaceCosts(ctx context.Context, home, cluster string, day time.Time, costs map[string]float64) (int, error) {
	n := 0
	err := r.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		for ns, c := range costs {
			if _, err := tx.Exec(ctx, `INSERT INTO k8s_namespace_costs (tenant_id, cluster, day, namespace, cost) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (cluster, day, namespace) DO UPDATE SET cost = excluded.cost`, home, cluster, day, ns, c); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}
