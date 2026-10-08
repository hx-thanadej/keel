package access

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
)

// Users lists the provider-native users (CAM sub-users) of an account.
type Users interface {
	Users(ctx context.Context) ([]string, error)
}

// Standing reports human access to production that no active Access Grant
// or registered break-glass identity explains (#134).
type Standing struct {
	Store     *store.Store
	Directory Directory
	Users     func(account string) (Users, error)
	// BreakGlass names provider users that are break-glass identities (#135).
	BreakGlass func(ctx context.Context, tenant, account string) (map[string]bool, error)
}

// StandingResult is the KPI: humans with standing production access.
type StandingResult struct {
	Accounts int `json:"accounts"`
	Standing int `json:"standing"`
	Excused  int `json:"excused"` // active grants and break-glass
}

type prodAccount struct{ external, env, project string }

// Run checks every production account of every Tenant.
func (s Standing) Run(ctx context.Context) (StandingResult, error) {
	var res StandingResult
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, tenant := range tenants {
		var accounts []prodAccount
		active := map[string]bool{} // role configuration|principal of active grants
		keel := map[string]bool{}   // Keel's role configurations
		if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT a.external_id, e.id::text, e.project_id::text FROM cloud_accounts a JOIN environments e ON e.id = a.environment_id
				WHERE a.provider = 'tencent' AND a.archived_at IS NULL AND e.name IN ('prod', 'production', 'prd')`)
			if err != nil {
				return err
			}
			if accounts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (prodAccount, error) {
				var a prodAccount
				err := r.Scan(&a.external, &a.env, &a.project)
				return a, err
			}); err != nil {
				return err
			}
			rows, err = tx.Query(ctx, `SELECT r.role_configuration, coalesce(g.principal_id, '') FROM access_grants g JOIN access_roles r ON r.id = g.role_id WHERE g.state = 'active'`)
			if err != nil {
				return err
			}
			for rows.Next() {
				var cfg, principal string
				if err := rows.Scan(&cfg, &principal); err != nil {
					return err
				}
				active[cfg+"|"+principal] = true
			}
			if err := rows.Err(); err != nil {
				return err
			}
			rows, err = tx.Query(ctx, `SELECT DISTINCT role_configuration FROM access_roles WHERE role_configuration IS NOT NULL`)
			if err != nil {
				return err
			}
			cfgs, err := pgx.CollectRows(rows, pgx.RowTo[string])
			for _, c := range cfgs {
				keel[c] = true
			}
			return err
		}); err != nil {
			return res, err
		}
		for _, a := range accounts {
			res.Accounts++
			var found []standingItem
			if s.Directory != nil {
				uin, err := strconv.ParseInt(a.external, 10, 64)
				if err != nil {
					continue
				}
				as, err := s.Directory.Assignments(ctx, uin)
				if err != nil {
					return res, fmt.Errorf("assignments %s: %w", a.external, err)
				}
				for _, as := range as {
					if active[as.RoleConfiguration+"|"+as.PrincipalID] {
						res.Excused++
						continue
					}
					what := "Identity Center assignment " + as.RoleName + " to " + strings.ToLower(as.PrincipalType) + " " + orDefault(as.PrincipalName, as.PrincipalID)
					if !keel[as.RoleConfiguration] {
						what += " (a role configuration Keel did not create)"
					}
					found = append(found, standingItem{key: "cic:" + as.RoleConfiguration + ":" + as.PrincipalID, what: what})
				}
			}
			if s.Users != nil {
				u, err := s.Users(a.external)
				if err != nil {
					return res, err
				}
				names, err := u.Users(ctx)
				if err != nil {
					return res, fmt.Errorf("users %s: %w", a.external, err)
				}
				excused := map[string]bool{}
				if s.BreakGlass != nil {
					if excused, err = s.BreakGlass(ctx, tenant, a.external); err != nil {
						return res, err
					}
				}
				for _, n := range names {
					if excused[n] {
						res.Excused++
						continue
					}
					found = append(found, standingItem{key: "cam:" + n, what: "CAM user " + n + " (standing credentials)"})
				}
			}
			res.Standing += len(found)
			if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error { return standingFindings(ctx, tx, tenant, a, found) }); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

type standingItem struct{ key, what string }

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func standingFindings(ctx context.Context, tx pgx.Tx, tenant string, a prodAccount, items []standingItem) error {
	prefix := "standing_access:" + a.external + ":"
	open := map[string]bool{}
	for _, it := range items {
		fp := prefix + it.key
		open[fp] = true
		detail, _ := json.Marshal(map[string]any{"account": a.external, "access": it.what})
		if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, environment_id, owner_team_id)
			VALUES ($1, 'standing_access', $2, 'critical', $3, $4, $5, $6, (SELECT team_id FROM projects WHERE id = $5))
			ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now()`,
			tenant, fp, "Standing production access in "+a.external+": "+it.what, detail, a.project, a.env); err != nil {
			return err
		}
	}
	rows, err := tx.Query(ctx, `SELECT fingerprint FROM findings WHERE kind = 'standing_access' AND status = 'open' AND fingerprint LIKE $1`, prefix+"%")
	if err != nil {
		return err
	}
	fps, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, fp := range fps {
		if !open[fp] {
			if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now(), resolution = 'access removed'
				WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, fp); err != nil {
				return err
			}
		}
	}
	return nil
}
