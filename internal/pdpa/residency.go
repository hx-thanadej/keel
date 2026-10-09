package pdpa

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
)

// Location is somewhere a Tenant's data or logs are stored.
type Location struct {
	Kind   string `json:"kind"` // cloud_account | archive | bill_bucket
	Name   string `json:"name"`
	Region string `json:"region"`
}

func (l Location) fingerprint() string {
	return "pdpa_residency:" + l.Kind + ":" + l.Name + ":" + l.Region
}

// ResidencyRun is one Tenant's residency check.
type ResidencyRun struct {
	Tenant   string     `json:"tenant"`
	Regions  []string   `json:"regions"`
	Outside  []Location `json:"outside"`
	Raised   int        `json:"raised"`
	Resolved int        `json:"resolved"`
}

// usageWindow is how far back billed usage places a Cloud Account in a region.
const usageWindowDays = 35

// RunResidency checks every Tenant's data against its region set: the
// regions its Cloud Accounts were billed in recently, and the platform
// buckets every Tenant's data passes through. Each Location outside the set
// is an open Finding until it is back inside or gone.
func (s Service) RunResidency(ctx context.Context) ([]ResidencyRun, error) {
	list, err := tenants(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	var out []ResidencyRun
	for _, tenant := range list {
		r, err := s.CheckResidency(ctx, tenant)
		if err != nil {
			return out, fmt.Errorf("tenant %s: %w", tenant, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// CheckResidency runs the check for one Tenant.
func (s Service) CheckResidency(ctx context.Context, tenant string) (ResidencyRun, error) {
	now := s.now()
	run := ResidencyRun{Tenant: tenant}
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		set, err := s.settings(ctx, tx)
		if err != nil {
			return err
		}
		run.Regions = set.DataRegions
		rows, err := tx.Query(ctx, `SELECT DISTINCT 'cloud_account', f.provider || ':' || coalesce(a.name, f.sub_account_id), f.region_id
			FROM cost_facts f LEFT JOIN cloud_accounts a ON a.id = f.cloud_account_id
			WHERE f.current AND f.region_id <> '' AND f.charge_period_start >= $1 ORDER BY 2, 3`, now.AddDate(0, 0, -usageWindowDays))
		if err != nil {
			return err
		}
		locs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Location, error) {
			var l Location
			err := r.Scan(&l.Kind, &l.Name, &l.Region)
			return l, err
		})
		if err != nil {
			return err
		}
		locs = append(slices.Clone(s.Stores), locs...)
		seen := []string{}
		for _, l := range locs {
			if slices.Contains(set.DataRegions, l.Region) {
				continue
			}
			run.Outside = append(run.Outside, l)
			seen = append(seen, l.fingerprint())
			tag, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at, last_seen_at)
				VALUES ($1, 'pdpa_residency', $2, 'high', $3, jsonb_build_object('kind', $4::text, 'name', $5::text, 'region', $6::text, 'data_regions', $7::text[], 'law', 'PDPA s.28'), $8, $8)
				ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO NOTHING`,
				tenant, l.fingerprint(), fmt.Sprintf("PDPA: %s %s stores data in %s, outside %s", strings.ReplaceAll(l.Kind, "_", " "), l.Name, l.Region, strings.Join(set.DataRegions, ", ")),
				l.Kind, l.Name, l.Region, set.DataRegions, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				run.Raised++
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE findings SET last_seen_at = $2 WHERE fingerprint = $1 AND status = 'open'`, l.fingerprint(), now); err != nil {
				return err
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $1, resolution = 'stored inside the Tenant data region set, or no longer stored'
			WHERE kind = 'pdpa_residency' AND status = 'open' AND fingerprint <> ALL ($2)`, now, seen)
		if err != nil {
			return err
		}
		run.Resolved = int(tag.RowsAffected())
		outcome := activity.Success
		if len(run.Outside) > 0 {
			outcome = activity.Failure
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/pdpa", Type: "keel.pdpa.residency.checked", Subject: "tenant/" + tenant,
			Operation: "CheckResidency", Kind: activity.Read, Actor: keelActor, Outcome: outcome, Time: now,
			StatusDetail: fmt.Sprintf("%d locations, %d outside %s; raised %d, resolved %d", len(locs), len(run.Outside), strings.Join(set.DataRegions, ","), run.Raised, run.Resolved)})
		return err
	})
	return run, err
}
