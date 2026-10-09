// Package pdpa runs Keel's Thailand PDPA obligations (#190, ADR-0017): each
// Tenant's data region set and the residency check against it, the retention
// schedule and its deletion job (dry run unless a platform admin enables
// deletion), and the 72-hour clock to notify the PDPC of a personal data
// breach.
package pdpa

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

var (
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = errors.New("not found")
	ErrState    = errors.New("breach has already ended")
)

// DefaultRegions is the region set for Thailand Tenants: Tencent Cloud and
// AWS Bangkok.
var DefaultRegions = []string{"ap-bangkok", "ap-southeast-7"}

// Settings is one Tenant's PDPA configuration.
type Settings struct {
	DataRegions     []string   `json:"data_regions"`
	DeletionEnabled bool       `json:"deletion_enabled"`
	LegalHold       string     `json:"legal_hold"` // the reason; "" means no hold
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	UpdatedBy       string     `json:"updated_by,omitempty"`
}

// Service is the PDPA module. Now is the service clock.
type Service struct {
	Store *store.Store
	Now   func() time.Time
	// Regions overrides DefaultRegions for Tenants with no settings.
	Regions []string
	// Stores are platform buckets that hold every Tenant's data or logs
	// (the Activity Log archive, bill buckets).
	Stores []Location
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Service) defaults() []string {
	if len(s.Regions) > 0 {
		return s.Regions
	}
	return DefaultRegions
}

func (s Service) settings(ctx context.Context, tx pgx.Tx) (Settings, error) {
	var out Settings
	err := tx.QueryRow(ctx, `SELECT data_regions, deletion_enabled, legal_hold, updated_at, updated_by FROM pdpa_settings`).
		Scan(&out.DataRegions, &out.DeletionEnabled, &out.LegalHold, &out.UpdatedAt, &out.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{DataRegions: s.defaults()}, nil
	}
	return out, err
}

var regionRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,39}$`)

// Configure replaces a Tenant's settings. Turning deletion on or off is
// recorded as its own Activity type.
func (s Service) Configure(ctx context.Context, tenant string, in Settings, by activity.Actor) (Settings, error) {
	if len(in.DataRegions) == 0 {
		in.DataRegions = s.defaults()
	}
	for _, r := range in.DataRegions {
		if !regionRE.MatchString(r) {
			return Settings{}, fmt.Errorf("%w: region %q", ErrInvalid, r)
		}
	}
	in.LegalHold = strings.TrimSpace(in.LegalHold)
	if len(in.LegalHold) > 500 {
		return Settings{}, fmt.Errorf("%w: legal hold reason over 500 characters", ErrInvalid)
	}
	slices.Sort(in.DataRegions)
	in.DataRegions = slices.Compact(in.DataRegions)
	now := s.now()
	in.UpdatedAt, in.UpdatedBy = &now, by.UID
	return in, s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		was, err := s.settings(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO pdpa_settings (tenant_id, data_regions, deletion_enabled, legal_hold, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id) DO UPDATE SET data_regions = $2, deletion_enabled = $3, legal_hold = $4, updated_at = $5, updated_by = $6`,
			tenant, in.DataRegions, in.DeletionEnabled, in.LegalHold, now, by.UID); err != nil {
			return err
		}
		typ := "keel.pdpa.settings.updated"
		switch {
		case in.DeletionEnabled && !was.DeletionEnabled:
			typ = "keel.pdpa.deletion.enabled"
		case !in.DeletionEnabled && was.DeletionEnabled:
			typ = "keel.pdpa.deletion.disabled"
		}
		hold := "none"
		if in.LegalHold != "" {
			hold = in.LegalHold
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/pdpa", Type: typ, Subject: "tenant/" + tenant,
			Operation: "ConfigurePDPA", Kind: activity.Update, Actor: by, Outcome: activity.Success, Time: now,
			StatusDetail: fmt.Sprintf("data regions %s; deletion enabled %t (was %t); legal hold: %s", strings.Join(in.DataRegions, ","), in.DeletionEnabled, was.DeletionEnabled, hold)})
		return err
	})
}

// Overview is what the API shows: settings, the retention schedule and every
// breach.
type Overview struct {
	Settings Settings `json:"settings"`
	Schedule []Class  `json:"retention_schedule"`
	Breaches []Breach `json:"breaches"`
}

// Overview reads one Tenant's PDPA state.
func (s Service) Overview(ctx context.Context, tenant string) (Overview, error) {
	out := Overview{Schedule: Schedule}
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if out.Settings, err = s.settings(ctx, tx); err != nil {
			return err
		}
		out.Breaches, err = breaches(ctx, tx, `TRUE ORDER BY aware_at DESC`)
		return err
	})
	return out, err
}

func tenants(ctx context.Context, s *store.Store) ([]string, error) {
	rows, err := s.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:pdpa"}
