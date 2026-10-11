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

// Change is a partial settings update: a nil field keeps its stored value,
// so omitting legal_hold never lifts a hold. Lifting one means sending
// legal_hold "" with a LiftReason.
type Change struct {
	DataRegions     *[]string `json:"data_regions"`
	DeletionEnabled *bool     `json:"deletion_enabled"`
	LegalHold       *string   `json:"legal_hold"`
	LiftReason      string    `json:"lift_reason"`
}

// Configure applies a Change to a Tenant's settings. Turning deletion on or
// off, and placing or lifting a legal hold, are each their own Activity type.
func (s Service) Configure(ctx context.Context, tenant string, ch Change, by activity.Actor) (Settings, error) {
	if ch.DataRegions != nil {
		for _, r := range *ch.DataRegions {
			if !regionRE.MatchString(r) {
				return Settings{}, fmt.Errorf("%w: region %q", ErrInvalid, r)
			}
		}
	}
	if ch.LegalHold != nil {
		if *ch.LegalHold = strings.TrimSpace(*ch.LegalHold); len(*ch.LegalHold) > 500 {
			return Settings{}, fmt.Errorf("%w: legal hold reason over 500 characters", ErrInvalid)
		}
	}
	ch.LiftReason = strings.TrimSpace(ch.LiftReason)
	if len(ch.LiftReason) > 500 {
		return Settings{}, fmt.Errorf("%w: lift reason over 500 characters", ErrInvalid)
	}
	now := s.now()
	var out Settings
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		was, err := s.settings(ctx, tx)
		if err != nil {
			return err
		}
		out = was
		if ch.DataRegions != nil {
			out.DataRegions = slices.Clone(*ch.DataRegions)
			if len(out.DataRegions) == 0 {
				out.DataRegions = s.defaults()
			}
			slices.Sort(out.DataRegions)
			out.DataRegions = slices.Compact(out.DataRegions)
		}
		if ch.DeletionEnabled != nil {
			out.DeletionEnabled = *ch.DeletionEnabled
		}
		if ch.LegalHold != nil {
			out.LegalHold = *ch.LegalHold
		}
		lifted := was.LegalHold != "" && out.LegalHold == ""
		if lifted && ch.LiftReason == "" {
			return fmt.Errorf("%w: lifting the legal hold needs lift_reason", ErrInvalid)
		}
		out.UpdatedAt, out.UpdatedBy = &now, by.UID
		if _, err := tx.Exec(ctx, `INSERT INTO pdpa_settings (tenant_id, data_regions, deletion_enabled, legal_hold, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id) DO UPDATE SET data_regions = $2, deletion_enabled = $3, legal_hold = $4, updated_at = $5, updated_by = $6`,
			tenant, out.DataRegions, out.DeletionEnabled, out.LegalHold, now, by.UID); err != nil {
			return err
		}
		var types []string
		switch {
		case out.DeletionEnabled && !was.DeletionEnabled:
			types = append(types, "keel.pdpa.deletion.enabled")
		case !out.DeletionEnabled && was.DeletionEnabled:
			types = append(types, "keel.pdpa.deletion.disabled")
		}
		switch {
		case lifted:
			types = append(types, "keel.pdpa.legal_hold.lifted")
		case out.LegalHold != was.LegalHold:
			types = append(types, "keel.pdpa.legal_hold.placed")
		}
		if len(types) == 0 {
			types = append(types, "keel.pdpa.settings.updated")
		}
		hold := func(h string) string {
			if h == "" {
				return "none"
			}
			return h
		}
		detail := fmt.Sprintf("data regions %s; deletion enabled %t (was %t); legal hold: %s (was %s)",
			strings.Join(out.DataRegions, ","), out.DeletionEnabled, was.DeletionEnabled, hold(out.LegalHold), hold(was.LegalHold))
		if lifted {
			detail += "; lifted because: " + ch.LiftReason
		}
		for _, typ := range types {
			if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/pdpa", Type: typ, Subject: "tenant/" + tenant,
				Operation: "ConfigurePDPA", Kind: activity.Update, Actor: by, Outcome: activity.Success, Time: now, StatusDetail: detail}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Settings{}, err
	}
	return out, nil
}

// Overview is what the API shows: settings, the retention schedule, every
// breach and the newest retention run.
type Overview struct {
	Settings      Settings `json:"settings"`
	Schedule      []Class  `json:"retention_schedule"`
	Breaches      []Breach `json:"breaches"`
	LastRetention *LastRun `json:"last_retention_run"`
}

// LastRun is a retention run as its Activity recorded it; Detail carries the
// per-class counts.
type LastRun struct {
	RanAt  time.Time `json:"ran_at"`
	Mode   Mode      `json:"mode"`
	Detail string    `json:"detail"`
}

// Overview reads one Tenant's PDPA state.
func (s Service) Overview(ctx context.Context, tenant string) (Overview, error) {
	out := Overview{Schedule: Schedule}
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if out.Settings, err = s.settings(ctx, tx); err != nil {
			return err
		}
		if out.Breaches, err = breaches(ctx, tx, `TRUE ORDER BY aware_at DESC`); err != nil {
			return err
		}
		var run LastRun
		var typ string
		err = tx.QueryRow(ctx, `SELECT occurred_at, type, coalesce(event->'data'->>'status_detail', '') FROM activities
			WHERE type IN ('keel.pdpa.retention.dry_run', 'keel.pdpa.retention.deleted', 'keel.pdpa.retention.held') ORDER BY seq DESC LIMIT 1`).
			Scan(&run.RanAt, &typ, &run.Detail)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		run.RanAt, run.Mode = run.RanAt.UTC(), Mode(strings.TrimPrefix(typ, "keel.pdpa.retention."))
		out.LastRetention = &run
		return nil
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
