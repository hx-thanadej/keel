package pdpa

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
)

// Class is one kind of data Keel stores and how long it keeps it. A Class
// with KeepDays 0 is never deleted by Keel, and Reason says why.
type Class struct {
	Name     string `json:"name"`
	Tables   string `json:"tables"`
	KeepDays int    `json:"keep_days"`
	From     string `json:"from,omitempty"` // what the period counts from
	Reason   string `json:"reason"`
	// expired selects the Class's rows older than the cutoff $1.
	expired string
}

// Schedule is the retention schedule, the same for every Tenant.
var Schedule = []Class{
	{Name: "activity_log", Tables: "activities, activity_digests, activity_exports", Reason: "Append-only and hash-chained (ADR-0005): deleting rows would break verify-log. " +
		"The WORM archive keeps the log under COMPLIANCE retention (KEEL_ARCHIVE_RETENTION_DAYS, default 7 years) and Keel never deletes from it."},
	{Name: "evidence_exports", Reason: "Built on demand and downloaded; Keel stores no copy, only the export Activity."},
	{Name: "findings", Tables: "findings", KeepDays: 3 * 365, From: "resolved_at", Reason: "Resolved Findings stay three years, a full audit cycle. Open Findings are never deleted.",
		expired: `status = 'resolved' AND resolved_at < $1 AND NOT EXISTS (SELECT 1 FROM recommendations r WHERE r.finding_id = findings.id)`},
	{Name: "cost_facts", Tables: "cost_facts", KeepDays: 5 * 365, From: "billing_period", Reason: "Billing lines stay five years, as accounting records.",
		expired: `billing_period < ($1::timestamptz AT TIME ZONE 'UTC')::date`},
	{Name: "tenant_reports", Tables: "tenant_reports", KeepDays: 5 * 365, From: "period", Reason: "Monthly reports carry cost figures; kept as long as the billing lines.",
		expired: `period < ($1::timestamptz AT TIME ZONE 'UTC')::date`},
	{Name: "utilisation", Tables: "utilisation_daily", KeepDays: 400, From: "day", Reason: "Rightsizing reads recent weeks; a year and a month allows year-on-year comparison.",
		expired: `day < ($1::timestamptz AT TIME ZONE 'UTC')::date`},
	{Name: "webhook_deliveries", Tables: "webhook_deliveries", KeepDays: 90, From: "received_at", Reason: "Delivery ids only guard against replays of recent deliveries.",
		expired: `received_at < $1`},
	{Name: "sessions", Tables: "sessions", KeepDays: 30, From: "expires_at", Reason: "Sessions name the signed-in person; kept 30 days past expiry for incident review.",
		expired: `expires_at < $1`},
}

// Mode is what a retention run did for a Tenant.
type Mode string

const (
	// DryRun counts what would be deleted: deletion is off for the Tenant.
	DryRun Mode = "dry_run"
	// Deleted deleted every expired row.
	Deleted Mode = "deleted"
	// Held counts and deletes nothing: a legal hold or an open breach.
	Held Mode = "held"
)

// ClassRun is one Class in one run. Rows counts the expired rows, deleted
// only when the run's Mode is Deleted.
type ClassRun struct {
	Class  string    `json:"class"`
	Before time.Time `json:"before"`
	Rows   int64     `json:"rows"`
}

// RetentionRun is one Tenant's run.
type RetentionRun struct {
	Tenant  string     `json:"tenant"`
	Mode    Mode       `json:"mode"`
	Why     string     `json:"why"`
	Classes []ClassRun `json:"classes"`
}

// RunRetention applies the schedule to every Tenant, one Activity per Tenant.
func (s Service) RunRetention(ctx context.Context) ([]RetentionRun, error) {
	list, err := tenants(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	var out []RetentionRun
	for _, tenant := range list {
		r, err := s.Retain(ctx, tenant)
		if err != nil {
			return out, fmt.Errorf("tenant %s: %w", tenant, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Retain applies the schedule to one Tenant. Deletion is off unless a
// platform admin enabled it; a legal hold or an open breach holds everything.
func (s Service) Retain(ctx context.Context, tenant string) (RetentionRun, error) {
	now := s.now()
	run := RetentionRun{Tenant: tenant}
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		set, err := s.settings(ctx, tx)
		if err != nil {
			return err
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pdpa_breaches WHERE state IN ('declared', 'warning', 'deadline')`).Scan(&open); err != nil {
			return err
		}
		switch {
		case set.LegalHold != "":
			run.Mode, run.Why = Held, "legal hold: "+set.LegalHold
		case open > 0:
			run.Mode, run.Why = Held, fmt.Sprintf("%d open personal data breach(es)", open)
		case set.DeletionEnabled:
			run.Mode, run.Why = Deleted, "deletion enabled"
		default:
			run.Mode, run.Why = DryRun, "deletion is off for this Tenant"
		}
		var parts []string
		for _, c := range Schedule {
			if c.expired == "" {
				continue
			}
			cr := ClassRun{Class: c.Name, Before: now.AddDate(0, 0, -c.KeepDays)}
			if run.Mode == Deleted {
				tag, err := tx.Exec(ctx, `DELETE FROM `+c.Tables+` WHERE `+c.expired, cr.Before)
				if err != nil {
					return fmt.Errorf("%s: %w", c.Name, err)
				}
				cr.Rows = tag.RowsAffected()
			} else if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+c.Tables+` WHERE `+c.expired, cr.Before).Scan(&cr.Rows); err != nil {
				return fmt.Errorf("%s: %w", c.Name, err)
			}
			run.Classes = append(run.Classes, cr)
			parts = append(parts, fmt.Sprintf("%s %d", c.Name, cr.Rows))
		}
		kind, verb := activity.Read, "would delete"
		if run.Mode == Deleted {
			kind, verb = activity.Delete, "deleted"
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/pdpa", Type: "keel.pdpa.retention." + string(run.Mode), Subject: "tenant/" + tenant,
			Operation: "ApplyRetention", Kind: kind, Actor: keelActor, Outcome: activity.Success, Time: now,
			StatusDetail: fmt.Sprintf("%s (%s): %s", verb, run.Why, strings.Join(parts, ", "))})
		return err
	})
	return run, err
}
