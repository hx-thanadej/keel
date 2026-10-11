package pdpa

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// Evidence is the pdpa section of the evidence export: the Tenant's
// settings, schedule, residency state, and the retention runs and breaches in
// the period. The PDPA framework section points its Controls here.
type Evidence struct {
	Settings        Settings        `json:"settings"`
	Schedule        []Class         `json:"retention_schedule"`
	Residency       json.RawMessage `json:"residency"`
	RetentionRuns   json.RawMessage `json:"retention_runs"`
	SettingsChanges json.RawMessage `json:"settings_changes"`
	Breaches        []Breach        `json:"breaches"`
}

// Evidence builds the section for [from, to) inside the export's Tenant
// transaction.
func (s Service) Evidence(ctx context.Context, tx pgx.Tx, from, to time.Time) (Evidence, error) {
	out := Evidence{Schedule: Schedule}
	var err error
	if out.Settings, err = s.settings(ctx, tx); err != nil {
		return out, err
	}
	if err := tx.QueryRow(ctx, `SELECT jsonb_build_object(
			'open', (SELECT coalesce(jsonb_agg(jsonb_build_object('title', title, 'detail', detail, 'first_seen_at', first_seen_at) ORDER BY first_seen_at), '[]') FROM findings WHERE kind = 'pdpa_residency' AND status = 'open'),
			'resolved_in_period', (SELECT count(*) FROM findings WHERE kind = 'pdpa_residency' AND resolved_at >= $1 AND resolved_at < $2),
			'checks_in_period', (SELECT count(*) FROM activities WHERE type = 'keel.pdpa.residency.checked' AND occurred_at >= $1 AND occurred_at < $2),
			'last_check', (SELECT jsonb_build_object('at', occurred_at, 'detail', event->'data'->>'status_detail') FROM activities
				WHERE type = 'keel.pdpa.residency.checked' AND occurred_at < $2 ORDER BY seq DESC LIMIT 1))`, from, to).Scan(&out.Residency); err != nil {
		return out, err
	}
	activities := func(types ...string) (json.RawMessage, error) {
		var raw json.RawMessage
		err := tx.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_object('at', occurred_at, 'type', type, 'actor', actor_uid, 'detail', event->'data'->>'status_detail') ORDER BY seq), '[]')
			FROM activities WHERE type = ANY ($3) AND occurred_at >= $1 AND occurred_at < $2`, from, to, types).Scan(&raw)
		return raw, err
	}
	if out.RetentionRuns, err = activities("keel.pdpa.retention."+string(DryRun), "keel.pdpa.retention."+string(Deleted), "keel.pdpa.retention."+string(Held)); err != nil {
		return out, err
	}
	if out.SettingsChanges, err = activities("keel.pdpa.settings.updated", "keel.pdpa.deletion.enabled", "keel.pdpa.deletion.disabled"); err != nil {
		return out, err
	}
	if out.Breaches, err = breaches(ctx, tx, `declared_at < $2 AND (ended_at IS NULL OR ended_at >= $1) ORDER BY aware_at`, from, to); err != nil {
		return out, err
	}
	return out, nil
}
