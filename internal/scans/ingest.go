package scans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

var (
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = errors.New("service not found")
)

// Run is one recorded upload.
type Run struct {
	ID        string    `json:"id"`
	ServiceID string    `json:"service_id"`
	Tool      string    `json:"tool"`
	Scope     string    `json:"scope"`
	CommitSHA string    `json:"commit_sha"`
	Ref       string    `json:"ref"`
	Results   int       `json:"results"`
	Raised    int       `json:"raised"`
	Resolved  int       `json:"resolved"`
	CreatedAt time.Time `json:"created_at"`
}

// Upload is one SARIF file from CI.
type Upload struct {
	Scope     string // full: absent results resolve; diff: only adds
	CommitSHA string
	Ref       string
	SARIF     []byte
	// Dismissed fingerprints are neither raised nor kept open: the source
	// already decided them (GitHub code scanning dismissals).
	Dismissed []string
	// GitHubAnalysisIDs are the GitHub code scanning analyses this SARIF
	// came from, so the GitHub sync ingests each analysis once.
	GitHubAnalysisIDs []int64
}

// Service ingests scans.
type Service struct {
	Store *store.Store
}

// Ingest records a SARIF upload for a Service as Findings owned by its Team.
func (s Service) Ingest(ctx context.Context, tenant, service string, u Upload, by activity.Actor) (Run, error) {
	if u.Scope != "full" && u.Scope != "diff" {
		return Run{}, fmt.Errorf("%w: scope must be full or diff", ErrInvalid)
	}
	tools, results, err := ParseSARIF(u.SARIF, service)
	if err != nil {
		return Run{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(tools) == 0 {
		return Run{}, fmt.Errorf("%w: SARIF has no runs", ErrInvalid)
	}
	run := Run{ServiceID: service, Tool: strings.Join(tools, ","), Scope: u.Scope, CommitSHA: u.CommitSHA, Ref: u.Ref, Results: len(results)}
	err = s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var project, team, slug string
		err := tx.QueryRow(ctx, `SELECT project_id::text, team_id::text, slug FROM services WHERE id = $1 AND archived_at IS NULL`, service).Scan(&project, &team, &slug)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		current := make([]string, 0, len(results))
		for _, r := range results {
			if slices.Contains(u.Dismissed, r.Fingerprint) {
				continue
			}
			current = append(current, r.Fingerprint)
			if r.Kind == "vulnerability" {
				var suppressed bool
				if err := tx.QueryRow(ctx, `SELECT vex_suppressed($1, $2)`, r.RuleID, service).Scan(&suppressed); err != nil {
					return err
				}
				if suppressed {
					continue // a VEX statement says this Service is not affected
				}
			}
			r.Detail["service"], r.Detail["commit"], r.Detail["ref"] = slug, u.CommitSHA, u.Ref
			detail, _ := json.Marshal(r.Detail)
			title := fmt.Sprintf("%s in %s: %s", r.RuleID, slug, r.Title)
			var inserted bool
			// One Finding per fingerprint: a second tool reporting the same
			// vulnerability adds itself to detail.tools instead of a duplicate.
			err := tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, owner_team_id, service_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
				ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET
				    last_seen_at = now(),
				    detail = findings.detail || jsonb_build_object(
				        'tools', (SELECT jsonb_agg(DISTINCT t) FROM jsonb_array_elements(coalesce(findings.detail->'tools', '[]') || (excluded.detail->'tools')) AS t),
				        'locations', excluded.detail->'locations', 'commit', excluded.detail->'commit', 'message', excluded.detail->'message'),
				    severity = CASE WHEN array_position(ARRAY['critical','high','medium','low'], excluded.severity) < array_position(ARRAY['critical','high','medium','low'], findings.severity)
				                    THEN excluded.severity ELSE findings.severity END
				RETURNING (xmax = 0)`, tenant, r.Kind, r.Fingerprint, r.Severity, title, detail, project, team, service).Scan(&inserted)
			if err != nil {
				return err
			}
			if inserted {
				run.Raised++
			}
		}
		if u.Scope == "full" {
			for _, tool := range tools {
				n, err := resolveAbsent(ctx, tx, service, tool, current)
				if err != nil {
					return err
				}
				run.Resolved += n
			}
		}
		if err := tx.QueryRow(ctx, `INSERT INTO scan_runs (tenant_id, service_id, tool, scope, commit_sha, ref, results, raised, resolved, uploaded_by, github_analysis_ids)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id::text, created_at`,
			tenant, service, run.Tool, run.Scope, run.CommitSHA, run.Ref, run.Results, run.Raised, run.Resolved, by.UID, u.GitHubAnalysisIDs).Scan(&run.ID, &run.CreatedAt); err != nil {
			return err
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/scans", Type: "keel.scan.ingested", Subject: "service/" + service,
			Operation: "IngestScan", Kind: activity.Create, Actor: by, Outcome: activity.Success,
			Resources:    []activity.Resource{{Type: "service", UID: service, OwnerTeam: team}, {Type: "scan_run", UID: run.ID}},
			StatusDetail: fmt.Sprintf("%s %s scan of %s@%.12s: %d results, %d new, %d resolved", run.Tool, run.Scope, slug, u.CommitSHA, run.Results, run.Raised, run.Resolved)})
		return err
	})
	return run, err
}

// ResolveAbsent is resolveAbsent for other sources of vulnerability
// Findings (OSV re-matching) that report under their own tool name.
func ResolveAbsent(ctx context.Context, tx pgx.Tx, service, tool string, current []string) (int, error) {
	return resolveAbsent(ctx, tx, service, tool, current)
}

// resolveAbsent: a full scan by tool that no longer reports a Finding removes
// the tool from it; with no tool left reporting, the Finding is resolved.
func resolveAbsent(ctx context.Context, tx pgx.Tx, service, tool string, current []string) (int, error) {
	if current == nil {
		current = []string{} // a nil slice is SQL NULL, and "x = ANY(NULL)" is never false
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET detail = jsonb_set(detail, '{tools}', (detail->'tools') - $2)
		WHERE service_id = $1 AND status = 'open' AND detail->'tools' ? $2 AND NOT (fingerprint = ANY ($3::text[]))`, service, tool, current); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now(), resolution = 'no longer reported by a full scan'
		WHERE service_id = $1 AND status = 'open' AND detail ? 'tools' AND jsonb_array_length(detail->'tools') = 0`, service)
	return int(tag.RowsAffected()), err
}

// Runs lists recent uploads.
func (s Service) Runs(ctx context.Context, tenant, service string) ([]Run, error) {
	var out []Run
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, service_id::text, tool, scope, commit_sha, ref, results, raised, resolved, created_at FROM scan_runs
			WHERE ($1 = '' OR service_id::text = $1) ORDER BY created_at DESC LIMIT 200`, service)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Run])
		return err
	})
	return out, err
}
