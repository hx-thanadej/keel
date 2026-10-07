package sbom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

var (
	ErrNotFound = errors.New("release not found")
	ErrInvalid  = errors.New("invalid")
)

// Summary is a stored SBOM.
type Summary struct {
	ID          string    `json:"id"`
	ReleaseID   string    `json:"release_id"`
	Format      string    `json:"format"`
	SpecVersion string    `json:"spec_version"`
	Tool        string    `json:"tool"`
	Components  int       `json:"components"`
	Gaps        []string  `json:"gaps"`
	CreatedAt   time.Time `json:"created_at"`
}

// Service stores SBOMs.
type Service struct {
	Store *store.Store
}

// Submit stores a Release's SBOM and its components.
func (s Service) Submit(ctx context.Context, tenant, release string, raw []byte, by activity.Actor) (Summary, error) {
	d, err := Parse(raw)
	if err != nil {
		return Summary{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if d.Gaps == nil {
		d.Gaps = []string{}
	}
	out := Summary{ReleaseID: release, Format: d.Format, SpecVersion: d.SpecVersion, Tool: d.Tool, Components: len(d.Components), Gaps: d.Gaps}
	err = s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM releases WHERE id = $1)`, release).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		gaps, _ := json.Marshal(d.Gaps)
		if err := tx.QueryRow(ctx, `INSERT INTO release_sboms (tenant_id, release_id, format, spec_version, tool, components, gaps, submitted_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id::text, created_at`, tenant, release, d.Format, d.SpecVersion, d.Tool, len(d.Components), gaps, by.UID).Scan(&out.ID, &out.CreatedAt); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, c := range d.Components {
			b.Queue(`INSERT INTO release_components (tenant_id, release_id, purl, name, version, ecosystem) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
				tenant, release, c.PURL, c.Name, c.Version, c.Ecosystem)
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
		_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/sbom", Type: "keel.release.sbom", Subject: "release/" + release,
			Operation: "SubmitSBOM", Kind: activity.Create, Actor: by, Outcome: activity.Success,
			Resources:    []activity.Resource{{Type: "release", UID: release}},
			StatusDetail: fmt.Sprintf("%s %s from %s: %d components, %d minimum-element gaps", d.Format, d.SpecVersion, orNone(d.Tool), len(d.Components), len(d.Gaps))})
		return err
	})
	return out, err
}

func orNone(s string) string {
	if s == "" {
		return "an unnamed tool"
	}
	return s
}

// Usage is where a component runs.
type Usage struct {
	Service      string   `json:"service"`
	ReleaseID    string   `json:"release_id"`
	Version      string   `json:"release_version"`
	PURL         string   `json:"purl"`
	Environments []string `json:"deployed_to"`
}

// Where answers "where do we run <name>?" across Releases, with the
// Environments each Release is currently deployed to.
func (s Service) Where(ctx context.Context, tenant, name string) ([]Usage, error) {
	var out []Usage
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.slug, r.id::text, r.version, c.purl,
				coalesce((SELECT array_agg(DISTINCT e.name ORDER BY e.name) FROM promotions p JOIN environments e ON e.id = p.environment_id
				          WHERE p.release_id = r.id AND p.state = 'deployed'), '{}')
			FROM release_components c JOIN releases r ON r.id = c.release_id JOIN services s ON s.id = r.service_id
			WHERE c.name = $1 OR c.purl LIKE '%/' || $1 || '@%' ORDER BY s.slug, r.created_at DESC LIMIT 500`, name)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Usage])
		return err
	})
	return out, err
}
