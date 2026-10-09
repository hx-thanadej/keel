// Package scorecard scores each Service against Checks drawn from Keel's own
// data (#149): ownership, Golden Path, supply chain, Findings SLA and
// delivery. Checks are versioned; every failing check says why.
package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
)

// Version names the check set.
const Version = "keel-scorecard@1"

// Check is one rule: a boolean SQL expression over a Service (@service) at
// the Service clock's time (@at), plus the explanation shown when it fails.
type Check struct {
	Name, Control, Why, SQL string
}

// Checks is keel-scorecard@1.
var Checks = []Check{
	{"owner", "PO.2.1", "no owning Team",
		`SELECT EXISTS (SELECT 1 FROM services s JOIN teams t ON t.id = s.team_id WHERE s.id = @service)`},
	{"repository", "PS.1.1", "no source repository registered (catalog-info.yaml or a Service Template)",
		`SELECT EXISTS (SELECT 1 FROM services WHERE id = @service AND repository <> '' AND repository_id IS NOT NULL)`},
	{"golden_path", "PO.3.2", "not created from a Service Template",
		`SELECT EXISTS (SELECT 1 FROM services WHERE id = @service AND template <> '')`},
	{"scanned", "PW.7.2", "no full scanner upload in the last 30 days",
		`SELECT EXISTS (SELECT 1 FROM scan_runs WHERE service_id = @service AND scope = 'full' AND created_at > now() - interval '30 days')`},
	{"provenance", "SLSA-BUILD-L3", "latest Release has no passing provenance verification",
		`SELECT coalesce((SELECT release_verified(id) FROM releases WHERE service_id = @service ORDER BY created_at DESC LIMIT 1), false)`},
	{"sbom", "PS.3.2", "latest Release has no SBOM",
		`SELECT EXISTS (SELECT 1 FROM release_sboms b WHERE b.release_id = (SELECT id FROM releases WHERE service_id = @service ORDER BY created_at DESC LIMIT 1))`},
	{"findings_sla", "RV.2.2", "has overdue Findings",
		`SELECT NOT EXISTS (SELECT 1 FROM findings WHERE service_id = @service AND status = 'open' AND due_at < @at)`},
	{"critical_findings", "RV.2.2", "has open critical Findings without an Exception",
		`SELECT NOT EXISTS (SELECT 1 FROM findings f WHERE f.service_id = @service AND f.status = 'open' AND f.severity = 'critical' AND NOT finding_excepted(f, @at))`},
	{"deployed_recently", "DORA", "not deployed in the last 30 days",
		`SELECT EXISTS (SELECT 1 FROM promotions p JOIN releases r ON r.id = p.release_id WHERE r.service_id = @service AND p.state = 'deployed' AND p.deployed_at > now() - interval '30 days')`},
}

// Result is one check's outcome.
type Result struct {
	Name    string `json:"name"`
	Control string `json:"control"`
	Pass    bool   `json:"pass"`
	Why     string `json:"why,omitempty"`
}

// Card is a Service's scorecard.
type Card struct {
	ServiceID string   `json:"service_id"`
	Service   string   `json:"service"`
	TeamID    string   `json:"team_id"`
	Score     int      `json:"score"`
	Results   []Result `json:"checks"`
	Previous  *int     `json:"previous_score"` // 30 days ago, if known
}

// TeamScore rolls Cards up.
type TeamScore struct {
	TeamID   string `json:"team_id"`
	Team     string `json:"team"`
	Services int    `json:"services"`
	Score    int    `json:"score"`
}

// Report is a Tenant's scorecards.
type Report struct {
	Version string      `json:"version"`
	Cards   []Card      `json:"services"`
	Teams   []TeamScore `json:"teams"`
	Score   int         `json:"score"`
}

// Service computes and snapshots scorecards.
type Service struct {
	Store *store.Store
	Now   func() time.Time // defaults to time.Now
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Compute scores every active Service in a Tenant.
func (s Service) Compute(ctx context.Context, tenant string) (Report, error) {
	rep := Report{Version: Version, Cards: []Card{}, Teams: []TeamScore{}}
	at := s.now()
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.id::text, s.slug, s.team_id::text, t.name,
				(SELECT score FROM scorecard_snapshots x WHERE x.service_id = s.id AND x.day <= current_date - 30 ORDER BY day DESC LIMIT 1)
			FROM services s JOIN teams t ON t.id = s.team_id WHERE s.archived_at IS NULL ORDER BY s.slug`)
		if err != nil {
			return err
		}
		type svc struct {
			id, slug, team, teamName string
			prev                     *int
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (svc, error) {
			var x svc
			err := r.Scan(&x.id, &x.slug, &x.team, &x.teamName, &x.prev)
			return x, err
		})
		if err != nil {
			return err
		}
		teams := map[string]*TeamScore{}
		total := 0
		for _, x := range list {
			c := Card{ServiceID: x.id, Service: x.slug, TeamID: x.team, Previous: x.prev}
			passed := 0
			for _, ch := range Checks {
				var ok bool
				if err := tx.QueryRow(ctx, ch.SQL, pgx.NamedArgs{"service": x.id, "at": at}).Scan(&ok); err != nil {
					return fmt.Errorf("check %s: %w", ch.Name, err)
				}
				r := Result{Name: ch.Name, Control: ch.Control, Pass: ok}
				if !ok {
					r.Why = ch.Why
				} else {
					passed++
				}
				c.Results = append(c.Results, r)
			}
			c.Score = passed * 100 / len(Checks)
			total += c.Score
			rep.Cards = append(rep.Cards, c)
			t := teams[x.team]
			if t == nil {
				t = &TeamScore{TeamID: x.team, Team: x.teamName}
				teams[x.team] = t
			}
			t.Services++
			t.Score += c.Score
		}
		for _, t := range teams {
			t.Score /= t.Services
			rep.Teams = append(rep.Teams, *t)
		}
		sort.Slice(rep.Teams, func(i, j int) bool { return rep.Teams[i].Team < rep.Teams[j].Team })
		if len(list) > 0 {
			rep.Score = total / len(list)
		}
		return nil
	})
	return rep, err
}

// Snapshot stores today's scores for every Tenant (daily job).
func (s Service) Snapshot(ctx context.Context) (int, error) {
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return 0, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	day := s.now().UTC().Format("2006-01-02")
	n := 0
	for _, tenant := range tenants {
		rep, err := s.Compute(ctx, tenant)
		if err != nil {
			return n, err
		}
		if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			for _, c := range rep.Cards {
				raw, _ := json.Marshal(c.Results)
				if _, err := tx.Exec(ctx, `INSERT INTO scorecard_snapshots (tenant_id, service_id, day, version, score, checks) VALUES ($1, $2, $3, $4, $5, $6)
					ON CONFLICT (service_id, day) DO UPDATE SET version = excluded.version, score = excluded.score, checks = excluded.checks`,
					tenant, c.ServiceID, day, Version, c.Score, raw); err != nil {
					return err
				}
				n++
			}
			return nil
		}); err != nil {
			return n, err
		}
	}
	return n, nil
}
