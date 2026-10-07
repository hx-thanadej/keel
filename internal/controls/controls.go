// Package controls is Keel's Controls registry (#116, ADR-0009): Controls
// from SSDF, SLSA, CRA and the OWASP CI/CD Top 10, the Keel Policies that
// satisfy them, and at which Enforcement Point. Coverage per Tenant says how
// many Services each Policy actually evaluated; M6 Scorecards and evidence
// exports build on it.
package controls

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"

	"github.com/hx-thanadej/keel/internal/store"
)

//go:embed controls.yaml
var registryYAML []byte

// Policy is one Keel policy at one Enforcement Point.
type Policy struct {
	Name        string `yaml:"name" json:"name"`
	Point       string `yaml:"point" json:"point"` // api | pr | pipeline | promotion | admission | cloud | platform
	Description string `yaml:"description" json:"description"`
}

// Control is a requirement.
type Control struct {
	ID        string   `yaml:"id" json:"id"`
	Framework string   `yaml:"framework" json:"framework"`
	Title     string   `yaml:"title" json:"title"`
	Policies  []string `yaml:"policies" json:"policies"`
}

// Registry is the versioned data.
type Registry struct {
	Version  string    `yaml:"version"`
	Policies []Policy  `yaml:"policies"`
	Controls []Control `yaml:"controls"`
}

// Load parses the embedded registry and checks every mapping names a known
// Policy.
func Load() (Registry, error) {
	var r Registry
	if err := yaml.Unmarshal(registryYAML, &r); err != nil {
		return r, err
	}
	known := map[string]bool{}
	for _, p := range r.Policies {
		if _, ok := coverage[p.Name]; !ok {
			return r, fmt.Errorf("policy %s has no coverage query", p.Name)
		}
		known[p.Name] = true
	}
	seen := map[string]bool{}
	for _, c := range r.Controls {
		if seen[c.Framework+c.ID] {
			return r, fmt.Errorf("control %s %s listed twice", c.Framework, c.ID)
		}
		seen[c.Framework+c.ID] = true
		for _, p := range c.Policies {
			if !known[p] {
				return r, fmt.Errorf("control %s names unknown policy %s", c.ID, p)
			}
		}
	}
	return r, nil
}

// coverage counts the Tenant's Services a Policy has evaluated.
var coverage = map[string]string{
	"keel-authz@1":       `SELECT count(*) FROM services WHERE archived_at IS NULL`,
	"keel-github@1":      `SELECT count(*) FROM services WHERE archived_at IS NULL AND repository_id IS NOT NULL`,
	"keel-scans@1":       `SELECT count(DISTINCT service_id) FROM scan_runs WHERE created_at > now() - interval '30 days'`,
	"keel-release@1":     `SELECT count(DISTINCT r.service_id) FROM release_attestations a JOIN releases r ON r.id = a.release_id WHERE a.passed`,
	"keel-sbom@1":        `SELECT count(DISTINCT r.service_id) FROM release_sboms b JOIN releases r ON r.id = b.release_id`,
	"keel-promotion@1":   `SELECT count(DISTINCT r.service_id) FROM promotions p JOIN releases r ON r.id = p.release_id`,
	"keel-admission@1":   `SELECT count(*) FROM services s WHERE archived_at IS NULL AND EXISTS (SELECT 1 FROM environments e WHERE e.project_id = s.project_id AND e.admission_hash <> '' AND e.admission_mode = 'enforce')`,
	"keel-baseline@1":    `SELECT count(*) FROM services s WHERE archived_at IS NULL AND EXISTS (SELECT 1 FROM environments e JOIN cloud_accounts a ON a.environment_id = e.id WHERE e.project_id = s.project_id AND a.baseline_version IS NOT NULL)`,
	"keel-ci-identity@1": `SELECT count(*) FROM services s WHERE archived_at IS NULL AND repository_id IS NOT NULL AND EXISTS (SELECT 1 FROM environments e JOIN cloud_accounts a ON a.environment_id = e.id WHERE e.project_id = s.project_id AND a.ci_identity_at IS NOT NULL)`,
	"keel-findings@1":    `SELECT count(*) FROM services WHERE archived_at IS NULL`,
	"keel-vex@1":         `SELECT count(DISTINCT service_id) FROM vex_statements`,
	"keel-activity@1":    `SELECT count(*) FROM services WHERE archived_at IS NULL`,
}

// PolicyCoverage is one Policy's reach in a Tenant.
type PolicyCoverage struct {
	Policy
	Covered int `json:"covered_services"`
}

// ControlView is a Control with its Policies' coverage.
type ControlView struct {
	Control
	Coverage []PolicyCoverage `json:"coverage"`
	Gap      bool             `json:"gap"` // no Policy, or no Service covered
}

// Report is a Tenant's view of the registry.
type Report struct {
	Version  string        `json:"version"`
	Services int           `json:"services"`
	Controls []ControlView `json:"controls"`
}

// Service computes coverage.
type Service struct {
	Store    *store.Store
	Registry Registry
}

// Report returns every Control with coverage for one Tenant.
func (s Service) Report(ctx context.Context, tenant string) (Report, error) {
	rep := Report{Version: s.Registry.Version}
	covered := map[string]int{}
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM services WHERE archived_at IS NULL`).Scan(&rep.Services); err != nil {
			return err
		}
		for _, p := range s.Registry.Policies {
			var n int
			if err := tx.QueryRow(ctx, coverage[p.Name]).Scan(&n); err != nil {
				return fmt.Errorf("coverage %s: %w", p.Name, err)
			}
			covered[p.Name] = n
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	byName := map[string]Policy{}
	for _, p := range s.Registry.Policies {
		byName[p.Name] = p
	}
	for _, c := range s.Registry.Controls {
		v := ControlView{Control: c, Coverage: []PolicyCoverage{}}
		any := false
		for _, name := range c.Policies {
			v.Coverage = append(v.Coverage, PolicyCoverage{Policy: byName[name], Covered: covered[name]})
			if covered[name] > 0 {
				any = true
			}
		}
		v.Gap = !any
		rep.Controls = append(rep.Controls, v)
	}
	return rep, nil
}
