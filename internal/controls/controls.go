// Package controls is Keel's Controls registry (#116, ADR-0009): Controls
// from SSDF, SLSA, CRA, the OWASP CI/CD Top 10, ISO/IEC 27001:2022 Annex A,
// the SOC 2 Trust Services Criteria (#188, #189) and Thailand's PDPA (#190),
// the Keel Policies that evidence them, and at which Enforcement Point.
// Coverage per Tenant says how many Services each Policy actually evaluated;
// M6 Scorecards and evidence exports build on it.
package controls

import (
	"bytes"
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

// Framework is a catalogue Controls come from.
type Framework struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
}

// Control is one framework requirement. CoveredBy names the Policies that
// evidence it; when none do, GapReason says why.
type Control struct {
	ID        string   `yaml:"id" json:"id"`
	Framework string   `yaml:"framework" json:"framework"`
	Title     string   `yaml:"title" json:"title"`
	CoveredBy []string `yaml:"covered_by" json:"covered_by"`
	GapReason string   `yaml:"gap_reason" json:"gap_reason,omitempty"`
}

// Registry is the versioned data.
type Registry struct {
	Version    string      `yaml:"version"`
	Frameworks []Framework `yaml:"frameworks"`
	Policies   []Policy    `yaml:"policies"`
	Controls   []Control   `yaml:"controls"`
}

// Load parses the embedded registry and checks it: every Control names a
// known framework and known Policies, appears once, and has either Policies
// or a gap reason.
func Load() (Registry, error) {
	return parse(registryYAML)
}

func parse(data []byte) (Registry, error) {
	var r Registry
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return r, err
	}
	frameworks := map[string]bool{}
	for _, f := range r.Frameworks {
		frameworks[f.ID] = true
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
		key := c.Framework + " " + c.ID
		if !frameworks[c.Framework] {
			return r, fmt.Errorf("control %s names unknown framework", key)
		}
		if seen[key] {
			return r, fmt.Errorf("control %s listed twice", key)
		}
		seen[key] = true
		if (len(c.CoveredBy) == 0) == (c.GapReason == "") {
			return r, fmt.Errorf("control %s needs either covered_by or a gap_reason, not both", key)
		}
		for _, p := range c.CoveredBy {
			if !known[p] {
				return r, fmt.Errorf("control %s names unknown policy %s", key, p)
			}
		}
	}
	return r, nil
}

// coverage counts the Tenant's Services a Policy has evaluated.
var coverage = map[string]string{
	"keel-authz@1":       `SELECT count(*) FROM services WHERE archived_at IS NULL`,
	"keel-access@1":      `SELECT count(*) FROM services s WHERE archived_at IS NULL AND EXISTS (SELECT 1 FROM access_roles r JOIN environments e ON e.id = r.environment_id WHERE e.project_id = s.project_id AND r.state = 'active')`,
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
	// The PDPA checks run per Tenant, so they reach every Service once they
	// have run.
	"keel-pdpa-residency@1": `SELECT count(*) FROM services WHERE archived_at IS NULL AND EXISTS (SELECT 1 FROM activities WHERE type = 'keel.pdpa.residency.checked')`,
	"keel-pdpa-retention@1": `SELECT count(*) FROM services WHERE archived_at IS NULL AND EXISTS (SELECT 1 FROM activities WHERE type IN ('keel.pdpa.retention.dry_run', 'keel.pdpa.retention.deleted', 'keel.pdpa.retention.held'))`,
	"keel-pdpa-breach@1":    `SELECT count(*) FROM services WHERE archived_at IS NULL`,
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

// FrameworkCoverage counts one framework's Controls. Mapped Controls have at
// least one Policy; covered ones have a Policy that reached a Service. Every
// Control that is not covered is a gap.
type FrameworkCoverage struct {
	Framework
	Controls int `json:"controls"`
	Mapped   int `json:"mapped"`
	Covered  int `json:"covered"`
	Gaps     int `json:"gaps"`
}

// Report is a Tenant's view of the registry.
type Report struct {
	Version    string              `json:"version"`
	Services   int                 `json:"services"`
	Frameworks []FrameworkCoverage `json:"frameworks"`
	Controls   []ControlView       `json:"controls"`
}

// Only narrows the report to one framework; false if the registry has no
// such framework.
func (r Report) Only(framework string) (Report, bool) {
	out := Report{Version: r.Version, Services: r.Services, Controls: []ControlView{}}
	for _, f := range r.Frameworks {
		if f.ID == framework {
			out.Frameworks = []FrameworkCoverage{f}
		}
	}
	if out.Frameworks == nil {
		return r, false
	}
	for _, c := range r.Controls {
		if c.Framework == framework {
			out.Controls = append(out.Controls, c)
		}
	}
	return out, true
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
	counts := map[string]*FrameworkCoverage{}
	for _, f := range s.Registry.Frameworks {
		rep.Frameworks = append(rep.Frameworks, FrameworkCoverage{Framework: f})
	}
	for i := range rep.Frameworks {
		counts[rep.Frameworks[i].ID] = &rep.Frameworks[i]
	}
	for _, c := range s.Registry.Controls {
		v := ControlView{Control: c, Coverage: []PolicyCoverage{}}
		any := false
		for _, name := range c.CoveredBy {
			v.Coverage = append(v.Coverage, PolicyCoverage{Policy: byName[name], Covered: covered[name]})
			if covered[name] > 0 {
				any = true
			}
		}
		v.Gap = !any
		rep.Controls = append(rep.Controls, v)
		f := counts[c.Framework]
		f.Controls++
		if len(c.CoveredBy) > 0 {
			f.Mapped++
		}
		if v.Gap {
			f.Gaps++
		} else {
			f.Covered++
		}
	}
	return rep, nil
}
