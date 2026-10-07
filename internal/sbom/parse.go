// Package sbom stores each Release's SBOM, checks it against the CISA 2026
// minimum elements, and re-matches deployed components against OSV daily
// (#110), raising vulnerability Findings per Service.
package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Component is one package in an SBOM.
type Component struct {
	PURL, Name, Version, Ecosystem string
}

// Doc is a parsed SBOM.
type Doc struct {
	Format, SpecVersion, Tool string
	Components                []Component
	Gaps                      []string
}

type cdx struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Timestamp    string            `json:"timestamp"`
		Authors      []json.RawMessage `json:"authors"`
		Manufacturer json.RawMessage   `json:"manufacturer"`
		Supplier     json.RawMessage   `json:"supplier"`
		Lifecycles   []json.RawMessage `json:"lifecycles"`
		Tools        json.RawMessage   `json:"tools"`
	} `json:"metadata"`
	Components   []cdxComponent    `json:"components"`
	Dependencies []json.RawMessage `json:"dependencies"`
	Signature    json.RawMessage   `json:"signature"`
}

type cdxComponent struct {
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	PURL     string            `json:"purl"`
	CPE      string            `json:"cpe"`
	Supplier json.RawMessage   `json:"supplier"`
	Hashes   []json.RawMessage `json:"hashes"`
	Licenses []json.RawMessage `json:"licenses"`
}

// Parse reads a CycloneDX JSON SBOM (SPDX is accepted for components only).
func Parse(raw []byte) (Doc, error) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Doc{}, fmt.Errorf("not JSON: %w", err)
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return parseCycloneDX(raw)
	case probe.SPDXVersion != "":
		return parseSPDX(raw)
	}
	return Doc{}, fmt.Errorf("neither CycloneDX nor SPDX JSON")
}

func parseCycloneDX(raw []byte) (Doc, error) {
	var b cdx
	if err := json.Unmarshal(raw, &b); err != nil {
		return Doc{}, err
	}
	d := Doc{Format: "CycloneDX", SpecVersion: b.SpecVersion, Tool: toolName(b.Metadata.Tools)}
	var noProducer, noHash, noLicense, noID int
	for _, c := range b.Components {
		if c.PURL == "" && c.CPE == "" {
			noID++
		}
		if len(c.Supplier) == 0 {
			noProducer++
		}
		if len(c.Hashes) == 0 {
			noHash++
		}
		if len(c.Licenses) == 0 {
			noLicense++
		}
		if c.PURL != "" {
			d.Components = append(d.Components, Component{PURL: c.PURL, Name: c.Name, Version: c.Version, Ecosystem: ecosystem(c.PURL)})
		}
	}
	gap := func(cond bool, msg string) {
		if cond {
			d.Gaps = append(d.Gaps, msg)
		}
	}
	n := len(b.Components)
	// CISA 2026 Minimum Elements for an SBOM (research/01 §3).
	gap(len(b.Metadata.Authors) == 0 && len(b.Metadata.Manufacturer) == 0 && len(b.Metadata.Supplier) == 0, "SBOM Author")
	gap(len(b.Signature) == 0, "SBOM Author Signature (embedded; a signed SBOM attestation also satisfies it)")
	gap(b.SpecVersion == "", "SBOM Data Format Name and Version")
	gap(len(b.Metadata.Lifecycles) == 0, "SBOM Generation Context (metadata.lifecycles)")
	gap(b.Metadata.Timestamp == "", "SBOM Timestamp")
	gap(d.Tool == "", "SBOM Tool Name and Version")
	gap(b.Version == 0, "SBOM Version")
	gap(n > 0 && noProducer > 0, fmt.Sprintf("Component Producer missing on %d of %d components", noProducer, n))
	gap(n > 0 && noID > 0, fmt.Sprintf("Component Identifiers missing on %d of %d components", noID, n))
	gap(len(b.Dependencies) == 0, "Component Dependency Relationship")
	gap(n > 0 && noHash > 0, fmt.Sprintf("Component Hash missing on %d of %d components", noHash, n))
	gap(n > 0 && noLicense > 0, fmt.Sprintf("Component License missing on %d of %d components", noLicense, n))
	return d, nil
}

func toolName(raw json.RawMessage) string {
	// CycloneDX ≥1.5: {"components":[{"name","version"}]}; older: [{"name","version"}].
	var modern struct {
		Components []struct{ Name, Version string } `json:"components"`
	}
	if json.Unmarshal(raw, &modern) == nil && len(modern.Components) > 0 {
		return strings.TrimSpace(modern.Components[0].Name + " " + modern.Components[0].Version)
	}
	var legacy []struct{ Name, Version string }
	if json.Unmarshal(raw, &legacy) == nil && len(legacy) > 0 {
		return strings.TrimSpace(legacy[0].Name + " " + legacy[0].Version)
	}
	return ""
}

func parseSPDX(raw []byte) (Doc, error) {
	var s struct {
		SPDXVersion  string `json:"spdxVersion"`
		CreationInfo struct {
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Packages []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return Doc{}, err
	}
	d := Doc{Format: "SPDX", SpecVersion: strings.TrimPrefix(s.SPDXVersion, "SPDX-")}
	for _, c := range s.CreationInfo.Creators {
		if strings.HasPrefix(c, "Tool: ") {
			d.Tool = strings.TrimPrefix(c, "Tool: ")
		}
	}
	for _, p := range s.Packages {
		for _, r := range p.ExternalRefs {
			if r.Type == "purl" {
				d.Components = append(d.Components, Component{PURL: r.Locator, Name: p.Name, Version: p.VersionInfo, Ecosystem: ecosystem(r.Locator)})
			}
		}
	}
	d.Gaps = []string{"SPDX documents are checked for components only; submit CycloneDX for the minimum-elements check"}
	return d, nil
}

// ecosystem is the purl type, e.g. pkg:golang/... → golang.
func ecosystem(purl string) string {
	t, _, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	return t
}
