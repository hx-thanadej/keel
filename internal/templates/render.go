package templates

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Params are what the rendered files need.
type Params struct {
	Tenant, Project, Team, Service, Title, Org string
	Template, TemplateVersion                  string
	ReusableWorkflow                           string // owner/repo/.github/workflows/x.yml@<sha>
	MinReleaseAgeDays                          int
}

// Files returns the governed files Keel writes into every new repository,
// whatever the template carries.
func Files(p Params) map[string][]byte {
	if p.MinReleaseAgeDays == 0 {
		p.MinReleaseAgeDays = 3
	}
	catalog := fmt.Sprintf(`# Managed by Keel (template %s@%s). The Catalog reads this file.
apiVersion: backstage.io/v1alpha1
kind: Component
metadata:
  name: %s
  title: %s
  annotations:
    keel.dev/tenant: %s
    keel.dev/template: %s
spec:
  type: service
  lifecycle: experimental
  owner: group:%s
  system: %s
`, p.Template, short(p.TemplateVersion), p.Service, quote(p.Title), p.Tenant, p.Template, p.Team, p.Project)
	codeowners := fmt.Sprintf("# Managed by Keel: the owning Team reviews every change.\n* @%s/%s\n", p.Org, p.Team)
	renovate, _ := json.MarshalIndent(map[string]any{
		"$schema":              "https://docs.renovatebot.com/renovate-schema.json",
		"extends":              []string{"config:recommended", "helpers:pinGitHubActionDigests"},
		"minimumReleaseAge":    fmt.Sprintf("%d days", p.MinReleaseAgeDays),
		"internalChecksFilter": "strict",
		"labels":               []string{"dependencies"},
	}, "", "  ")
	adr := `# 1. Record architecture decisions

Date: (created by Keel)

## Status

Accepted

## Context

We need to record the architectural decisions made on this Service.

## Decision

We use Markdown Architectural Decision Records (MADR) in docs/decisions/.
Keel indexes them across repositories.

## Consequences

Each hard-to-reverse decision gets a numbered file; superseded, never edited.
`
	files := map[string][]byte{
		"catalog-info.yaml":  []byte(catalog),
		".github/CODEOWNERS": []byte(codeowners),
		"renovate.json":      append(renovate, '\n'),
		"docs/decisions/0001-record-architecture-decisions.md": []byte(adr),
	}
	if p.ReusableWorkflow != "" {
		files[".github/workflows/keel.yml"] = []byte(fmt.Sprintf(`# Managed by Keel: build, sign and attest through the pinned reusable workflow.
name: keel
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  keel:
    permissions:
      contents: read
      id-token: write
      packages: write
      attestations: write
    uses: %s
`, p.ReusableWorkflow))
	}
	return files
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return strings.TrimSpace(string(b))
}
