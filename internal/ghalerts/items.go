package ghalerts

import (
	"fmt"
	"strconv"

	"github.com/hx-thanadej/keel/internal/scans"
)

const (
	toolDependabot = "dependabot"
	toolSecrets    = "github-secret-scanning"
)

// item is one alert normalised to the Finding it becomes.
type item struct {
	tool        string
	kind        string
	fingerprint string
	severity    string
	rule        string // title prefix
	title       string
	vuln        string // vulnerability id for the VEX check, else ""
	detail      map[string]any
	// own: the Finding is this alert's alone, so each sync replaces its
	// detail (a code scanning alert's location moves with the code).
	own bool
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// merge folds a duplicate alert (same fingerprint) into it: one Finding,
// all places, worst severity.
func (it *item) merge(o item) {
	if severityRank[o.severity] < severityRank[it.severity] {
		it.severity = o.severity
	}
	if more, ok := o.detail["alert_numbers"].([]int); ok {
		it.detail["alert_numbers"] = append(it.detail["alert_numbers"].([]int), more...)
	}
	for _, k := range []string{"locations", "components"} {
		if more, ok := o.detail[k].([]string); ok {
			it.detail[k] = append(it.detail[k].([]string), more...)
		}
	}
}

// dedupe merges items sharing a fingerprint, keeping first-seen order.
func dedupe(in []item) []item {
	idx := map[string]int{}
	var out []item
	for _, it := range in {
		if i, ok := idx[it.fingerprint]; ok {
			out[i].merge(it)
			continue
		}
		idx[it.fingerprint] = len(out)
		out = append(out, it)
	}
	return out
}

// codeFingerprint is GitHub's identity for a code scanning alert: the
// repository's immutable id and the alert number.
func codeFingerprint(repoID int64, number int) string {
	return codePrefix(repoID) + strconv.Itoa(number)
}

func codePrefix(repoID int64) string { return fmt.Sprintf("scan:github:%d:", repoID) }

func codeItem(a CodeAlert, repoID int64) item {
	loc := a.Path
	if a.Line > 0 {
		loc += ":" + strconv.Itoa(a.Line)
	}
	kind := scans.Kind(a.Tool, a.RuleID)
	it := item{tool: scans.GitHubCodeScanningTool, kind: kind, severity: a.Severity, rule: a.RuleID, title: trim(a.Description, 200), own: true,
		fingerprint: codeFingerprint(repoID, a.Number),
		detail: map[string]any{"tool": a.Tool, "rule_id": a.RuleID, "message": trim(a.Message, 1000), "locations": []string{loc},
			"alert_url": a.URL, "alert_number": a.Number}}
	if it.title == "" {
		it.title = trim(a.Message, 200)
	}
	if kind == "vulnerability" {
		it.vuln = a.RuleID
	}
	return it
}

func dependabotItems(alerts []DependabotAlert, service string) []item {
	out := make([]item, 0, len(alerts))
	for _, a := range alerts {
		id := preferredID(a)
		if id == "" {
			continue // an alert without an advisory id cannot be matched to anything
		}
		out = append(out, item{tool: toolDependabot, kind: "vulnerability", severity: a.Severity, rule: id, title: trim(a.Summary, 200), vuln: id,
			fingerprint: "vuln:" + id + ":" + service,
			detail:      map[string]any{"ghsa": a.GHSA, "cve": a.CVE, "components": []string{a.Ecosystem + "/" + a.Package}, "locations": []string{a.ManifestPath}, "alert_numbers": []int{a.Number}}})
	}
	return dedupe(out)
}

// preferredID is the CVE when the advisory has one, so Dependabot and the
// scanners and OSV matcher that report the CVE land on one Finding (see
// sbom.preferredID).
func preferredID(a DependabotAlert) string {
	if a.CVE != "" {
		return a.CVE
	}
	return a.GHSA
}

// secretItems never carries the secret value: SecretAlert has no field for it.
func secretItems(alerts []SecretAlert, repoKey string) []item {
	out := make([]item, 0, len(alerts))
	for _, a := range alerts {
		name := a.DisplayName
		if name == "" {
			name = a.Type
		}
		out = append(out, item{tool: toolSecrets, kind: "secret", severity: "critical", rule: a.Type, title: fmt.Sprintf("%s (secret scanning alert #%d)", name, a.Number),
			fingerprint: fmt.Sprintf("secret:github:%s:%d", repoKey, a.Number),
			detail:      map[string]any{"rule_id": a.Type, "secret_type": a.Type, "alert_url": a.URL, "alert_numbers": []int{a.Number}}})
	}
	return out
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
