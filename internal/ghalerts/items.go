package ghalerts

import "fmt"

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
