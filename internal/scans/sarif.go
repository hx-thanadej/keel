// Package scans turns scanner output into Findings (#109): SARIF 2.1 from
// any tool in CI, deduplicated by rule and stable location fingerprint, and
// across tools for the same vulnerability id.
package scans

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Result is one normalised scanner result.
type Result struct {
	Fingerprint string         `json:"fingerprint"`
	Kind        string         `json:"kind"` // vulnerability | secret | iac | sast | code_scan
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Location    string         `json:"location"`
	Detail      map[string]any `json:"detail"`
}

type sarifLog struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string      `json:"name"`
				Rules []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				Physical struct {
					Artifact struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Properties          map[string]any    `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

type sarifRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties map[string]any `json:"properties"`
}

var vulnID = regexp.MustCompile(`^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$`)

var toolKinds = map[string]string{
	"gitleaks": "secret", "trufflehog": "secret", "betterleaks": "secret",
	"checkov": "iac", "tfsec": "iac", "kics": "iac", "trivy-config": "iac",
	"semgrep": "sast", "codeql": "sast", "gosec": "sast", "bandit": "sast",
	"zizmor": "workflow",
}

// Kind is the Finding kind of a result tool reports under rule: a
// vulnerability for a CVE or GHSA id, else what the tool scans for.
func Kind(tool, rule string) string {
	if vulnID.MatchString(rule) {
		return "vulnerability"
	}
	if k := toolKinds[tool]; k != "" {
		return k
	}
	return "code_scan"
}

// CodeScanning reports whether a Finding kind is a code scanning kind, the
// only kinds a Service's code scanning source governs. Vulnerabilities,
// secrets, IaC and workflow results are not: other sources own them.
func CodeScanning(kind string) bool { return kind == "sast" || kind == "code_scan" }

// ParseSARIF normalises every result of every run. service scopes the
// fingerprints, so the same rule in two Services is two Findings.
func ParseSARIF(raw []byte, service string) (tools []string, out []Result, err error) {
	var log sarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		return nil, nil, fmt.Errorf("not SARIF JSON: %w", err)
	}
	if !strings.HasPrefix(log.Version, "2.1") {
		return nil, nil, fmt.Errorf("SARIF version %q, want 2.1.x", log.Version)
	}
	seen := map[string]int{}
	for _, run := range log.Runs {
		tool := strings.ToLower(run.Tool.Driver.Name)
		tools = append(tools, tool)
		rules := map[string]sarifRule{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}
		for _, res := range run.Results {
			rule := rules[res.RuleID]
			loc := ""
			if len(res.Locations) > 0 {
				pl := res.Locations[0].Physical
				loc = pl.Artifact.URI
				if pl.Region.StartLine > 0 {
					loc += ":" + strconv.Itoa(pl.Region.StartLine)
				}
			}
			r := Result{RuleID: res.RuleID, Location: loc, Severity: severity(res.Properties, rule, res.Level)}
			r.Title = rule.ShortDescription.Text
			if r.Title == "" {
				r.Title = res.Message.Text
			}
			if len(r.Title) > 200 {
				r.Title = r.Title[:200]
			}
			r.Kind = Kind(tool, res.RuleID)
			if r.Kind == "vulnerability" {
				r.Fingerprint = "vuln:" + res.RuleID + ":" + service
			} else {
				r.Fingerprint = "scan:" + tool + ":" + res.RuleID + ":" + service + ":" + stable(res.PartialFingerprints, loc, res.Message.Text)
			}
			r.Detail = map[string]any{"tools": []string{tool}, "rule_id": res.RuleID, "message": trim(res.Message.Text, 1000), "locations": []string{loc}}
			if i, dup := seen[r.Fingerprint]; dup {
				// Same vulnerability in several places: one Finding, all locations.
				locs := out[i].Detail["locations"].([]string)
				out[i].Detail["locations"] = append(locs, loc)
				if rank(r.Severity) < rank(out[i].Severity) {
					out[i].Severity = r.Severity
				}
				continue
			}
			seen[r.Fingerprint] = len(out)
			out = append(out, r)
		}
	}
	return tools, out, nil
}

// stable prefers the scanner's own location-independent fingerprint, so a
// result survives lines moving; else it hashes location and message.
func stable(partial map[string]string, loc, msg string) string {
	for _, k := range []string{"primaryLocationLineHash", "primaryLocationStartColumnFingerprint"} {
		if v := partial[k]; v != "" {
			return short(k + "=" + v)
		}
	}
	return short(loc + "|" + msg)
}

func short(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// severity: GitHub's security-severity (CVSS-like 0–10) when present, else the SARIF level.
func severity(resProps map[string]any, rule sarifRule, level string) string {
	for _, props := range []map[string]any{resProps, rule.Properties} {
		if v, ok := props["security-severity"]; ok {
			var f float64
			switch t := v.(type) {
			case string:
				f, _ = strconv.ParseFloat(t, 64)
			case float64:
				f = t
			}
			switch {
			case f >= 9:
				return "critical"
			case f >= 7:
				return "high"
			case f >= 4:
				return "medium"
			default:
				return "low"
			}
		}
	}
	if level == "" {
		level = rule.DefaultConfiguration.Level
	}
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	default:
		return "low"
	}
}

func rank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	}
	return 3
}
