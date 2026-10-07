// Package githubgov keeps the GitHub organisation governed as code (#91):
// custom properties, default-branch rulesets (by property), secret scanning
// with push protection, and the OIDC subject template keyless CI relies on.
// A reconcile job reports drift as Findings and restores the desired state
// only when remediation is on. What the organisation's plan cannot enforce is
// reported, not hidden (Q1).
package githubgov

import (
	"encoding/json"
	"sort"

	"github.com/hx-thanadej/keel/internal/ciidentity"
)

// Property is an organisation custom property.
type Property struct {
	Name          string   `json:"property_name"`
	ValueType     string   `json:"value_type"` // string | single_select
	Required      bool     `json:"required"`
	DefaultValue  *string  `json:"default_value,omitempty"`
	Description   string   `json:"description,omitempty"`
	AllowedValues []string `json:"allowed_values,omitempty"`
}

// RulesetSpec is one default-branch ruleset; Tier "" applies to every repository.
type RulesetSpec struct {
	Name              string
	Tier              string
	Reviews           int
	LastPushApproval  bool
	RequiredChecks    []string
	RequireCodeOwners bool
}

// Policy is the desired state.
type Policy struct {
	Version      string
	Properties   []Property
	Rulesets     []RulesetSpec
	SubClaimKeys []string
}

// Required properties every repository must carry.
const (
	PropTenant  = "keel-tenant"
	PropProject = "keel-project"
	PropTier    = "keel-tier"
)

// Default is keel-github@1.
func Default(requiredChecks []string) Policy {
	return Policy{
		Version: "keel-github@1",
		Properties: []Property{
			{Name: PropTenant, ValueType: "string", Required: false, Description: "Keel Tenant slug that owns this repository"},
			{Name: PropProject, ValueType: "string", Required: false, Description: "Keel Project slug"},
			{Name: PropTier, ValueType: "single_select", Required: false, Description: "Highest Environment this repository deploys to", AllowedValues: []string{"prod", "nonprod", "sandbox"}},
		},
		Rulesets: []RulesetSpec{
			{Name: "keel-default-branch", Reviews: 1, RequireCodeOwners: true, RequiredChecks: requiredChecks},
			{Name: "keel-prod-tier", Tier: "prod", Reviews: 2, LastPushApproval: true, RequireCodeOwners: true, RequiredChecks: requiredChecks},
		},
		SubClaimKeys: ciidentity.SubjectClaimKeys,
	}
}

// Ruleset is GitHub's ruleset shape (the parts Keel manages).
type Ruleset struct {
	ID           int64          `json:"id,omitempty"`
	Name         string         `json:"name"`
	Target       string         `json:"target"`
	Enforcement  string         `json:"enforcement"`
	Conditions   map[string]any `json:"conditions"`
	Rules        []Rule         `json:"rules"`
	BypassActors []any          `json:"bypass_actors"`
}

// Rule is one ruleset rule.
type Rule struct {
	Type       string         `json:"type"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

// Build turns a spec into the ruleset to send. org=false builds a
// repository ruleset (no repository conditions).
func (s RulesetSpec) Build(org bool) Ruleset {
	cond := map[string]any{"ref_name": map[string]any{"include": []string{"~DEFAULT_BRANCH"}, "exclude": []string{}}}
	if org {
		if s.Tier == "" {
			cond["repository_name"] = map[string]any{"include": []string{"~ALL"}, "exclude": []string{}, "protected": false}
		} else {
			cond["repository_property"] = map[string]any{"include": []any{map[string]any{"name": PropTier, "property_values": []string{s.Tier}, "source": "custom"}}, "exclude": []any{}}
		}
	}
	rules := []Rule{
		{Type: "deletion"},
		{Type: "non_fast_forward"},
		{Type: "pull_request", Parameters: map[string]any{
			"required_approving_review_count": s.Reviews, "dismiss_stale_reviews_on_push": true,
			"require_code_owner_review": s.RequireCodeOwners, "require_last_push_approval": s.LastPushApproval,
			"required_review_thread_resolution": true,
		}},
	}
	if len(s.RequiredChecks) > 0 {
		var checks []map[string]any
		for _, c := range s.RequiredChecks {
			checks = append(checks, map[string]any{"context": c})
		}
		rules = append(rules, Rule{Type: "required_status_checks", Parameters: map[string]any{"strict_required_status_checks_policy": false, "required_status_checks": checks}})
	}
	return Ruleset{Name: s.Name, Target: "branch", Enforcement: "active", Conditions: cond, Rules: rules, BypassActors: []any{}}
}

// Same reports whether an existing ruleset enforces what want does. Keys
// GitHub adds on its side (ids, links, extra parameters) are ignored.
func Same(have, want Ruleset) bool {
	if have.Enforcement != want.Enforcement || have.Target != want.Target || len(have.BypassActors) != 0 {
		return false
	}
	byType := map[string]Rule{}
	for _, r := range have.Rules {
		byType[r.Type] = r
	}
	if len(byType) != len(want.Rules) {
		return false
	}
	for _, w := range want.Rules {
		h, ok := byType[w.Type]
		if !ok {
			return false
		}
		for k, v := range w.Parameters {
			if canon(h.Parameters[k]) != canon(v) {
				return false
			}
		}
	}
	for k, v := range want.Conditions {
		if !subset(have.Conditions[k], v) {
			return false
		}
	}
	return true
}

// subset: every key in want appears in have with the same value.
func subset(have, want any) bool {
	wm, ok := want.(map[string]any)
	if !ok {
		return canon(have) == canon(want)
	}
	hm, ok := toMap(have)
	if !ok {
		return false
	}
	for k, v := range wm {
		if !subset(hm[k], v) {
			return false
		}
	}
	return true
}

func toMap(v any) (map[string]any, bool) {
	var m map[string]any
	b, err := json.Marshal(v)
	if err != nil || json.Unmarshal(b, &m) != nil {
		return nil, false
	}
	return m, m != nil
}

// canon renders a value as canonical JSON (numbers as float, lists sorted
// when they are lists of scalars or of maps compared by their JSON).
func canon(v any) string {
	b, _ := json.Marshal(v)
	var x any
	_ = json.Unmarshal(b, &x)
	return string(mustJSON(sortLists(x)))
}

func sortLists(x any) any {
	switch t := x.(type) {
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = sortLists(t[i])
		}
		sort.Slice(out, func(i, j int) bool { return string(mustJSON(out[i])) < string(mustJSON(out[j])) })
		return out
	case map[string]any:
		for k, v := range t {
			t[k] = sortLists(v)
		}
	}
	return x
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
