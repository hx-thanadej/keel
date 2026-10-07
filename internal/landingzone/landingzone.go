// Package landingzone applies and watches the baseline every vended Cloud
// Account gets (#89): organisation guardrail policies attached to the
// account. The baseline is versioned data; applying it is idempotent, and a
// daily check raises a Finding for every attachment or policy that drifted.
package landingzone

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Policy is one organisation policy.
type Policy struct {
	Name        string         `json:"name"`
	Type        string         `json:"type"` // SERVICE_CONTROL_POLICY
	Description string         `json:"description"`
	Document    map[string]any `json:"document"`
}

// Baseline is the desired state of a Cloud Account.
type Baseline struct {
	Version  string   `json:"version"`
	Policies []Policy `json:"policies"`
}

// Content is a policy's canonical JSON (sorted keys, no whitespace).
func (p Policy) Content() string {
	b, _ := json.Marshal(p.Document)
	return string(b)
}

// Canonical re-encodes JSON so documents compare regardless of formatting.
func Canonical(doc string) (string, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader([]byte(doc)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	return string(b), err
}

// Hash identifies the baseline's content.
func (b Baseline) Hash() string {
	ps := append([]Policy(nil), b.Policies...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
	raw, _ := json.Marshal(ps)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// Options shape the Tencent baseline.
type Options struct {
	// AutomationRole is exempt from the identity guardrail: Keel creates
	// every CAM principal (ADR-0006).
	AutomationRole string
	// RoleConditionKey is the SCP condition key naming the caller's role.
	// Tencent does not document one for SCPs (research/02 T2); the default
	// must be verified on a sandbox account before enforcing.
	RoleConditionKey string
}

// Tencent returns keel-baseline@1 for Tencent member accounts.
func Tencent(o Options) Baseline {
	if o.RoleConditionKey == "" {
		o.RoleConditionKey = "qcs:role_name"
	}
	stmt := func(actions []string) map[string]any {
		return map[string]any{"effect": "deny", "action": actions, "resource": []string{"*"}}
	}
	identity := stmt([]string{
		"cam:CreateRole", "cam:AddUser", "cam:CreateAccessKey", "cam:AttachRolePolicy", "cam:AttachUserPolicy",
		"cam:PutRolePermissionsBoundary", "cam:DeleteRolePermissionsBoundary",
		"cam:PutUserPermissionsBoundary", "cam:DeleteUserPermissionsBoundary",
		"cam:CreateOIDCConfig", "cam:UpdateOIDCConfig", "cam:DeleteOIDCConfig",
		"cam:CreateSAMLProvider", "cam:UpdateSAMLProvider", "cam:DeleteSAMLProvider",
	})
	if o.AutomationRole != "" {
		identity["condition"] = map[string]any{"string_not_equal": map[string]any{o.RoleConditionKey: []string{o.AutomationRole}}}
	}
	return Baseline{Version: "keel-baseline@1", Policies: []Policy{
		{Name: "keel_stay_in_organisation", Type: "SERVICE_CONTROL_POLICY", Description: "Keel: members cannot leave the organisation",
			Document: map[string]any{"version": "2.0", "statement": []any{stmt([]string{"organization:QuitOrganization"})}}},
		{Name: "keel_protect_audit", Type: "SERVICE_CONTROL_POLICY", Description: "Keel: CloudAudit tracking cannot be stopped, changed or deleted",
			Document: map[string]any{"version": "2.0", "statement": []any{stmt([]string{
				"cloudaudit:StopLogging", "cloudaudit:DeleteAudit", "cloudaudit:UpdateAudit",
				"cloudaudit:DeleteAuditTrack", "cloudaudit:ModifyAuditTrack"})}}},
		{Name: "keel_identities_via_keel", Type: "SERVICE_CONTROL_POLICY", Description: "Keel: only Keel creates CAM principals, keys and identity providers (ADR-0006, ADR-0007)",
			Document: map[string]any{"version": "2.0", "statement": []any{identity}}},
	}}
}

// Org is the provider's organisation-policy API.
type Org interface {
	// EnsurePolicy creates the policy, or updates its content, by name.
	EnsurePolicy(ctx context.Context, p Policy) (id string, err error)
	// FindPolicy returns the policy's id and canonical content, if it exists.
	FindPolicy(ctx context.Context, name, typ string) (id, content string, found bool, err error)
	// Attached lists policy ids attached directly to the account.
	Attached(ctx context.Context, account, typ string) (map[string]bool, error)
	Attach(ctx context.Context, account, policyID, typ string) error
}

// Apply makes the account match the baseline.
func Apply(ctx context.Context, org Org, b Baseline, account string) error {
	for _, p := range b.Policies {
		id, err := org.EnsurePolicy(ctx, p)
		if err != nil {
			return fmt.Errorf("policy %s: %w", p.Name, err)
		}
		attached, err := org.Attached(ctx, account, p.Type)
		if err != nil {
			return fmt.Errorf("attached policies: %w", err)
		}
		if !attached[id] {
			if err := org.Attach(ctx, account, id, p.Type); err != nil {
				return fmt.Errorf("attach %s: %w", p.Name, err)
			}
		}
	}
	return nil
}

// Drift is one difference between the account and the baseline.
type Drift struct {
	Policy  string `json:"policy"`
	Problem string `json:"problem"` // missing_policy | content_changed | detached
}

// Check compares the account with the baseline without changing anything.
func Check(ctx context.Context, org Org, b Baseline, account string) ([]Drift, error) {
	var out []Drift
	attachedByType := map[string]map[string]bool{}
	for _, p := range b.Policies {
		id, content, found, err := org.FindPolicy(ctx, p.Name, p.Type)
		if err != nil {
			return nil, err
		}
		if !found {
			out = append(out, Drift{Policy: p.Name, Problem: "missing_policy"})
			continue
		}
		if want, _ := Canonical(p.Content()); content != want {
			out = append(out, Drift{Policy: p.Name, Problem: "content_changed"})
		}
		if attachedByType[p.Type] == nil {
			if attachedByType[p.Type], err = org.Attached(ctx, account, p.Type); err != nil {
				return nil, err
			}
		}
		if !attachedByType[p.Type][id] {
			out = append(out, Drift{Policy: p.Name, Problem: "detached"})
		}
	}
	return out, nil
}
