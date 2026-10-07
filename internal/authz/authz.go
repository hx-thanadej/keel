// Package authz is Keel's policy decision point. Every API handler asks it
// "may this principal do this action on this resource?"; no handler checks
// roles itself (ADR-0009).
package authz

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/hx-thanadej/keel/internal/auth"
)

//go:embed policy.rego
var policy string

// Resource is what an action targets.
type Resource struct {
	Type      string `json:"type"`
	ID        string `json:"id,omitempty"`
	TenantID  string `json:"tenant_id"`
	ProjectID string `json:"project_id,omitempty"`
	TeamID    string `json:"team_id,omitempty"`
}

// Request is one authorisation question.
type Request struct {
	Principal auth.Principal `json:"principal"`
	Action    string         `json:"action"`
	Resource  Resource       `json:"resource"`
}

// Decision is the answer, with a reason and policy version for the Activity Log.
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	Policy string `json:"policy"`
}

// String formats the decision for an Activity's status detail.
func (d Decision) String() string {
	verdict := "deny"
	if d.Allow {
		verdict = "allow"
	}
	return fmt.Sprintf("%s: %s (%s)", d.Policy, verdict, d.Reason)
}

// Authorizer evaluates the embedded policy.
type Authorizer struct {
	query rego.PreparedEvalQuery
}

// New compiles the policy.
func New() (*Authorizer, error) {
	q, err := rego.New(
		rego.Query("data.keel.authz.decision"),
		rego.Module("policy.rego", policy),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("compile authz policy: %w", err)
	}
	return &Authorizer{query: q}, nil
}

// Decide evaluates req. An evaluation error is returned as an error and must
// be treated as deny by callers.
func (a *Authorizer) Decide(ctx context.Context, req Request) (Decision, error) {
	if req.Principal.Bindings == nil {
		req.Principal.Bindings = []auth.Binding{}
	}
	rs, err := a.query.Eval(ctx, rego.EvalInput(req))
	if err != nil {
		return Decision{}, fmt.Errorf("evaluate authz: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return Decision{}, fmt.Errorf("authz: unexpected result %v", rs)
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{}, fmt.Errorf("authz: decision is %T", rs[0].Expressions[0].Value)
	}
	d := Decision{}
	d.Allow, _ = m["allow"].(bool)
	d.Reason, _ = m["reason"].(string)
	d.Policy, _ = m["policy"].(string)
	return d, nil
}
