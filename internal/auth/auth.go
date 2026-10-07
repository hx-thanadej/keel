// Package auth carries the authenticated Principal through a request.
package auth

import (
	"context"
	"errors"
	"net/http"
)

// Principal kinds.
const (
	KindHuman    = "human"
	KindPipeline = "pipeline"
	KindWorkload = "workload"
)

// Roles (DESIGN.md §3).
const (
	RolePlatformAdmin  = "platform_admin"
	RoleSecurityLead   = "security_lead"
	RoleFinOpsLead     = "finops_lead"
	RoleTeamLead       = "team_lead"
	RoleEngineer       = "engineer"
	RoleTenantViewer   = "tenant_viewer"
	RoleTenantApprover = "tenant_approver"
)

// Binding grants a Role within one Tenant, optionally narrowed to Teams.
// TeamIDs empty means the whole Tenant.
type Binding struct {
	Role     string   `json:"role"`
	TenantID string   `json:"tenant_id"`
	TeamIDs  []string `json:"team_ids,omitempty"`
}

// Principal is an authenticated caller.
type Principal struct {
	Subject  string    `json:"subject"`   // e.g. "user:alice@harmonyx.co"
	Kind     string    `json:"kind"`      // human | pipeline | workload
	TenantID string    `json:"tenant_id"` // the Tenant the principal belongs to
	Home     bool      `json:"home"`      // belongs to the home (operating) Tenant
	Issuer   string    `json:"issuer,omitempty"`
	MFA      bool      `json:"mfa,omitempty"`
	Bindings []Binding `json:"bindings"`
}

type ctxKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the Principal, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// ErrUnauthenticated means the request carried no valid credentials.
var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator turns a request into a Principal.
type Authenticator interface {
	Authenticate(r *http.Request) (Principal, error)
}
