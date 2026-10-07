// Package boundary gives every Environment's account a Permission Boundary
// (#131, ADR-0006): the most any role there can ever do, whatever is granted
// inside it. Keel stamps it on every role it creates and reports roles
// without it. Production's boundary is stricter.
package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Version names the boundary content.
const Version = "keel-boundary@1"

// PolicyName is the boundary's CAM policy name in each account.
const PolicyName = "keel_permission_boundary"

// Services a Project may use at all. Anything else is outside the boundary.
var Services = []string{"cvm", "cbs", "clb", "vpc", "tke", "tcr", "cos", "cdb", "postgres", "redis", "ckafka", "cls", "monitor", "ssm", "kms", "scf", "apigateway", "tag", "sts", "dnspod", "ssl", "waf", "antiddos"}

// Document renders the boundary for an Environment.
func Document(prod bool) string {
	allow := make([]string, 0, len(Services))
	for _, s := range Services {
		allow = append(allow, s+":*")
	}
	statements := []any{
		map[string]any{"effect": "allow", "action": allow, "resource": []string{"*"}},
		// Never: identity, organisation and audit administration (ADR-0006).
		map[string]any{"effect": "deny", "action": []string{"cam:*", "organization:*", "cloudaudit:*", "sts:AssumeRoleWithSAML"}, "resource": []string{"*"}},
	}
	if prod {
		// Production: destructive and data-exfiltrating actions need break-glass.
		statements = append(statements, map[string]any{"effect": "deny", "action": []string{
			"cvm:TerminateInstances", "cbs:TerminateDisks", "cos:DeleteBucket", "cos:PutBucketACL", "cos:PutBucketPolicy",
			"tke:DeleteCluster", "cdb:IsolateDBInstance", "cdb:OfflineIsolatedInstances", "postgres:IsolateDBInstances", "redis:DestroyPrepaidInstance",
			"kms:ScheduleKeyDeletion", "kms:DisableKey", "ssm:DeleteSecret",
		}, "resource": []string{"*"}})
	}
	b, _ := json.Marshal(map[string]any{"version": "2.0", "statement": statements})
	return string(b)
}

// Role is a CAM role in an account.
type Role struct {
	ID, Name, Type string
}

// IAM is the account's identity API.
type IAM interface {
	// EnsurePolicy creates or updates a custom policy by name.
	EnsurePolicy(ctx context.Context, name, document, description string) (int64, error)
	Roles(ctx context.Context) ([]Role, error)
	// RoleBoundary returns the boundary policy id of a role (0 if none).
	RoleBoundary(ctx context.Context, roleID string) (int64, error)
	PutBoundary(ctx context.Context, roleName string, policyID int64) error
}

// Exempt roles are not governed by the boundary: the organisation's own
// access role (Keel and break-glass operate through it) and service-linked
// roles, which providers manage.
func Exempt(r Role) bool {
	return r.Name == "OrganizationAccessControlRole" || strings.EqualFold(r.Type, "service_linked") || strings.HasPrefix(r.Name, "SLR_") || strings.HasPrefix(r.Name, "TCR_QCSLinkedRole")
}

// Result is what an Apply did.
type Result struct {
	PolicyID int64    `json:"policy_id"`
	Stamped  []string `json:"stamped"`
	Missing  []string `json:"missing"` // roles without the boundary, left as found
}

// Apply ensures the boundary policy and checks every role. With stamp, roles
// missing the boundary get it (used on new accounts, where every role is
// Keel's); otherwise they are reported.
func Apply(ctx context.Context, iam IAM, prod, stamp bool) (Result, error) {
	var res Result
	id, err := iam.EnsurePolicy(ctx, PolicyName, Document(prod), "Keel Permission Boundary ("+Version+")")
	if err != nil {
		return res, fmt.Errorf("boundary policy: %w", err)
	}
	res.PolicyID = id
	roles, err := iam.Roles(ctx)
	if err != nil {
		return res, fmt.Errorf("roles: %w", err)
	}
	for _, r := range roles {
		if Exempt(r) {
			continue
		}
		have, err := iam.RoleBoundary(ctx, r.ID)
		if err != nil {
			return res, fmt.Errorf("boundary of %s: %w", r.Name, err)
		}
		if have == id {
			continue
		}
		if !stamp {
			res.Missing = append(res.Missing, r.Name)
			continue
		}
		if err := iam.PutBoundary(ctx, r.Name, id); err != nil {
			return res, fmt.Errorf("stamp %s: %w", r.Name, err)
		}
		res.Stamped = append(res.Stamped, r.Name)
	}
	return res, nil
}
