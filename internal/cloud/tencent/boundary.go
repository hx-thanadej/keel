package tencent

import (
	"context"
	"fmt"

	cam "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam/v20190116"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/boundary"
	"github.com/hx-thanadej/keel/internal/landingzone"
)

// BoundaryAPI is the slice of CAM used for Permission Boundaries.
type BoundaryAPI interface {
	ListPoliciesWithContext(context.Context, *cam.ListPoliciesRequest) (*cam.ListPoliciesResponse, error)
	CreatePolicyWithContext(context.Context, *cam.CreatePolicyRequest) (*cam.CreatePolicyResponse, error)
	UpdatePolicyWithContext(context.Context, *cam.UpdatePolicyRequest) (*cam.UpdatePolicyResponse, error)
	GetPolicyWithContext(context.Context, *cam.GetPolicyRequest) (*cam.GetPolicyResponse, error)
	DescribeRoleListWithContext(context.Context, *cam.DescribeRoleListRequest) (*cam.DescribeRoleListResponse, error)
	GetRolePermissionBoundaryWithContext(context.Context, *cam.GetRolePermissionBoundaryRequest) (*cam.GetRolePermissionBoundaryResponse, error)
	PutRolePermissionsBoundaryWithContext(context.Context, *cam.PutRolePermissionsBoundaryRequest) (*cam.PutRolePermissionsBoundaryResponse, error)
}

// Boundaries implements boundary.IAM in one member account.
type Boundaries struct {
	API BoundaryAPI
}

var _ boundary.IAM = Boundaries{}

// NewBoundaries builds a CAM client for one member account.
func NewBoundaries(creds common.Provider) (Boundaries, error) {
	api, err := NewCAM(creds)
	if err != nil {
		return Boundaries{}, err
	}
	c, ok := api.(*cam.Client)
	if !ok {
		return Boundaries{}, fmt.Errorf("unexpected CAM client")
	}
	return Boundaries{API: c}, nil
}

// EnsurePolicy implements boundary.IAM.
func (b Boundaries) EnsurePolicy(ctx context.Context, name, document, description string) (int64, error) {
	want, err := landingzone.Canonical(document)
	if err != nil {
		return 0, err
	}
	for page := uint64(1); page <= 50; page++ {
		req := cam.NewListPoliciesRequest()
		req.Rp, req.Page, req.Scope, req.Keyword = common.Uint64Ptr(200), common.Uint64Ptr(page), common.StringPtr("Local"), common.StringPtr(name)
		res, err := b.API.ListPoliciesWithContext(ctx, req)
		if err != nil {
			return 0, fmt.Errorf("ListPolicies: %w", err)
		}
		if res.Response == nil {
			break
		}
		for _, p := range res.Response.List {
			if p == nil || p.PolicyName == nil || *p.PolicyName != name || p.PolicyId == nil {
				continue
			}
			g := cam.NewGetPolicyRequest()
			g.PolicyId = p.PolicyId
			cur, err := b.API.GetPolicyWithContext(ctx, g)
			if err != nil {
				return 0, fmt.Errorf("GetPolicy: %w", err)
			}
			have := ""
			if cur.Response != nil && cur.Response.PolicyDocument != nil {
				have, _ = landingzone.Canonical(*cur.Response.PolicyDocument)
			}
			if have != want {
				u := cam.NewUpdatePolicyRequest()
				u.PolicyId, u.PolicyDocument, u.Description = p.PolicyId, common.StringPtr(want), &description
				if _, err := b.API.UpdatePolicyWithContext(ctx, u); err != nil {
					return 0, fmt.Errorf("UpdatePolicy: %w", err)
				}
			}
			return int64(*p.PolicyId), nil
		}
		if len(res.Response.List) < 200 {
			break
		}
	}
	c := cam.NewCreatePolicyRequest()
	c.PolicyName, c.PolicyDocument, c.Description = &name, common.StringPtr(want), &description
	res, err := b.API.CreatePolicyWithContext(ctx, c)
	if err != nil {
		return 0, fmt.Errorf("CreatePolicy: %w", err)
	}
	if res.Response == nil || res.Response.PolicyId == nil {
		return 0, fmt.Errorf("CreatePolicy: no policy id")
	}
	return int64(*res.Response.PolicyId), nil
}

// Roles implements boundary.IAM.
func (b Boundaries) Roles(ctx context.Context) ([]boundary.Role, error) {
	var out []boundary.Role
	for page := uint64(1); page <= 100; page++ {
		req := cam.NewDescribeRoleListRequest()
		req.Page, req.Rp = common.Uint64Ptr(page), common.Uint64Ptr(200)
		res, err := b.API.DescribeRoleListWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("DescribeRoleList: %w", err)
		}
		if res.Response == nil {
			break
		}
		for _, r := range res.Response.List {
			if r == nil || r.RoleId == nil || r.RoleName == nil {
				continue
			}
			out = append(out, boundary.Role{ID: *r.RoleId, Name: *r.RoleName, Type: deref(r.RoleType)})
		}
		if len(res.Response.List) < 200 {
			break
		}
	}
	return out, nil
}

// RoleBoundary implements boundary.IAM.
func (b Boundaries) RoleBoundary(ctx context.Context, roleID string) (int64, error) {
	req := cam.NewGetRolePermissionBoundaryRequest()
	req.RoleId = &roleID
	res, err := b.API.GetRolePermissionBoundaryWithContext(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("GetRolePermissionBoundary: %w", err)
	}
	if res.Response == nil || res.Response.PolicyId == nil {
		return 0, nil
	}
	return *res.Response.PolicyId, nil
}

// PutBoundary implements boundary.IAM.
func (b Boundaries) PutBoundary(ctx context.Context, roleName string, policyID int64) error {
	req := cam.NewPutRolePermissionsBoundaryRequest()
	req.RoleName, req.PolicyId = &roleName, &policyID
	if _, err := b.API.PutRolePermissionsBoundaryWithContext(ctx, req); err != nil {
		return fmt.Errorf("PutRolePermissionsBoundary: %w", err)
	}
	return nil
}
