package tencent

import (
	"context"
	"fmt"
	"strings"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"

	"github.com/hx-thanadej/keel/internal/access"
)

// CICAPI is the slice of Cloud Identity Center (Organization) Keel uses.
type CICAPI interface {
	ListRoleConfigurationsWithContext(context.Context, *org.ListRoleConfigurationsRequest) (*org.ListRoleConfigurationsResponse, error)
	CreateRoleConfigurationWithContext(context.Context, *org.CreateRoleConfigurationRequest) (*org.CreateRoleConfigurationResponse, error)
	AddPermissionPolicyToRoleConfigurationWithContext(context.Context, *org.AddPermissionPolicyToRoleConfigurationRequest) (*org.AddPermissionPolicyToRoleConfigurationResponse, error)
	ListUsersWithContext(context.Context, *org.ListUsersRequest) (*org.ListUsersResponse, error)
	CreateRoleAssignmentWithContext(context.Context, *org.CreateRoleAssignmentRequest) (*org.CreateRoleAssignmentResponse, error)
	DeleteRoleAssignmentWithContext(context.Context, *org.DeleteRoleAssignmentRequest) (*org.DeleteRoleAssignmentResponse, error)
	ListRoleAssignmentsWithContext(context.Context, *org.ListRoleAssignmentsRequest) (*org.ListRoleAssignmentsResponse, error)
}

// IdentityCenter implements access.Directory in one CIC zone.
type IdentityCenter struct {
	API    CICAPI
	ZoneID string
}

var _ access.Directory = IdentityCenter{}

// EnsureRoleConfiguration implements access.Directory: a role configuration
// named name with one inline (Custom) policy. An existing configuration is
// reused; its policy is set when created.
func (c IdentityCenter) EnsureRoleConfiguration(ctx context.Context, name, description, policy string, hours int) (string, error) {
	var next *string
	for i := 0; i < 50; i++ {
		req := org.NewListRoleConfigurationsRequest()
		req.ZoneId, req.MaxResults, req.NextToken = &c.ZoneID, common.Int64Ptr(100), next
		res, err := c.API.ListRoleConfigurationsWithContext(ctx, req)
		if err != nil {
			return "", fmt.Errorf("ListRoleConfigurations: %w", err)
		}
		if res.Response == nil {
			break
		}
		for _, rc := range res.Response.RoleConfigurations {
			if rc != nil && rc.RoleConfigurationName != nil && *rc.RoleConfigurationName == name && rc.RoleConfigurationId != nil {
				return *rc.RoleConfigurationId, nil
			}
		}
		if res.Response.IsTruncated == nil || !*res.Response.IsTruncated {
			break
		}
		next = res.Response.NextToken
	}
	cr := org.NewCreateRoleConfigurationRequest()
	cr.ZoneId, cr.RoleConfigurationName, cr.Description, cr.SessionDuration = &c.ZoneID, &name, &description, common.Int64Ptr(int64(hours)*3600)
	res, err := c.API.CreateRoleConfigurationWithContext(ctx, cr)
	if err != nil {
		return "", fmt.Errorf("CreateRoleConfiguration: %w", err)
	}
	if res.Response == nil || res.Response.RoleConfigurationInfo == nil || res.Response.RoleConfigurationInfo.RoleConfigurationId == nil {
		return "", fmt.Errorf("CreateRoleConfiguration: no id")
	}
	id := *res.Response.RoleConfigurationInfo.RoleConfigurationId
	ap := org.NewAddPermissionPolicyToRoleConfigurationRequest()
	ap.ZoneId, ap.RoleConfigurationId, ap.RolePolicyType = &c.ZoneID, &id, common.StringPtr("Custom")
	ap.RolePolicyNames, ap.CustomPolicyDocument = []*string{common.StringPtr(strings.ReplaceAll(name, "-", "_"))}, &policy
	if _, err := c.API.AddPermissionPolicyToRoleConfigurationWithContext(ctx, ap); err != nil {
		return "", fmt.Errorf("AddPermissionPolicyToRoleConfiguration: %w", err)
	}
	return id, nil
}

// UserID implements access.Directory: the CIC user whose email matches.
func (c IdentityCenter) UserID(ctx context.Context, email string) (string, bool, error) {
	req := org.NewListUsersRequest()
	req.ZoneId, req.Filter, req.MaxResults = &c.ZoneID, &email, common.Int64Ptr(100)
	res, err := c.API.ListUsersWithContext(ctx, req)
	if err != nil {
		return "", false, fmt.Errorf("ListUsers: %w", err)
	}
	if res.Response != nil {
		for _, u := range res.Response.Users {
			if u != nil && u.UserId != nil && u.Email != nil && strings.EqualFold(*u.Email, email) && deref(u.UserStatus) != "Disabled" {
				return *u.UserId, true, nil
			}
		}
	}
	return "", false, nil
}

func target(account int64) (*int64, *string) { return &account, common.StringPtr("MemberUin") }

// Assign implements access.Directory.
func (c IdentityCenter) Assign(ctx context.Context, cfg string, account int64, user string) error {
	uin, typ := target(account)
	req := org.NewCreateRoleAssignmentRequest()
	req.ZoneId = &c.ZoneID
	req.RoleAssignmentInfo = []*org.RoleAssignmentInfo{{RoleConfigurationId: &cfg, TargetUin: uin, TargetType: typ, PrincipalId: &user, PrincipalType: common.StringPtr("User")}}
	if _, err := c.API.CreateRoleAssignmentWithContext(ctx, req); err != nil {
		return fmt.Errorf("CreateRoleAssignment: %w", err)
	}
	return nil
}

// Unassign implements access.Directory; the provisioned CAM role is removed
// from the account when no one else holds it.
func (c IdentityCenter) Unassign(ctx context.Context, cfg string, account int64, user string) error {
	uin, typ := target(account)
	req := org.NewDeleteRoleAssignmentRequest()
	req.ZoneId, req.RoleConfigurationId, req.TargetUin, req.TargetType = &c.ZoneID, &cfg, uin, typ
	req.PrincipalId, req.PrincipalType, req.DeprovisionStrategy = &user, common.StringPtr("User"), common.StringPtr("DeprovisionForLastRoleAssignmentOnAccount")
	if _, err := c.API.DeleteRoleAssignmentWithContext(ctx, req); err != nil {
		return fmt.Errorf("DeleteRoleAssignment: %w", err)
	}
	return nil
}

// Assignments implements access.Directory.
func (c IdentityCenter) Assignments(ctx context.Context, account int64) ([]access.Assignment, error) {
	var out []access.Assignment
	var next *string
	for i := 0; i < 100; i++ {
		uin, typ := target(account)
		req := org.NewListRoleAssignmentsRequest()
		req.ZoneId, req.TargetUin, req.TargetType, req.MaxResults, req.NextToken = &c.ZoneID, uin, typ, common.Int64Ptr(100), next
		res, err := c.API.ListRoleAssignmentsWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListRoleAssignments: %w", err)
		}
		if res.Response == nil {
			break
		}
		for _, a := range res.Response.RoleAssignments {
			if a == nil {
				continue
			}
			out = append(out, access.Assignment{RoleConfiguration: deref(a.RoleConfigurationId), RoleName: deref(a.RoleConfigurationName),
				PrincipalID: deref(a.PrincipalId), PrincipalName: deref(a.PrincipalName), PrincipalType: deref(a.PrincipalType)})
		}
		if res.Response.IsTruncated == nil || !*res.Response.IsTruncated {
			break
		}
		next = res.Response.NextToken
	}
	return out, nil
}
