package tencent_test

import (
	"context"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

type fakeCIC struct {
	configs  []*org.RoleConfiguration
	policy   *org.AddPermissionPolicyToRoleConfigurationRequest
	assigned []*org.RoleAssignmentInfo
	deleted  *org.DeleteRoleAssignmentRequest
}

func (f *fakeCIC) ListRoleConfigurationsWithContext(context.Context, *org.ListRoleConfigurationsRequest) (*org.ListRoleConfigurationsResponse, error) {
	r := org.NewListRoleConfigurationsResponse()
	r.Response = &org.ListRoleConfigurationsResponseParams{RoleConfigurations: f.configs, IsTruncated: common.BoolPtr(false)}
	return r, nil
}
func (f *fakeCIC) CreateRoleConfigurationWithContext(_ context.Context, q *org.CreateRoleConfigurationRequest) (*org.CreateRoleConfigurationResponse, error) {
	rc := &org.RoleConfiguration{RoleConfigurationId: common.StringPtr("rc-1"), RoleConfigurationName: q.RoleConfigurationName}
	f.configs = append(f.configs, rc)
	r := org.NewCreateRoleConfigurationResponse()
	r.Response = &org.CreateRoleConfigurationResponseParams{RoleConfigurationInfo: rc}
	return r, nil
}
func (f *fakeCIC) AddPermissionPolicyToRoleConfigurationWithContext(_ context.Context, q *org.AddPermissionPolicyToRoleConfigurationRequest) (*org.AddPermissionPolicyToRoleConfigurationResponse, error) {
	f.policy = q
	return org.NewAddPermissionPolicyToRoleConfigurationResponse(), nil
}
func (f *fakeCIC) ListUsersWithContext(context.Context, *org.ListUsersRequest) (*org.ListUsersResponse, error) {
	r := org.NewListUsersResponse()
	r.Response = &org.ListUsersResponseParams{Users: []*org.UserInfo{
		{UserId: common.StringPtr("u-other"), Email: common.StringPtr("someone@harmonyx.co")},
		{UserId: common.StringPtr("u-eng"), Email: common.StringPtr("Eng@HarmonyX.co")}}}
	return r, nil
}
func (f *fakeCIC) CreateRoleAssignmentWithContext(_ context.Context, q *org.CreateRoleAssignmentRequest) (*org.CreateRoleAssignmentResponse, error) {
	f.assigned = append(f.assigned, q.RoleAssignmentInfo...)
	return org.NewCreateRoleAssignmentResponse(), nil
}
func (f *fakeCIC) DeleteRoleAssignmentWithContext(_ context.Context, q *org.DeleteRoleAssignmentRequest) (*org.DeleteRoleAssignmentResponse, error) {
	f.deleted = q
	return org.NewDeleteRoleAssignmentResponse(), nil
}
func (f *fakeCIC) ListRoleAssignmentsWithContext(context.Context, *org.ListRoleAssignmentsRequest) (*org.ListRoleAssignmentsResponse, error) {
	r := org.NewListRoleAssignmentsResponse()
	var out []*org.RoleAssignments
	for _, a := range f.assigned {
		out = append(out, &org.RoleAssignments{RoleConfigurationId: a.RoleConfigurationId, PrincipalId: a.PrincipalId, PrincipalType: a.PrincipalType})
	}
	r.Response = &org.ListRoleAssignmentsResponseParams{RoleAssignments: out}
	return r, nil
}

func TestIdentityCenter(t *testing.T) {
	ctx := context.Background()
	f := &fakeCIC{}
	c := tencent.IdentityCenter{API: f, ZoneID: "z-1"}
	id, err := c.EnsureRoleConfiguration(ctx, "keel-operator", "ops", `{"version":"2.0"}`, 2)
	if err != nil || id != "rc-1" || *f.policy.RolePolicyType != "Custom" || *f.policy.RolePolicyNames[0] != "keel_operator" {
		t.Fatalf("%s %v %+v", id, err, f.policy)
	}
	f.policy = nil
	if id, _ := c.EnsureRoleConfiguration(ctx, "keel-operator", "ops", "{}", 2); id != "rc-1" || f.policy != nil {
		t.Fatal("recreated an existing role configuration")
	}
	if u, ok, _ := c.UserID(ctx, "eng@harmonyx.co"); !ok || u != "u-eng" {
		t.Fatal(u, ok)
	}
	if err := c.Assign(ctx, "rc-1", 100002, "u-eng"); err != nil || *f.assigned[0].TargetType != "MemberUin" || *f.assigned[0].TargetUin != 100002 {
		t.Fatalf("%v %+v", err, f.assigned)
	}
	if as, _ := c.Assignments(ctx, 100002); len(as) != 1 || as[0].PrincipalID != "u-eng" {
		t.Fatalf("%+v", as)
	}
	if err := c.Unassign(ctx, "rc-1", 100002, "u-eng"); err != nil || *f.deleted.DeprovisionStrategy != "DeprovisionForLastRoleAssignmentOnAccount" {
		t.Fatal(err)
	}
}
