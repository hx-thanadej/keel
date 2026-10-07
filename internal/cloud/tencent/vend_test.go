package tencent_test

import (
	"context"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

type fakeOrgAPI struct {
	nodes   []*org.OrgNode
	members []*org.OrgMember
	created *org.CreateOrganizationMemberRequest
	added   *org.AddOrganizationNodeRequest
}

func (f *fakeOrgAPI) DescribeOrganizationNodesWithContext(_ context.Context, r *org.DescribeOrganizationNodesRequest) (*org.DescribeOrganizationNodesResponse, error) {
	res := org.NewDescribeOrganizationNodesResponse()
	res.Response = &org.DescribeOrganizationNodesResponseParams{Items: f.nodes}
	return res, nil
}
func (f *fakeOrgAPI) AddOrganizationNodeWithContext(_ context.Context, r *org.AddOrganizationNodeRequest) (*org.AddOrganizationNodeResponse, error) {
	f.added = r
	res := org.NewAddOrganizationNodeResponse()
	res.Response = &org.AddOrganizationNodeResponseParams{NodeId: common.Int64Ptr(77)}
	return res, nil
}
func (f *fakeOrgAPI) DescribeOrganizationMembersWithContext(_ context.Context, r *org.DescribeOrganizationMembersRequest) (*org.DescribeOrganizationMembersResponse, error) {
	res := org.NewDescribeOrganizationMembersResponse()
	var items []*org.OrgMember
	for _, m := range f.members {
		if r.SearchKey == nil || *m.Name == *r.SearchKey || len(*r.SearchKey) < len(*m.Name) && (*m.Name)[:len(*r.SearchKey)] == *r.SearchKey {
			items = append(items, m)
		}
	}
	res.Response = &org.DescribeOrganizationMembersResponseParams{Items: items}
	return res, nil
}
func (f *fakeOrgAPI) CreateOrganizationMemberWithContext(_ context.Context, r *org.CreateOrganizationMemberRequest) (*org.CreateOrganizationMemberResponse, error) {
	f.created = r
	f.members = append(f.members, &org.OrgMember{Name: r.Name, MemberUin: common.Int64Ptr(100099)})
	res := org.NewCreateOrganizationMemberResponse()
	res.Response = &org.CreateOrganizationMemberResponseParams{Uin: common.Int64Ptr(100099)}
	return res, nil
}

func TestAccountFactory(t *testing.T) {
	ctx := context.Background()
	f := &fakeOrgAPI{
		nodes: []*org.OrgNode{{NodeId: common.Int64Ptr(1), Name: common.StringPtr("root"), ParentNodeId: common.Int64Ptr(0)},
			{NodeId: common.Int64Ptr(5), Name: common.StringPtr("tat"), ParentNodeId: common.Int64Ptr(1)}},
		// Prefix search also returns the longer name; only an exact match counts.
		members: []*org.OrgMember{{Name: common.StringPtr("tat-crm-dev-old"), MemberUin: common.Int64Ptr(100001)}},
	}
	a := tencent.AccountFactory{API: f}
	if id, err := a.EnsureUnit(ctx, "tat"); err != nil || id != "5" || f.added != nil {
		t.Fatalf("existing unit %s %v", id, err)
	}
	if id, err := a.EnsureUnit(ctx, "scb"); err != nil || id != "77" || *f.added.ParentNodeId != 1 {
		t.Fatalf("new unit %s %v", id, err)
	}
	if _, found, err := a.FindAccount(ctx, "tat-crm-dev"); err != nil || found {
		t.Fatalf("found by prefix: %v %v", found, err)
	}
	id, err := a.CreateAccount(ctx, "tat-crm-dev", "5", map[string]string{"keel-tenant": "tat", "keel-env": "dev"})
	if err != nil || id != "100099" {
		t.Fatal(id, err)
	}
	c := f.created
	if *c.PolicyType != "Financial" || *c.NodeId != 5 || len(c.PermissionIds) != 5 || *c.PermissionIds[0] != 1 || *c.PermissionIds[1] != 2 || len(c.Tags) != 2 || *c.Tags[0].TagKey != "keel-env" {
		t.Fatalf("create request %+v", c)
	}
	if ok, err := a.AccountReady(ctx, "100099"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, _ := a.AccountReady(ctx, "999"); ok {
		t.Fatal("unknown account ready")
	}
}
