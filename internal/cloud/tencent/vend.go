package tencent

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"

	"github.com/hx-thanadej/keel/internal/vending"
)

var _ vending.Org = AccountFactory{}

// OrgAPI is the slice of Tencent Organization the account factory uses.
type OrgAPI interface {
	DescribeOrganizationNodesWithContext(context.Context, *org.DescribeOrganizationNodesRequest) (*org.DescribeOrganizationNodesResponse, error)
	AddOrganizationNodeWithContext(context.Context, *org.AddOrganizationNodeRequest) (*org.AddOrganizationNodeResponse, error)
	DescribeOrganizationMembersWithContext(context.Context, *org.DescribeOrganizationMembersRequest) (*org.DescribeOrganizationMembersResponse, error)
	CreateOrganizationMemberWithContext(context.Context, *org.CreateOrganizationMemberRequest) (*org.CreateOrganizationMemberResponse, error)
}

// NewOrgAPI returns an Organization API whose every call uses fresh
// credentials (role credentials expire); they must belong to the
// organisation admin account.
func NewOrgAPI(region string, creds common.Provider) OrgAPI {
	return lazyOrg{region: region, creds: creds}
}

type lazyOrg struct {
	region string
	creds  common.Provider
}

func (l lazyOrg) client() (*org.Client, error) {
	cred, err := l.creds.GetCredential()
	if err != nil {
		return nil, fmt.Errorf("tencent credentials: %w", err)
	}
	return org.NewClient(cred, l.region, profile.NewClientProfile())
}

func (l lazyOrg) DescribeOrganizationNodesWithContext(ctx context.Context, r *org.DescribeOrganizationNodesRequest) (*org.DescribeOrganizationNodesResponse, error) {
	c, err := l.client()
	if err != nil {
		return nil, err
	}
	return c.DescribeOrganizationNodesWithContext(ctx, r)
}

func (l lazyOrg) AddOrganizationNodeWithContext(ctx context.Context, r *org.AddOrganizationNodeRequest) (*org.AddOrganizationNodeResponse, error) {
	c, err := l.client()
	if err != nil {
		return nil, err
	}
	return c.AddOrganizationNodeWithContext(ctx, r)
}

func (l lazyOrg) DescribeOrganizationMembersWithContext(ctx context.Context, r *org.DescribeOrganizationMembersRequest) (*org.DescribeOrganizationMembersResponse, error) {
	c, err := l.client()
	if err != nil {
		return nil, err
	}
	return c.DescribeOrganizationMembersWithContext(ctx, r)
}

func (l lazyOrg) CreateOrganizationMemberWithContext(ctx context.Context, r *org.CreateOrganizationMemberRequest) (*org.CreateOrganizationMemberResponse, error) {
	c, err := l.client()
	if err != nil {
		return nil, err
	}
	return c.CreateOrganizationMemberWithContext(ctx, r)
}

// AccountFactory implements vending.Org for Tencent Cloud: Tenants are
// departments (organisation nodes) under the root, Environments are member
// accounts with the Financial relationship.
type AccountFactory struct {
	API OrgAPI
}

// memberPermissions: 1 view bill, 2 view balance (both mandatory),
// 4 consolidated billing, 8 cost analysis, 9 budget management.
var memberPermissions = []uint64{1, 2, 4, 8, 9}

// Provider implements vending.Org.
func (AccountFactory) Provider() string { return "tencent" }

func (f AccountFactory) nodes(ctx context.Context) ([]*org.OrgNode, error) {
	var out []*org.OrgNode
	const page = 50
	for offset := int64(0); ; offset += page {
		req := org.NewDescribeOrganizationNodesRequest()
		req.Limit, req.Offset = common.Int64Ptr(page), common.Int64Ptr(offset)
		res, err := f.API.DescribeOrganizationNodesWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("DescribeOrganizationNodes: %w", err)
		}
		if res.Response == nil {
			return out, nil
		}
		out = append(out, res.Response.Items...)
		if len(res.Response.Items) < page {
			return out, nil
		}
	}
}

// EnsureUnit implements vending.Org.
func (f AccountFactory) EnsureUnit(ctx context.Context, name string) (string, error) {
	nodes, err := f.nodes(ctx)
	if err != nil {
		return "", err
	}
	var root *org.OrgNode
	for _, n := range nodes {
		if n == nil || n.NodeId == nil {
			continue
		}
		if n.ParentNodeId == nil || *n.ParentNodeId == 0 {
			root = n
		}
	}
	if root == nil {
		return "", fmt.Errorf("organisation has no root node")
	}
	// Deterministic: if two match (created concurrently), use the lowest id.
	sort.Slice(nodes, func(i, j int) bool { return ptrInt(nodes[i].NodeId) < ptrInt(nodes[j].NodeId) })
	for _, n := range nodes {
		if n != nil && n.Name != nil && *n.Name == name && n.ParentNodeId != nil && *n.ParentNodeId == *root.NodeId {
			return strconv.FormatInt(*n.NodeId, 10), nil
		}
	}
	req := org.NewAddOrganizationNodeRequest()
	parent := uint64(*root.NodeId)
	req.ParentNodeId, req.Name, req.Remark = &parent, &name, common.StringPtr("Keel Tenant unit")
	res, err := f.API.AddOrganizationNodeWithContext(ctx, req)
	if err != nil {
		return "", fmt.Errorf("AddOrganizationNode: %w", err)
	}
	if res.Response == nil || res.Response.NodeId == nil {
		return "", fmt.Errorf("AddOrganizationNode: no node id")
	}
	return strconv.FormatInt(*res.Response.NodeId, 10), nil
}

func ptrInt(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// FindAccount implements vending.Org.
func (f AccountFactory) FindAccount(ctx context.Context, name string) (string, bool, error) {
	const page = 50
	for offset := uint64(0); ; offset += page {
		req := org.NewDescribeOrganizationMembersRequest()
		req.Offset, req.Limit, req.SearchKey = common.Uint64Ptr(offset), common.Uint64Ptr(page), common.StringPtr(name)
		res, err := f.API.DescribeOrganizationMembersWithContext(ctx, req)
		if err != nil {
			return "", false, fmt.Errorf("DescribeOrganizationMembers: %w", err)
		}
		if res.Response == nil {
			return "", false, nil
		}
		for _, m := range res.Response.Items {
			if m != nil && m.Name != nil && *m.Name == name && m.MemberUin != nil {
				return strconv.FormatInt(*m.MemberUin, 10), true, nil
			}
		}
		if len(res.Response.Items) < page {
			return "", false, nil
		}
	}
}

// CreateAccount implements vending.Org.
func (f AccountFactory) CreateAccount(ctx context.Context, name, unit string, tags map[string]string) (string, error) {
	node, err := strconv.ParseInt(unit, 10, 64)
	if err != nil {
		return "", fmt.Errorf("unit id %q: %w", unit, err)
	}
	req := org.NewCreateOrganizationMemberRequest()
	req.Name, req.AccountName, req.PolicyType, req.NodeId = &name, &name, common.StringPtr("Financial"), &node
	req.Remark = common.StringPtr("Created by Keel account vending")
	for _, p := range memberPermissions {
		req.PermissionIds = append(req.PermissionIds, common.Uint64Ptr(p))
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		req.Tags = append(req.Tags, &org.Tag{TagKey: common.StringPtr(k), TagValue: common.StringPtr(tags[k])})
	}
	res, err := f.API.CreateOrganizationMemberWithContext(ctx, req)
	if err != nil {
		return "", fmt.Errorf("CreateOrganizationMember: %w", err)
	}
	if res.Response == nil || res.Response.Uin == nil {
		return "", fmt.Errorf("CreateOrganizationMember: no uin")
	}
	return strconv.FormatInt(*res.Response.Uin, 10), nil
}

// AccountReady implements vending.Org: the member is listed in the organisation.
func (f AccountFactory) AccountReady(ctx context.Context, id string) (bool, error) {
	const page = 50
	for offset := uint64(0); ; offset += page {
		req := org.NewDescribeOrganizationMembersRequest()
		req.Offset, req.Limit = common.Uint64Ptr(offset), common.Uint64Ptr(page)
		res, err := f.API.DescribeOrganizationMembersWithContext(ctx, req)
		if err != nil {
			return false, fmt.Errorf("DescribeOrganizationMembers: %w", err)
		}
		if res.Response == nil {
			return false, nil
		}
		for _, m := range res.Response.Items {
			if m != nil && m.MemberUin != nil && strconv.FormatInt(*m.MemberUin, 10) == id {
				return true, nil
			}
		}
		if len(res.Response.Items) < page {
			return false, nil
		}
	}
}
