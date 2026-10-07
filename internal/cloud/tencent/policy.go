package tencent

import (
	"context"
	"fmt"
	"strconv"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"

	"github.com/hx-thanadej/keel/internal/landingzone"
)

// PolicyAPI is the slice of Tencent Organization used for guardrail policies.
type PolicyAPI interface {
	ListPoliciesWithContext(context.Context, *org.ListPoliciesRequest) (*org.ListPoliciesResponse, error)
	CreatePolicyWithContext(context.Context, *org.CreatePolicyRequest) (*org.CreatePolicyResponse, error)
	UpdatePolicyWithContext(context.Context, *org.UpdatePolicyRequest) (*org.UpdatePolicyResponse, error)
	DescribePolicyWithContext(context.Context, *org.DescribePolicyRequest) (*org.DescribePolicyResponse, error)
	ListPoliciesForTargetWithContext(context.Context, *org.ListPoliciesForTargetRequest) (*org.ListPoliciesForTargetResponse, error)
	AttachPolicyWithContext(context.Context, *org.AttachPolicyRequest) (*org.AttachPolicyResponse, error)
}

// Guardrails implements landingzone.Org with organisation policies attached
// to member accounts.
type Guardrails struct {
	API PolicyAPI
}

var _ landingzone.Org = Guardrails{}

func (g Guardrails) find(ctx context.Context, name, typ string) (uint64, bool, error) {
	for page := uint64(1); page <= 200; page++ {
		req := org.NewListPoliciesRequest()
		req.Rp, req.Page, req.Scope, req.Keyword, req.PolicyType = common.Uint64Ptr(200), common.Uint64Ptr(page), common.StringPtr("Local"), common.StringPtr(name), common.StringPtr(typ)
		res, err := g.API.ListPoliciesWithContext(ctx, req)
		if err != nil {
			return 0, false, fmt.Errorf("ListPolicies: %w", err)
		}
		if res.Response == nil {
			return 0, false, nil
		}
		for _, p := range res.Response.List {
			if p != nil && p.PolicyName != nil && *p.PolicyName == name && p.PolicyId != nil {
				return *p.PolicyId, true, nil
			}
		}
		if len(res.Response.List) < 200 {
			return 0, false, nil
		}
	}
	return 0, false, nil
}

func (g Guardrails) content(ctx context.Context, id uint64, typ string) (string, error) {
	req := org.NewDescribePolicyRequest()
	req.PolicyId, req.PolicyType = &id, &typ
	res, err := g.API.DescribePolicyWithContext(ctx, req)
	if err != nil {
		return "", fmt.Errorf("DescribePolicy: %w", err)
	}
	if res.Response == nil || res.Response.PolicyDocument == nil {
		return "", nil
	}
	return landingzone.Canonical(*res.Response.PolicyDocument)
}

// EnsurePolicy implements landingzone.Org.
func (g Guardrails) EnsurePolicy(ctx context.Context, p landingzone.Policy) (string, error) {
	want, err := landingzone.Canonical(p.Content())
	if err != nil {
		return "", err
	}
	id, found, err := g.find(ctx, p.Name, p.Type)
	if err != nil {
		return "", err
	}
	if !found {
		req := org.NewCreatePolicyRequest()
		req.Name, req.Content, req.Type, req.Description = &p.Name, common.StringPtr(want), &p.Type, &p.Description
		res, err := g.API.CreatePolicyWithContext(ctx, req)
		if err != nil {
			return "", fmt.Errorf("CreatePolicy: %w", err)
		}
		if res.Response == nil || res.Response.PolicyId == nil {
			return "", fmt.Errorf("CreatePolicy: no policy id")
		}
		return strconv.FormatUint(*res.Response.PolicyId, 10), nil
	}
	have, err := g.content(ctx, id, p.Type)
	if err != nil {
		return "", err
	}
	if have != want {
		req := org.NewUpdatePolicyRequest()
		pid := int64(id)
		req.PolicyId, req.Name, req.Content, req.Type, req.Description = &pid, &p.Name, common.StringPtr(want), &p.Type, &p.Description
		if _, err := g.API.UpdatePolicyWithContext(ctx, req); err != nil {
			return "", fmt.Errorf("UpdatePolicy: %w", err)
		}
	}
	return strconv.FormatUint(id, 10), nil
}

// FindPolicy implements landingzone.Org.
func (g Guardrails) FindPolicy(ctx context.Context, name, typ string) (string, string, bool, error) {
	id, found, err := g.find(ctx, name, typ)
	if err != nil || !found {
		return "", "", false, err
	}
	c, err := g.content(ctx, id, typ)
	return strconv.FormatUint(id, 10), c, true, err
}

// Attached implements landingzone.Org: policies attached directly to the member.
func (g Guardrails) Attached(ctx context.Context, account, typ string) (map[string]bool, error) {
	uin, err := strconv.ParseUint(account, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("account %q: %w", account, err)
	}
	out := map[string]bool{}
	for page := uint64(1); page <= 200; page++ {
		req := org.NewListPoliciesForTargetRequest()
		req.TargetId, req.Rp, req.Page, req.PolicyType = &uin, common.Uint64Ptr(200), common.Uint64Ptr(page), &typ
		res, err := g.API.ListPoliciesForTargetWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListPoliciesForTarget: %w", err)
		}
		if res.Response == nil {
			return out, nil
		}
		for _, p := range res.Response.List {
			if p != nil && p.StrategyId != nil {
				out[strconv.FormatUint(*p.StrategyId, 10)] = true
			}
		}
		if len(res.Response.List) < 200 {
			return out, nil
		}
	}
	return out, nil
}

// Attach implements landingzone.Org.
func (g Guardrails) Attach(ctx context.Context, account, policyID, typ string) error {
	uin, err := strconv.ParseUint(account, 10, 64)
	if err != nil {
		return fmt.Errorf("account %q: %w", account, err)
	}
	id, err := strconv.ParseUint(policyID, 10, 64)
	if err != nil {
		return fmt.Errorf("policy %q: %w", policyID, err)
	}
	req := org.NewAttachPolicyRequest()
	req.TargetId, req.TargetType, req.PolicyId, req.Type = &uin, common.StringPtr("MEMBER"), &id, &typ
	if _, err := g.API.AttachPolicyWithContext(ctx, req); err != nil {
		return fmt.Errorf("AttachPolicy: %w", err)
	}
	return nil
}
