package tencent

import (
	"context"
	"fmt"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	tcr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/tcr/v20190924"

	"github.com/hx-thanadej/keel/internal/registry"
)

// TCRAPI is the slice of Tencent Container Registry (Enterprise) Keel uses.
type TCRAPI interface {
	DescribeNamespacesWithContext(context.Context, *tcr.DescribeNamespacesRequest) (*tcr.DescribeNamespacesResponse, error)
	CreateNamespaceWithContext(context.Context, *tcr.CreateNamespaceRequest) (*tcr.CreateNamespaceResponse, error)
	DescribeImmutableTagRulesWithContext(context.Context, *tcr.DescribeImmutableTagRulesRequest) (*tcr.DescribeImmutableTagRulesResponse, error)
	CreateImmutableTagRulesWithContext(context.Context, *tcr.CreateImmutableTagRulesRequest) (*tcr.CreateImmutableTagRulesResponse, error)
	DescribeTagRetentionRulesWithContext(context.Context, *tcr.DescribeTagRetentionRulesRequest) (*tcr.DescribeTagRetentionRulesResponse, error)
	CreateTagRetentionRuleWithContext(context.Context, *tcr.CreateTagRetentionRuleRequest) (*tcr.CreateTagRetentionRuleResponse, error)
	CreateInstanceTokenWithContext(context.Context, *tcr.CreateInstanceTokenRequest) (*tcr.CreateInstanceTokenResponse, error)
}

// TempToken implements registry.Broker: a one-hour TCR login (never longterm).
func (r Registry) TempToken(ctx context.Context) (string, string, time.Time, error) {
	req := tcr.NewCreateInstanceTokenRequest()
	req.RegistryId, req.TokenType = &r.RegistryID, common.StringPtr("temp")
	res, err := r.API.CreateInstanceTokenWithContext(ctx, req)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("CreateInstanceToken: %w", err)
	}
	if res.Response == nil || res.Response.Username == nil || res.Response.Token == nil {
		return "", "", time.Time{}, fmt.Errorf("CreateInstanceToken: empty response")
	}
	exp := time.Now().Add(time.Hour)
	if res.Response.ExpTime != nil {
		exp = time.UnixMilli(*res.Response.ExpTime)
	}
	return *res.Response.Username, *res.Response.Token, exp, nil
}

// NewTCR builds a TCR client.
func NewTCR(region string, creds common.Provider) (TCRAPI, error) {
	cred, err := creds.GetCredential()
	if err != nil {
		return nil, fmt.Errorf("tencent credentials: %w", err)
	}
	return tcr.NewClient(cred, region, profile.NewClientProfile())
}

// Registry implements registry.Registry on one TCR Enterprise instance.
type Registry struct {
	API        TCRAPI
	RegistryID string
}

var (
	_ registry.Registry = Registry{}
	_ registry.Broker   = Registry{}
)

// EnsureNamespace implements registry.Registry.
func (r Registry) EnsureNamespace(ctx context.Context, name string) (int64, bool, error) {
	find := func() (int64, bool, error) {
		req := tcr.NewDescribeNamespacesRequest()
		req.RegistryId, req.NamespaceName, req.Limit = &r.RegistryID, &name, common.Int64Ptr(100)
		res, err := r.API.DescribeNamespacesWithContext(ctx, req)
		if err != nil {
			return 0, false, fmt.Errorf("DescribeNamespaces: %w", err)
		}
		if res.Response != nil {
			for _, n := range res.Response.NamespaceList {
				if n != nil && n.Name != nil && *n.Name == name && n.NamespaceId != nil {
					return *n.NamespaceId, true, nil
				}
			}
		}
		return 0, false, nil
	}
	if id, ok, err := find(); err != nil || ok {
		return id, false, err
	}
	req := tcr.NewCreateNamespaceRequest()
	req.RegistryId, req.NamespaceName, req.IsPublic, req.IsAutoScan = &r.RegistryID, &name, common.BoolPtr(false), common.BoolPtr(true)
	if _, err := r.API.CreateNamespaceWithContext(ctx, req); err != nil {
		return 0, false, fmt.Errorf("CreateNamespace: %w", err)
	}
	id, ok, err := find()
	if err == nil && !ok {
		err = fmt.Errorf("namespace %s not visible after creation", name)
	}
	return id, true, err
}

// EnsureImmutableTags implements registry.Registry.
func (r Registry) EnsureImmutableTags(ctx context.Context, name string) (bool, error) {
	for page := int64(1); page <= 50; page++ {
		req := tcr.NewDescribeImmutableTagRulesRequest()
		req.RegistryId, req.Page, req.PageSize = &r.RegistryID, common.Int64Ptr(page), common.Int64Ptr(100)
		res, err := r.API.DescribeImmutableTagRulesWithContext(ctx, req)
		if err != nil {
			return false, fmt.Errorf("DescribeImmutableTagRules: %w", err)
		}
		if res.Response == nil {
			break
		}
		for _, rule := range res.Response.Rules {
			if rule != nil && rule.NsName != nil && *rule.NsName == name && (rule.Disabled == nil || !*rule.Disabled) &&
				deref(rule.RepositoryPattern) == "**" && deref(rule.TagPattern) == "**" {
				return false, nil
			}
		}
		if len(res.Response.Rules) < 100 {
			break
		}
	}
	req := tcr.NewCreateImmutableTagRulesRequest()
	req.RegistryId, req.NamespaceName = &r.RegistryID, &name
	req.Rule = &tcr.ImmutableTagRule{RepositoryPattern: common.StringPtr("**"), TagPattern: common.StringPtr("**"),
		RepositoryDecoration: common.StringPtr("repoMatches"), TagDecoration: common.StringPtr("matches"), Disabled: common.BoolPtr(false)}
	if _, err := r.API.CreateImmutableTagRulesWithContext(ctx, req); err != nil {
		return false, fmt.Errorf("CreateImmutableTagRules: %w", err)
	}
	return true, nil
}

// EnsureRetention implements registry.Registry: keep the newest keep images
// per repository, evaluated daily.
func (r Registry) EnsureRetention(ctx context.Context, name string, id int64, keep int) (bool, error) {
	req := tcr.NewDescribeTagRetentionRulesRequest()
	req.RegistryId, req.NamespaceName, req.Limit = &r.RegistryID, &name, common.Int64Ptr(100)
	res, err := r.API.DescribeTagRetentionRulesWithContext(ctx, req)
	if err != nil {
		return false, fmt.Errorf("DescribeTagRetentionRules: %w", err)
	}
	if res.Response != nil {
		for _, p := range res.Response.RetentionPolicyList {
			if p != nil && p.NamespaceName != nil && *p.NamespaceName == name {
				return false, nil
			}
		}
	}
	c := tcr.NewCreateTagRetentionRuleRequest()
	c.RegistryId, c.NamespaceId, c.CronSetting, c.Disabled = &r.RegistryID, &id, common.StringPtr("daily"), common.BoolPtr(false)
	c.RetentionRule = &tcr.RetentionRule{Key: common.StringPtr("latestPushedK"), Value: common.Int64Ptr(int64(keep))}
	if _, err := r.API.CreateTagRetentionRuleWithContext(ctx, c); err != nil {
		return false, fmt.Errorf("CreateTagRetentionRule: %w", err)
	}
	return true, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
