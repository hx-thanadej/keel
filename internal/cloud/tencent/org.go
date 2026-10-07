// Package tencent adapts Tencent Cloud APIs to Keel's provider interfaces.
package tencent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"

	"github.com/hx-thanadej/keel/internal/discovery"
)

// Credentials prefers keyless identity (ADR-0007): TKE pod identity (OIDC),
// then the CVM instance role. Environment/profile keys are accepted only when
// KEEL_ENV=dev.
func Credentials() common.Provider {
	var chain []common.Provider
	if p, err := common.DefaultTkeOIDCRoleArnProvider(); err == nil && os.Getenv("TKE_WEB_IDENTITY_TOKEN_FILE") != "" {
		chain = append(chain, p)
	}
	chain = append(chain, common.DefaultCvmRoleProvider())
	if os.Getenv("KEEL_ENV") == "dev" {
		chain = append(chain, common.DefaultEnvProvider(), common.DefaultProfileProvider())
	}
	return common.NewProviderChain(chain)
}

// OrgSource lists member accounts of the Tencent Cloud organisation the
// credentials belong to (must be the organisation admin account).
type OrgSource struct {
	Region string
	Creds  common.Provider
}

// Provider implements discovery.Source.
func (OrgSource) Provider() string { return "tencent" }

// ListAccounts implements discovery.Source.
func (s OrgSource) ListAccounts(ctx context.Context) ([]discovery.Account, error) {
	cred, err := s.Creds.GetCredential()
	if err != nil {
		return nil, fmt.Errorf("tencent credentials: %w", err)
	}
	client, err := org.NewClient(cred, s.Region, profile.NewClientProfile())
	if err != nil {
		return nil, err
	}
	var out []discovery.Account
	const page = 50
	for offset := uint64(0); ; offset += page {
		req := org.NewDescribeOrganizationMembersRequest()
		req.Offset, req.Limit = common.Uint64Ptr(offset), common.Uint64Ptr(page)
		res, err := client.DescribeOrganizationMembersWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("DescribeOrganizationMembers: %w", err)
		}
		if res.Response == nil {
			return nil, errors.New("DescribeOrganizationMembers: empty response")
		}
		for _, m := range res.Response.Items {
			out = append(out, MemberAccount(m))
		}
		if len(res.Response.Items) < page {
			return out, nil
		}
	}
}

// MemberAccount maps an organisation member to a discovered account.
func MemberAccount(m *org.OrgMember) discovery.Account {
	a := discovery.Account{Provider: "tencent", Tags: map[string]string{}}
	if m.MemberUin != nil {
		a.ExternalID = strconv.FormatInt(*m.MemberUin, 10)
	}
	if m.Name != nil {
		a.Name = *m.Name
	}
	if m.NodeName != nil {
		a.Parent = *m.NodeName
	}
	for _, t := range m.Tags {
		if t != nil && t.TagKey != nil && t.TagValue != nil {
			a.Tags[*t.TagKey] = *t.TagValue
		}
	}
	return a
}
