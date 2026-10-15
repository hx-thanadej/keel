// Package tencent adapts Tencent Cloud APIs to Keel's provider interfaces.
package tencent

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"

	"github.com/hx-thanadej/keel/internal/discovery"
)

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
	client, err := guard(org.NewClient(cred, s.Region, profile.NewClientProfile()))
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

// STS yields Tencent credentials for reading COS through its S3-compatible
// API.
type STS struct{ Creds common.Provider }

// Get returns (secretId, secretKey, token).
func (s STS) Get() (string, string, string, error) {
	c, err := s.Creds.GetCredential()
	if err != nil {
		return "", "", "", err
	}
	id, key, token := c.GetCredential()
	return id, key, token, nil
}

// WriteSTS yields Tencent credentials for writing COS (the Activity Log
// archive). COS is not behind guard, so a read-only identity is refused
// here (ADR-0022).
type WriteSTS struct{ Creds common.Provider }

// Get returns (secretId, secretKey, token).
func (s WriteSTS) Get() (string, string, string, error) {
	c, err := s.Creds.GetCredential()
	if err != nil {
		return "", "", "", err
	}
	if IsReadOnly(c) {
		return "", "", "", fmt.Errorf("tencent COS write %w", ErrReadOnly)
	}
	id, key, token := c.GetCredential()
	return id, key, token, nil
}
