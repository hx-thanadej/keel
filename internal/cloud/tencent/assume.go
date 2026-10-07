package tencent

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	sts "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sts/v20180813"
)

// MemberRole assumes a read-only role in a member account with Keel's own
// keyless credentials, so Keel reads each account (Cloud Monitor, CVM) with
// short-lived credentials scoped to that account (ADR-0006, ADR-0007).
type MemberRole struct {
	Base    common.Provider
	Account string // member UIN
	Role    string // role name in the member account, e.g. KeelReadOnly
	Region  string

	mu      sync.Mutex
	cached  common.CredentialIface
	expires time.Time
}

// RoleArn is the member role's ARN.
func (m *MemberRole) RoleArn() string {
	return fmt.Sprintf("qcs::cam::uin/%s:roleName/%s", m.Account, m.Role)
}

// GetCredential implements common.Provider, renewing 5 minutes before expiry.
func (m *MemberRole) GetCredential() (common.CredentialIface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cached != nil && time.Until(m.expires) > 5*time.Minute {
		return m.cached, nil
	}
	base, err := m.Base.GetCredential()
	if err != nil {
		return nil, err
	}
	c, err := sts.NewClient(base, m.Region, profile.NewClientProfile())
	if err != nil {
		return nil, err
	}
	req := sts.NewAssumeRoleRequest()
	arn, session, dur := m.RoleArn(), "keel", uint64(3600)
	req.RoleArn, req.RoleSessionName, req.DurationSeconds = &arn, &session, &dur
	res, err := c.AssumeRole(req)
	if err != nil {
		return nil, fmt.Errorf("AssumeRole %s: %w", arn, err)
	}
	if res.Response == nil || res.Response.Credentials == nil || res.Response.Credentials.TmpSecretId == nil {
		return nil, errors.New("AssumeRole: no credentials in response")
	}
	cr := res.Response.Credentials
	m.cached = common.NewTokenCredential(*cr.TmpSecretId, *cr.TmpSecretKey, *cr.Token)
	m.expires = time.Now().Add(time.Duration(dur) * time.Second)
	if res.Response.ExpiredTime != nil {
		m.expires = time.Unix(*res.Response.ExpiredTime, 0)
	}
	return m.cached, nil
}
