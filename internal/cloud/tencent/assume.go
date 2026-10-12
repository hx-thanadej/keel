package tencent

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
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
	// ExternalID is sent on AssumeRole when set; a client role's trust policy
	// requires it (sts:external_id) so only Keel's registration of that payer
	// can assume it.
	ExternalID string
	// Policy, when set, is the session policy sent on AssumeRole, limiting
	// the session to what it allows.
	Policy string
	// Endpoint overrides the STS host (scheme://host), for tests.
	Endpoint string

	mu      sync.Mutex
	cached  common.CredentialIface
	expires time.Time
}

var roleARN = regexp.MustCompile(`^qcs::cam::uin/(\d{1,20}):roleName/([\w+=,.@-]{1,128})$`)

// ReadOnlyRole is a client's read-only role (ADR-0018), assumed from Keel's
// base identity with Keel's ExternalId for that payer. The role must live in
// account, the client payer whose bills it reads.
func ReadOnlyRole(base common.Provider, arn, account, externalID, region string) (*MemberRole, error) {
	m := roleARN.FindStringSubmatch(arn)
	if m == nil {
		return nil, fmt.Errorf("read-only role %q is not qcs::cam::uin/<uin>:roleName/<name>", arn)
	}
	if m[1] != account {
		return nil, fmt.Errorf("read-only role %s is not in payer %s", arn, account)
	}
	if externalID == "" {
		return nil, fmt.Errorf("read-only role %s has no ExternalId", arn)
	}
	return &MemberRole{Base: base, Account: account, Role: m[2], Region: region, ExternalID: externalID}, nil
}

// ReadActions are the only actions a client-reads session may use, one per
// API call the client reads make: DescribeBudget, DescribeStrategies,
// DescribeTaskStrategyRisks, GetMonitorData and DescribeInstances.
var ReadActions = []string{"finance:DescribeBudget", "advisor:DescribeStrategies", "advisor:DescribeTaskStrategyRisks",
	"monitor:GetMonitorData", "cvm:DescribeInstances"}

// ReadsRole is a client's read-only role assumed for Budget, Smart Advisor
// and Cloud Monitor reads: the same checks and ExternalId as ReadOnlyRole,
// with a session policy that allows only ReadActions.
func ReadsRole(base common.Provider, arn, account, externalID, region string) (*MemberRole, error) {
	r, err := ReadOnlyRole(base, arn, account, externalID, region)
	if err != nil {
		return nil, err
	}
	r.Policy = `{"version":"2.0","statement":[{"effect":"allow","action":["` + strings.Join(ReadActions, `","`) + `"],"resource":["*"]}]}`
	return r, nil
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
	c, err := stsClient(base, m.Region, m.Endpoint)
	if err != nil {
		return nil, err
	}
	req := sts.NewAssumeRoleRequest()
	arn, session, dur := m.RoleArn(), "keel", uint64(3600)
	req.RoleArn, req.RoleSessionName, req.DurationSeconds = &arn, &session, &dur
	if m.ExternalID != "" {
		req.ExternalId = &m.ExternalID
	}
	if m.Policy != "" {
		policy := url.QueryEscape(m.Policy) // STS URL-decodes Policy
		req.Policy = &policy
	}
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

// stsClient signs with cred. endpoint overrides the STS host
// (scheme://host), for tests.
func stsClient(cred common.CredentialIface, region, endpoint string) (*sts.Client, error) {
	cpf := profile.NewClientProfile()
	if scheme, host, ok := strings.Cut(endpoint, "://"); ok {
		cpf.HttpProfile.Scheme, cpf.HttpProfile.Endpoint = scheme, host
	}
	return sts.NewClient(cred, region, cpf)
}

// CallerIdentity asks STS who cred is. Credentials can load and still be
// rejected (expired, revoked, deleted), and an AssumeRole made with them
// fails as if the target role had refused; this tells the two apart. It
// reads nothing and needs no permission. endpoint overrides the STS host
// (scheme://host), for tests.
func CallerIdentity(cred common.CredentialIface, region, endpoint string) error {
	c, err := stsClient(cred, region, endpoint)
	if err != nil {
		return err
	}
	_, err = c.GetCallerIdentity(sts.NewGetCallerIdentityRequest())
	return err
}
