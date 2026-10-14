package tencent

import (
	"context"
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

	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store"
)

// KeelRole is one of Keel's own roles in an account, assumed from Keel's
// keyless base identity so Keel reaches each account with short-lived
// credentials scoped to it (ADR-0006, ADR-0007). It is assumed only inside
// account.Enter, which refuses a client-owned account (ADR-0018), and its
// cached session is handed out only after account.Check, so no replica
// uses it once the account is client-owned. It never sends an ExternalId:
// a client's role is a ClientRole.
type KeelRole struct {
	base     common.Provider
	account  catalog.KeelAccount
	role     string // role name in the account, e.g. KeelReadOnly
	region   string
	endpoint string
	session
}

// NewKeelRole is role in Tencent account, which no Tenant may hold as
// client-owned; the error wraps catalog.ErrClientOwned when one does.
// stsEndpoint overrides the STS host (scheme://host), for tests.
func NewKeelRole(ctx context.Context, st *store.Store, base common.Provider, account, role, region, stsEndpoint string) (*KeelRole, error) {
	a, err := catalog.ReachKeelAccount(ctx, st, "tencent", account)
	if err != nil {
		return nil, err
	}
	return &KeelRole{base: base, account: a, role: role, region: region, endpoint: stsEndpoint}, nil
}

// RoleArn is the role's ARN.
func (k *KeelRole) RoleArn() string {
	return fmt.Sprintf("qcs::cam::uin/%s:roleName/%s", k.account.ID(), k.role)
}

// GetCredential implements common.Provider. A Tencent SDK client keeps the
// credential it was built with, so build clients per job, not per process.
func (k *KeelRole) GetCredential() (common.CredentialIface, error) {
	if err := k.account.Check(context.Background()); err != nil {
		return nil, err
	}
	return k.get(func() (cred common.CredentialIface, expires time.Time, err error) {
		err = k.account.Enter(context.Background(), func() error {
			cred, expires, err = assumeRole(k.base, k.region, k.endpoint, k.RoleArn(), nil, "")
			return err
		})
		return cred, expires, err
	})
}

var roleARN = regexp.MustCompile(`^qcs::cam::uin/(\d{1,20}):roleName/([\w+=,.@-]{1,128})$`)

// ClientRole is a client's read-only role in its payer (ADR-0018), assumed
// from Keel's base identity with Keel's ExternalId for that payer.
type ClientRole struct {
	base     common.Provider
	grant    catalog.ClientReadRole
	region   string
	policy   string
	endpoint string
	session
}

// ReadOnlyRole is grant, a client's read-only role, which must live in the
// payer whose bills it reads. stsEndpoint overrides the STS host
// (scheme://host), for tests.
func ReadOnlyRole(base common.Provider, grant catalog.ClientReadRole, region, stsEndpoint string) (*ClientRole, error) {
	m := roleARN.FindStringSubmatch(grant.ARN())
	if m == nil {
		return nil, fmt.Errorf("read-only role %q is not qcs::cam::uin/<uin>:roleName/<name>", grant.ARN())
	}
	if m[1] != grant.Payer() {
		return nil, fmt.Errorf("read-only role %s is not in payer %s", grant.ARN(), grant.Payer())
	}
	if grant.ExternalID() == "" {
		return nil, fmt.Errorf("read-only role %s has no ExternalId", grant.ARN())
	}
	return &ClientRole{base: base, grant: grant, region: region, endpoint: stsEndpoint}, nil
}

// ReadActions are the only actions a client-reads session may use, one per
// API call the client reads make: DescribeBudget, DescribeStrategies,
// DescribeTaskStrategyRisks, GetMonitorData and DescribeInstances.
var ReadActions = []string{"finance:DescribeBudget", "advisor:DescribeStrategies", "advisor:DescribeTaskStrategyRisks",
	"monitor:GetMonitorData", "cvm:DescribeInstances"}

// ReadsRole is a client's read-only role assumed for Budget, Smart Advisor
// and Cloud Monitor reads: the same checks and ExternalId as ReadOnlyRole,
// with a session policy that allows only ReadActions.
func ReadsRole(base common.Provider, grant catalog.ClientReadRole, region, stsEndpoint string) (*ClientRole, error) {
	r, err := ReadOnlyRole(base, grant, region, stsEndpoint)
	if err != nil {
		return nil, err
	}
	r.policy = `{"version":"2.0","statement":[{"effect":"allow","action":["` + strings.Join(ReadActions, `","`) + `"],"resource":["*"]}]}`
	return r, nil
}

// GetCredential implements common.Provider. The zero ClientRole, which no
// constructor built, has no ExternalId and is refused.
func (c *ClientRole) GetCredential() (common.CredentialIface, error) {
	return c.get(func() (common.CredentialIface, time.Time, error) {
		externalID := c.grant.ExternalID()
		if externalID == "" {
			return nil, time.Time{}, errors.New("client role: no ExternalId; build it with ReadOnlyRole or ReadsRole")
		}
		return assumeRole(c.base, c.region, c.endpoint, c.grant.ARN(), &externalID, c.policy)
	})
}

// session caches an assumed role's credentials, renewing them 5 minutes
// before expiry.
type session struct {
	mu      sync.Mutex
	cached  common.CredentialIface
	expires time.Time
}

func (s *session) get(assume func() (common.CredentialIface, time.Time, error)) (common.CredentialIface, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil && time.Until(s.expires) > 5*time.Minute {
		return s.cached, nil
	}
	c, expires, err := assume()
	if err != nil {
		return nil, err
	}
	s.cached, s.expires = c, expires
	return c, nil
}

// assumeRole assumes arn from base, sending externalID and policy (a
// session policy limiting the session) when set.
func assumeRole(base common.Provider, region, endpoint, arn string, externalID *string, policy string) (common.CredentialIface, time.Time, error) {
	cred, err := base.GetCredential()
	if err != nil {
		return nil, time.Time{}, err
	}
	c, err := stsClient(cred, region, endpoint)
	if err != nil {
		return nil, time.Time{}, err
	}
	req := sts.NewAssumeRoleRequest()
	session, dur := "keel", uint64(3600)
	req.RoleArn, req.RoleSessionName, req.DurationSeconds, req.ExternalId = &arn, &session, &dur, externalID
	if policy != "" {
		policy = url.QueryEscape(policy) // STS URL-decodes Policy
		req.Policy = &policy
	}
	res, err := c.AssumeRole(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("AssumeRole %s: %w", arn, err)
	}
	if res.Response == nil || res.Response.Credentials == nil || res.Response.Credentials.TmpSecretId == nil {
		return nil, time.Time{}, errors.New("AssumeRole: no credentials in response")
	}
	cr := res.Response.Credentials
	expires := time.Now().Add(time.Duration(dur) * time.Second)
	if res.Response.ExpiredTime != nil {
		expires = time.Unix(*res.Response.ExpiredTime, 0)
	}
	return common.NewTokenCredential(*cr.TmpSecretId, *cr.TmpSecretKey, *cr.Token), expires, nil
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
