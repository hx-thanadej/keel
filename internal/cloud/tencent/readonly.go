package tencent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
)

// ErrReadOnly is the refusal of a write made with a stored-key connection,
// or with a role session assumed from one (ADR-0022).
var ErrReadOnly = errors.New("refused: Keel's Tencent identity is a stored-key connection, which is read-only (ADR-0022)")

// StoredKey returns the stored connection's key, or ok false when there is
// none. Keel's connections service implements it.
type StoredKey func(ctx context.Context) (secretID, secretKey string, ok bool, err error)

// readOnly marks a credential that may only read: a stored key, or a session
// assumed from one. guard reads the mark off the client's credential.
type readOnly struct{ common.CredentialIface }

// StoredCredential is a stored connection's key as a read-only credential.
func StoredCredential(secretID, secretKey string) common.CredentialIface {
	return readOnly{common.NewCredential(secretID, secretKey)}
}

// IsReadOnly reports whether c may only read.
func IsReadOnly(c common.CredentialIface) bool {
	_, ok := c.(readOnly)
	return ok
}

// Credentials is Keel's base Tencent identity. A stored connection comes
// first (ADR-0022); without one, keyless identity (ADR-0007): TKE pod
// identity (OIDC), then the CVM instance role, and environment or profile
// keys only when KEEL_ENV=dev. A stored connection that cannot be read is
// an error, never a fall back to a writable identity.
func Credentials(stored StoredKey) common.Provider {
	var chain []common.Provider
	if p, err := common.DefaultTkeOIDCRoleArnProvider(); err == nil && os.Getenv("TKE_WEB_IDENTITY_TOKEN_FILE") != "" {
		chain = append(chain, p)
	}
	chain = append(chain, common.DefaultCvmRoleProvider())
	if os.Getenv("KEEL_ENV") == "dev" {
		chain = append(chain, common.DefaultEnvProvider(), common.DefaultProfileProvider())
	}
	return storedFirst{stored: stored, keyless: common.NewProviderChain(chain)}
}

type storedFirst struct {
	stored  StoredKey
	keyless common.Provider
}

func (s storedFirst) GetCredential() (common.CredentialIface, error) {
	if s.stored != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		id, key, ok, err := s.stored(ctx)
		if err != nil {
			return nil, fmt.Errorf("stored Tencent connection: %w", err)
		}
		if ok {
			return StoredCredential(id, key), nil
		}
	}
	return s.keyless.GetCredential()
}

// sdkClient is any Tencent SDK service client.
type sdkClient interface {
	GetCredential() common.CredentialIface
	WithHttpTransport(http.RoundTripper) *common.Client
}

// guard takes a freshly built SDK client. When its credential is read-only,
// every call but one of Keel's reads fails before it leaves Keel. Every SDK
// client in Keel is built inside guard (TestEverySDKClientIsGuarded).
func guard[C sdkClient](c C, err error) (C, error) {
	if err != nil {
		return c, err
	}
	if IsReadOnly(c.GetCredential()) {
		c.WithHttpTransport(readsOnly{})
	}
	return c, nil
}

// reads are the only actions a read-only identity may send, as
// service:Action: exactly the reads Keel makes (TestReadsAreExactlyKeelsReads).
// sts:AssumeRole is one, because assumeRole marks the session it returns
// read-only.
var reads = set(
	"advisor:DescribeStrategies", "advisor:DescribeTaskStrategyRisks",
	"billing:DescribeBillDetail", "billing:DescribeBillSummaryByPayMode", "billing:DescribeBudget",
	"cam:DescribeOIDCConfig", "cam:DescribeRoleList", "cam:GetPolicy", "cam:GetRole", "cam:GetRolePermissionBoundary",
	"cam:ListAccessKeys", "cam:ListPolicies", "cam:ListUsers",
	"cbs:DescribeDisks",
	"clb:DescribeLoadBalancers", "clb:DescribeTargets",
	"cloudaudit:LookUpEvents",
	"cvm:DescribeInstances", "cvm:DescribeZoneInstanceConfigInfos",
	"monitor:GetMonitorData",
	"organization:DescribeOrganizationMembers", "organization:DescribeOrganizationNodes", "organization:DescribePolicy",
	"organization:ListPolicies", "organization:ListPoliciesForTarget", "organization:ListRoleAssignments",
	"organization:ListRoleConfigurations", "organization:ListUsers",
	"sts:AssumeRole", "sts:GetCallerIdentity",
	"tcr:DescribeImmutableTagRules", "tcr:DescribeNamespaces", "tcr:DescribeTagRetentionRules",
	"vpc:DescribeAddresses",
)

// mints are actions that mint a credential which would not carry the
// read-only mark. They are refused even if one is added to reads.
var mints = set(
	"sts:GetSessionToken", "sts:GetFederationToken", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML",
	"cam:CreateAccessKey", "tcr:CreateInstanceToken",
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// readsOnly sends only reads. The service comes from the request's TC3
// signature scope, which the SDK computes; a request without one (an older
// signature, or an unsigned call) is not known to be a read and is refused.
type readsOnly struct{}

func (readsOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	a := service(r.Header.Get("Authorization")) + ":" + r.Header.Get("X-TC-Action")
	if mints[a] || !reads[a] {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, fmt.Errorf("tencent %s %w", a, ErrReadOnly)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// service reads the service from a TC3-HMAC-SHA256 Authorization header,
// whose credential scope is SecretId/date/service/tc3_request.
func service(authorization string) string {
	_, cred, ok := strings.Cut(authorization, "Credential=")
	if !ok || !strings.HasPrefix(authorization, "TC3-HMAC-SHA256 ") {
		return ""
	}
	cred, _, _ = strings.Cut(cred, ",")
	parts := strings.Split(cred, "/")
	if len(parts) < 4 || parts[len(parts)-1] != "tc3_request" {
		return ""
	}
	return parts[len(parts)-2]
}
