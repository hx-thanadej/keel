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
// every call but a read fails before it leaves Keel. Every client this
// package builds passes through here (TestEverySDKClientIsGuarded).
func guard[C sdkClient](c C, err error) (C, error) {
	if err != nil {
		return c, err
	}
	if IsReadOnly(c.GetCredential()) {
		c.WithHttpTransport(readsOnly{})
	}
	return c, nil
}

// readsOnly sends only read actions. A request with no action header is not
// known to be a read, so it is refused too.
type readsOnly struct{}

func (readsOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if a := r.Header.Get("X-TC-Action"); !isRead(a) {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, fmt.Errorf("tencent %s %w", a, ErrReadOnly)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// isRead allows Describe*, List*, Get* and LookUp* calls, and AssumeRole,
// whose session stays read-only (assumeRole marks it). GetFederationToken
// mints a credential that would not carry the mark.
func isRead(action string) bool {
	if action == "AssumeRole" {
		return true
	}
	if action == "GetFederationToken" {
		return false
	}
	for _, p := range []string{"Describe", "List", "Get", "LookUp"} {
		if strings.HasPrefix(action, p) && len(action) > len(p) {
			return true
		}
	}
	return false
}
