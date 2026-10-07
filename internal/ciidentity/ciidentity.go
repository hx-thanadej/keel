// Package ciidentity gives each Environment's Cloud Account a keyless CI
// identity (#90, ADR-0007): an OIDC identity provider for GitHub Actions and
// one deploy role whose trust is pinned to immutable repository ids and the
// GitHub environment. No access key is ever created.
//
// Tencent CAM stores the identity provider's signing keys instead of fetching
// them (research/02 T1). Keel turns on CAM's key auto-rotation and also syncs
// the keys from GitHub's JWKS daily, raising a Finding if it cannot.
package ciidentity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

// GitHubIssuer is GitHub Actions' OIDC issuer.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// MaxSubjects is the most values CAM's oidc:sub condition accepts (T12).
const MaxSubjects = 10

// ErrTooManyRepos means more repositories deploy to one Environment than a
// single role's trust can name.
var ErrTooManyRepos = errors.New("more than 10 repositories deploy to this environment")

// Config names what Keel creates in each account.
type Config struct {
	ProviderName string // CAM identity provider name, default "github-actions"
	Audience     string // expected aud, default "sts.tencentcloudapi.com"
	RoleName     string // deploy role, default "keel-deploy"
}

func (c Config) withDefaults() Config {
	if c.ProviderName == "" {
		c.ProviderName = "github-actions"
	}
	if c.Audience == "" {
		c.Audience = "sts.tencentcloudapi.com"
	}
	if c.RoleName == "" {
		c.RoleName = "keel-deploy"
	}
	return c
}

// Binding is one repository allowed to deploy to one GitHub environment.
type Binding struct {
	OwnerID, RepoID int64
	Environment     string
}

// Subject is the oidc:sub GitHub issues once the organisation's subject
// template includes repository_owner_id, repository_id and environment.
// Ids survive renames and transfers; names do not.
func (b Binding) Subject() string {
	return fmt.Sprintf("repository_owner_id:%d:repository_id:%d:environment:%s", b.OwnerID, b.RepoID, b.Environment)
}

// SubjectClaimKeys is the organisation's OIDC subject template.
var SubjectClaimKeys = []string{"repository_owner_id", "repository_id", "environment"}

// Provider is an identity provider's configuration.
type Provider struct {
	URL        string
	ClientIDs  []string
	Keys       string // JWKS JSON
	AutoRotate bool
}

// IAM is the slice of the cloud's identity API in one account.
type IAM interface {
	OIDCProvider(ctx context.Context, name string) (Provider, bool, error)
	CreateOIDCProvider(ctx context.Context, name string, p Provider) error
	UpdateOIDCProvider(ctx context.Context, name string, p Provider) error
	RoleTrust(ctx context.Context, name string) (string, bool, error)
	CreateRole(ctx context.Context, name, trust, description string) error
	UpdateRoleTrust(ctx context.Context, name, trust string) error
}

// Trust is the role's trust policy: AssumeRoleWithWebIdentity from the
// account's GitHub provider, only for the given subjects. With no subjects it
// names a value GitHub never issues, so the role trusts nobody yet.
func Trust(account string, c Config, subjects []string) string {
	c = c.withDefaults()
	if len(subjects) == 0 {
		subjects = []string{"keel:no-repository-yet"}
	}
	sort.Strings(subjects)
	doc := map[string]any{"version": "2.0", "statement": []any{map[string]any{
		"action":    []string{"name/sts:AssumeRoleWithWebIdentity"},
		"effect":    "allow",
		"principal": map[string]any{"federated": []string{fmt.Sprintf("qcs::cam::uin/%s:oidc-provider/%s", account, c.ProviderName)}},
		"condition": map[string]any{"string_equal": map[string]any{
			"oidc:iss": []string{GitHubIssuer},
			"oidc:aud": []string{c.Audience},
			"oidc:sub": subjects,
		}},
	}}}
	b, _ := json.Marshal(doc)
	return string(b)
}

// Subjects turns bindings into a role's subject list.
func Subjects(bs []Binding) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, b := range bs {
		if s := b.Subject(); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) > MaxSubjects {
		return out[:MaxSubjects], fmt.Errorf("%w (%d)", ErrTooManyRepos, len(out))
	}
	return out, nil
}

// Change describes what Ensure did.
type Change struct {
	ProviderCreated, KeysUpdated, RoleCreated, TrustUpdated bool
}

// Ensure makes the account's provider and role match: keys from jwks, trust
// from subjects. It never creates access keys.
func Ensure(ctx context.Context, iam IAM, account string, c Config, jwks string, subjects []string) (Change, error) {
	c = c.withDefaults()
	var ch Change
	want := Provider{URL: GitHubIssuer, ClientIDs: []string{c.Audience}, Keys: jwks, AutoRotate: true}
	have, found, err := iam.OIDCProvider(ctx, c.ProviderName)
	if err != nil {
		return ch, err
	}
	switch {
	case !found:
		if err := iam.CreateOIDCProvider(ctx, c.ProviderName, want); err != nil {
			return ch, err
		}
		ch.ProviderCreated = true
	case !SameKeys(have.Keys, jwks) || !have.AutoRotate || have.URL != want.URL:
		if err := iam.UpdateOIDCProvider(ctx, c.ProviderName, want); err != nil {
			return ch, err
		}
		ch.KeysUpdated = true
	}
	trust := Trust(account, c, subjects)
	cur, found, err := iam.RoleTrust(ctx, c.RoleName)
	if err != nil {
		return ch, err
	}
	switch {
	case !found:
		if err := iam.CreateRole(ctx, c.RoleName, trust, "Keel: GitHub Actions deploy role, trust pinned to repository ids (ADR-0007)"); err != nil {
			return ch, err
		}
		ch.RoleCreated = true
	case !sameJSON(cur, trust):
		if err := iam.UpdateRoleTrust(ctx, c.RoleName, trust); err != nil {
			return ch, err
		}
		ch.TrustUpdated = true
	}
	return ch, nil
}

// SameKeys compares two JWKS documents by their key ids.
func SameKeys(a, b string) bool {
	ka, ea := kids(a)
	kb, eb := kids(b)
	if ea != nil || eb != nil || len(ka) != len(kb) {
		return false
	}
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

func kids(jwks string) ([]string, error) {
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks), &doc); err != nil {
		return nil, err
	}
	var out []string
	for _, k := range doc.Keys {
		out = append(out, k.Kid)
	}
	sort.Strings(out)
	return out, nil
}

func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return string(ja) == string(jb)
}

// Base64 is how CAM wants the JWKS.
func Base64(jwks string) string { return base64.StdEncoding.EncodeToString([]byte(jwks)) }

// GitHubJWKS fetches GitHub Actions' current signing keys.
func GitHubJWKS(c *http.Client) func(context.Context) (string, error) {
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	return func(ctx context.Context) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, GitHubIssuer+"/.well-known/jwks", nil)
		if err != nil {
			return "", err
		}
		res, err := c.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = res.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if res.StatusCode != http.StatusOK {
			return "", fmt.Errorf("github jwks: HTTP %d", res.StatusCode)
		}
		if _, err := kids(string(body)); err != nil {
			return "", fmt.Errorf("github jwks: %w", err)
		}
		return string(body), nil
	}
}
