package ghapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// App mints installation tokens for a GitHub App. Each token lives an hour
// and carries only the permissions asked for.
type App struct {
	BaseURL      string // default https://api.github.com
	ID           string // App ID or Client ID
	Installation int64
	Owner        string // the account login the installation must belong to
	Key          *rsa.PrivateKey
	HTTP         *http.Client
	Now          func() time.Time // defaults to time.Now
}

// ParseAppKey reads the PEM private key GitHub generates for an App
// (PKCS #1), or the same key converted to PKCS #8.
func ParseAppKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return nil, errors.New("github app key: no PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("github app key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github app key: not RSA")
	}
	return rk, nil
}

// Permissions maps a GitHub App permission (e.g. "contents") to the access
// level an installation token asks for ("read", "write" or "admin").
type Permissions map[string]string

// Source returns a token source for perms. Each GitHub caller gets its own,
// so its tokens carry only what its endpoints need (#231).
func (a App) Source(perms Permissions) *TokenSource {
	return &TokenSource{app: a, perms: perms}
}

// TokenSource hands out one installation token with fixed permissions and
// mints a new one five minutes before the current one expires. It is safe
// for concurrent use: callers wait on one mint rather than each minting.
type TokenSource struct {
	app   App
	perms Permissions

	mu      sync.Mutex
	token   string
	refresh time.Time
}

// refreshBefore is how long before expires_at a token is replaced, so a
// request never starts with a token about to lapse.
const refreshBefore = 5 * time.Minute

// Token returns the cached installation token, minting one if there is
// none or it is within five minutes of expiry.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.app.now().Before(s.refresh) {
		return s.token, nil
	}
	tok, exp, err := s.app.mint(ctx, s.perms)
	if err != nil {
		return "", err
	}
	s.token, s.refresh = tok, exp.Add(-refreshBefore)
	return tok, nil
}

// Client returns base with a transport that adds the installation token to
// every request for the GitHub API host, and to no other host.
func (s *TokenSource) Client(base *http.Client) *http.Client {
	c := *base
	next := c.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	host := "api.github.com"
	if u, err := url.Parse(s.app.BaseURL); err == nil && s.app.BaseURL != "" {
		host = u.Host
	}
	c.Transport = tokenTransport{src: s, host: host, next: next}
	return &c
}

type tokenTransport struct {
	src  *TokenSource
	host string
	next http.RoundTripper
}

func (t tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != t.host {
		return t.next.RoundTrip(req)
	}
	tok, err := t.src.Token(req.Context())
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, fmt.Errorf("github app installation token: %w", err)
	}
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+tok)
	return t.next.RoundTrip(req)
}

// mint asks GitHub for a new installation token limited to perms. It
// refuses an installation on any account but Owner, so a wrong
// installation id never yields a token for someone else's organisation.
func (a App) mint(ctx context.Context, perms Permissions) (string, time.Time, error) {
	if a.Owner == "" {
		return "", time.Time{}, errors.New("github app: no owner to check the installation against")
	}
	jwt, err := a.jwt()
	if err != nil {
		return "", time.Time{}, err
	}
	gh := Client{BaseURL: a.BaseURL, Token: jwt, HTTP: a.HTTP}
	var inst struct {
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := gh.Do(ctx, http.MethodGet, fmt.Sprintf("/app/installations/%d", a.Installation), nil, &inst); err != nil {
		return "", time.Time{}, err
	}
	if !strings.EqualFold(inst.Account.Login, a.Owner) {
		return "", time.Time{}, fmt.Errorf("github app: installation %d is on %q, not %q", a.Installation, inst.Account.Login, a.Owner)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	in := map[string]any{"permissions": perms}
	if err := gh.Do(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", a.Installation), in, &out); err != nil {
		return "", time.Time{}, err
	}
	if out.Token == "" || out.ExpiresAt.IsZero() {
		return "", time.Time{}, errors.New("github app: installation token response has no token or expires_at")
	}
	return out.Token, out.ExpiresAt, nil
}

func (a App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// jwt signs the App's RS256 assertion. iat is a minute early for clock
// drift; GitHub rejects an expiry more than ten minutes out.
func (a App) jwt() (string, error) {
	now := a.now()
	enc := base64.RawURLEncoding
	claims, err := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": a.ID})
	if err != nil {
		return "", err
	}
	signing := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
