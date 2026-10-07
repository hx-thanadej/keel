// Package oidctest is a minimal OpenID Provider for tests: discovery, JWKS,
// an authorize endpoint that logs in a preset user, and a PKCE-checking
// token endpoint.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Provider is a running fake IdP.
type Provider struct {
	URL      string
	ClientID string
	Secret   string

	key    *rsa.PrivateKey
	signer jose.Signer

	mu    sync.Mutex
	user  map[string]any
	codes map[string]pending
}

type pending struct {
	claims    map[string]any
	nonce     string
	challenge string
}

// New starts a provider for one client.
func New(t *testing.T, clientID, secret string) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{ClientID: clientID, Secret: secret, key: key, signer: signer, codes: map[string]pending{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	p.URL = srv.URL
	return p
}

// LoginAs sets the claims the next /authorize will issue.
func (p *Provider) LoginAs(claims map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.user = claims
}

// Mint signs an ID token for bearer-token tests.
func (p *Provider) Mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := p.sign(claims, "")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (p *Provider) sign(extra map[string]any, nonce string) (string, error) {
	now := time.Now()
	c := map[string]any{
		"iss": p.URL, "aud": p.ClientID, "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
	if nonce != "" {
		c["nonce"] = nonce
	}
	for k, v := range extra {
		c[k] = v
	}
	return jwt.Signed(p.signer).Claims(c).Serialize()
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                p.URL,
		"authorization_endpoint":                p.URL + "/authorize",
		"token_endpoint":                        p.URL + "/token",
		"jwks_uri":                              p.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	user := p.user
	code := rand.Text()
	p.codes[code] = pending{claims: user, nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	p.mu.Unlock()
	if user == nil {
		http.Error(w, "no user configured", http.StatusForbidden)
		return
	}
	u, _ := url.Parse(q.Get("redirect_uri"))
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || secret != p.Secret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	p.mu.Lock()
	pend, found := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || base64.RawURLEncoding.EncodeToString(sum[:]) != pend.challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	idt, err := p.sign(pend.claims, pend.nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + rand.Text(), "token_type": "Bearer", "id_token": idt, "expires_in": 600})
}
