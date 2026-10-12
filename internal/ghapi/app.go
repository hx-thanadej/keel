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
	"time"
)

// App mints installation tokens for a GitHub App. Each token lives an hour
// and carries only the permissions asked for.
type App struct {
	BaseURL      string // default https://api.github.com
	ID           string // App ID or Client ID
	Installation int64
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

// Token returns a new installation token limited to perms.
func (a App) Token(ctx context.Context, perms map[string]string) (string, error) {
	jwt, err := a.jwt()
	if err != nil {
		return "", err
	}
	var out struct {
		Token string `json:"token"`
	}
	in := map[string]any{"permissions": perms}
	if err := (Client{BaseURL: a.BaseURL, Token: jwt, HTTP: a.HTTP}).Do(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", a.Installation), in, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("github app: empty installation token")
	}
	return out.Token, nil
}

// jwt signs the App's RS256 assertion. iat is a minute early for clock
// drift; GitHub rejects an expiry more than ten minutes out.
func (a App) jwt() (string, error) {
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
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
