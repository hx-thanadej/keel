package ghapi_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/ghapi"
)

func TestAppTokenSignsJWTAndNarrowsPermissions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	var gotPerms map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/77/access_tokens" {
			t.Errorf("%s %s, want POST /app/installations/77/access_tokens", r.Method, r.URL.Path)
		}
		jwt, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(jwt, ".")
		if !ok || len(parts) != 3 {
			t.Fatalf("authorization %q is not a bearer JWT", r.Header.Get("Authorization"))
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
			t.Errorf("JWT signature: %v", err)
		}
		var hdr struct{ Alg string }
		var claims struct {
			Iat, Exp int64
			Iss      string
		}
		h, _ := base64.RawURLEncoding.DecodeString(parts[0])
		c, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if json.Unmarshal(h, &hdr) != nil || json.Unmarshal(c, &claims) != nil {
			t.Fatalf("JWT header %s claims %s", h, c)
		}
		if hdr.Alg != "RS256" || claims.Iss != "123" || claims.Iat > now.Unix() || claims.Exp <= now.Unix() || claims.Exp-claims.Iat > 600 {
			t.Errorf("JWT header %s claims %s", h, c)
		}
		var body struct {
			Permissions map[string]string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		gotPerms = body.Permissions
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_installation","expires_at":"2027-01-15T09:00:00Z"}`))
	}))
	defer srv.Close()

	for name, block := range map[string]*pem.Block{
		"pkcs1": {Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)},
		"pkcs8": func() *pem.Block {
			b, _ := x509.MarshalPKCS8PrivateKey(key)
			return &pem.Block{Type: "PRIVATE KEY", Bytes: b}
		}(),
	} {
		parsed, err := ghapi.ParseAppKey(pem.EncodeToMemory(block))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		app := ghapi.App{BaseURL: srv.URL, ID: "123", Installation: 77, Key: parsed, Now: func() time.Time { return now }}
		tok, err := app.Token(t.Context(), map[string]string{"organization_hooks": "write"})
		if err != nil || tok != "ghs_installation" {
			t.Fatalf("%s: token %q, %v", name, tok, err)
		}
		if len(gotPerms) != 1 || gotPerms["organization_hooks"] != "write" {
			t.Fatalf("%s: requested permissions %v, want only organization_hooks:write", name, gotPerms)
		}
	}
	if _, err := ghapi.ParseAppKey([]byte("not a key")); err == nil {
		t.Fatal("garbage parsed as a key")
	}
}
