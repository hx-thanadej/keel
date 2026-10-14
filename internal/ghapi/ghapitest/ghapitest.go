// Package ghapitest fakes the GitHub App installation in front of a test
// GitHub, so integration tests authenticate the way Keel does in production.
package ghapitest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/ghapi"
)

// Token prefixes every installation token the fake mints. Each mint gets its
// own token so the fake can enforce the permissions that mint asked for.
const Token = "ghs_ghapitest"

const installation = 1

var key = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

// Server is a test GitHub with one App installation on Owner.
type Server struct {
	*httptest.Server
	Owner string

	mu     sync.Mutex
	asked  []ghapi.Permissions
	tokens map[string]ghapi.Permissions
}

// NewServer serves the installation endpoints and passes every other
// request to next, answering 401 to any that does not carry Token.
func NewServer(t testing.TB, owner string, next http.Handler) *Server {
	s := &Server{Owner: owner, tokens: map[string]ghapi.Permissions{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == fmt.Sprintf("/app/installations/%d", installation):
			_ = json.NewEncoder(w).Encode(map[string]any{"id": installation, "account": map[string]string{"login": owner}})
		case r.Method == http.MethodPost && r.URL.Path == fmt.Sprintf("/app/installations/%d/access_tokens", installation):
			var body struct {
				Permissions ghapi.Permissions `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.asked = append(s.asked, body.Permissions)
			tok := fmt.Sprintf("%s_%d", Token, len(s.asked))
			s.tokens[tok] = body.Permissions
			s.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": tok, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		case strings.HasPrefix(r.URL.Path, "/app/"):
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		default:
			perms, ok := s.permissions(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if !ok {
				http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
				return
			}
			if needs := requiredPermission(r); needs != "" && perms[needs] != "write" && perms[needs] != "admin" {
				http.Error(w, fmt.Sprintf(`{"message":"Resource not accessible by integration (needs %s: write)"}`, needs), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *Server) permissions(token string) (ghapi.Permissions, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.tokens[token]
	return p, ok
}

// requiredPermission is the permission GitHub's "Permissions required for
// GitHub Apps" adds to a request beyond what the endpoint's own resource
// needs. Writing a file under .github/workflows needs Workflows: write in
// addition to Contents.
func requiredPermission(r *http.Request) string {
	if r.Method != http.MethodGet && strings.Contains(r.URL.Path, "/contents/.github/workflows/") {
		return "workflows"
	}
	return ""
}

// App is the installation as Keel configures it.
func (s *Server) App() ghapi.App {
	return ghapi.App{BaseURL: s.URL, ID: "1", Installation: installation, Owner: s.Owner, Key: key(), HTTP: s.Server.Client()}
}

// Client authenticates as the installation with perms.
func (s *Server) Client(perms ghapi.Permissions) *http.Client {
	return s.App().Source(perms).Client(s.Server.Client())
}

// Asked returns the permissions of every token minted so far.
func (s *Server) Asked() []ghapi.Permissions {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ghapi.Permissions(nil), s.asked...)
}
