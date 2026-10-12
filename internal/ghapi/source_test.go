package ghapi_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/ghapi"
)

// mintServer is a GitHub that mints ghs_<n> tokens expiring an hour after
// the test clock, and records each mint's requested permissions.
type mintServer struct {
	*httptest.Server
	mu     sync.Mutex
	now    time.Time
	mints  atomic.Int32
	asked  []ghapi.Permissions
	delay  time.Duration
	bearer []string
}

func newMintServer(t *testing.T) *mintServer {
	m := &mintServer{now: time.Unix(1_800_000_000, 0)}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/app/installations/77":
			_, _ = w.Write([]byte(`{"id":77,"account":{"login":"acme"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens":
			time.Sleep(m.delay)
			var body struct {
				Permissions ghapi.Permissions `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			n := m.mints.Add(1)
			m.mu.Lock()
			m.asked = append(m.asked, body.Permissions)
			exp := m.now.Add(time.Hour)
			m.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"token":"ghs_%d","expires_at":%q}`, n, exp.UTC().Format(time.RFC3339))
		default:
			m.mu.Lock()
			m.bearer = append(m.bearer, r.Header.Get("Authorization"))
			m.mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *mintServer) set(now time.Time) {
	m.mu.Lock()
	m.now = now
	m.mu.Unlock()
}

func (m *mintServer) app(t *testing.T) ghapi.App {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return ghapi.App{BaseURL: m.URL, ID: "123", Installation: 77, Owner: "acme", Key: key,
		Now: func() time.Time { m.mu.Lock(); defer m.mu.Unlock(); return m.now }}
}

func TestTokenSourceReusesATokenUntilFiveMinutesBeforeItExpires(t *testing.T) {
	m := newMintServer(t)
	start := m.now
	src := m.app(t).Source(ghapi.Permissions{"contents": "read"})
	for i, step := range []struct {
		at   time.Duration
		want string
	}{
		{0, "ghs_1"},
		{30 * time.Minute, "ghs_1"},
		{55*time.Minute - time.Second, "ghs_1"},
		{55 * time.Minute, "ghs_2"},
		{60 * time.Minute, "ghs_2"},
	} {
		m.set(start.Add(step.at))
		tok, err := src.Token(t.Context())
		if err != nil || tok != step.want {
			t.Fatalf("step %d at +%v: token %q, %v; want %q", i, step.at, tok, err, step.want)
		}
	}
	if n := m.mints.Load(); n != 2 {
		t.Fatalf("%d mints, want 2 (one per hour, refreshed 5 minutes early)", n)
	}
}

func TestTokenSourceMintsOnceForConcurrentCallers(t *testing.T) {
	m := newMintServer(t)
	m.delay = 50 * time.Millisecond
	src := m.app(t).Source(ghapi.Permissions{"contents": "read"})
	var wg sync.WaitGroup
	toks := make([]string, 32)
	for i := range toks {
		wg.Go(func() {
			tok, err := src.Token(t.Context())
			if err != nil {
				t.Error(err)
			}
			toks[i] = tok
		})
	}
	wg.Wait()
	if n := m.mints.Load(); n != 1 {
		t.Fatalf("%d mints for 32 concurrent callers, want 1", n)
	}
	for _, tok := range toks {
		if tok != "ghs_1" {
			t.Fatalf("tokens %v, want all ghs_1", toks)
		}
	}
}

func TestTokenSourceAsksOnlyForItsPermissions(t *testing.T) {
	m := newMintServer(t)
	app := m.app(t)
	a := app.Source(ghapi.Permissions{"contents": "write", "pull_requests": "write"})
	b := app.Source(ghapi.Permissions{"secret_scanning_alerts": "read"})
	for _, src := range []*ghapi.TokenSource{a, b, a} {
		if _, err := src.Token(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{`{"contents":"write","pull_requests":"write"}`, `{"secret_scanning_alerts":"read"}`}
	if len(m.asked) != len(want) {
		t.Fatalf("asked %v, want one mint per source", m.asked)
	}
	for i, p := range m.asked {
		got, _ := json.Marshal(p)
		if string(got) != want[i] {
			t.Errorf("mint %d asked %s, want %s", i, got, want[i])
		}
	}
}

// The client authenticates requests to the GitHub API host only, so a
// redirect or a link elsewhere never carries the installation token.
func TestTokenSourceClientSendsTheTokenOnlyToGitHub(t *testing.T) {
	m := newMintServer(t)
	var elsewhere string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere = r.Header.Get("Authorization")
	}))
	t.Cleanup(other.Close)
	c := m.app(t).Source(ghapi.Permissions{"contents": "read"}).Client(&http.Client{Timeout: 5 * time.Second})
	if err := (ghapi.Client{BaseURL: m.URL, HTTP: c}).Do(t.Context(), http.MethodGet, "/repos/acme/crm", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(m.bearer) != 1 || m.bearer[0] != "Bearer ghs_1" {
		t.Fatalf("GitHub saw Authorization %q, want Bearer ghs_1", m.bearer)
	}
	res, err := c.Get(other.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if elsewhere != "" {
		t.Fatalf("another host got Authorization %q", elsewhere)
	}
}

func TestTokenSourceRejectsATokenWithoutExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"account":{"login":"acme"}}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_forever"}`))
	}))
	t.Cleanup(srv.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	app := ghapi.App{BaseURL: srv.URL, ID: "1", Installation: 1, Owner: "acme", Key: key}
	if tok, err := app.Source(ghapi.Permissions{"contents": "read"}).Token(t.Context()); err == nil {
		t.Fatalf("token %q with no expires_at accepted", tok)
	}
}
