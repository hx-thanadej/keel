package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/githubgov"
	"github.com/hx-thanadej/keel/internal/leaks"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

const catchupToken = "ghs_never-log-this-installation-token"

type fakeAttempt struct {
	ID          int64     `json:"id"`
	GUID        string    `json:"guid"`
	DeliveredAt time.Time `json:"delivered_at"`
	Redelivery  bool      `json:"redelivery"`
	Status      string    `json:"status"`
	StatusCode  int       `json:"status_code"`
	Event       string    `json:"event"`
}

// fakeHookAPI is GitHub's view of organisation hook 42 on acme: every
// attempt to deliver, newest first, two per page. A redelivery POSTs the
// original payload, signed, to Keel and records the new attempt.
type fakeHookAPI struct {
	t        *testing.T
	keel     string
	mu       sync.Mutex
	attempts []fakeAttempt
	payloads map[string][2]string // guid -> event, body
	resent   []string             // guids redelivered, in order
	minted   []map[string]string  // permissions of each installation token
}

func (f *fakeHookAPI) deliver(guid, event, body string, at time.Time, reachKeel bool, redelivery bool) {
	f.t.Helper()
	f.payloads[guid] = [2]string{event, body}
	a := fakeAttempt{ID: int64(len(f.attempts) + 1000), GUID: guid, DeliveredAt: at, Redelivery: redelivery, Event: event, Status: "Invalid HTTP Response: 502", StatusCode: 502}
	if reachKeel {
		req, _ := http.NewRequest(http.MethodPost, f.keel+"/v1/webhooks/github", strings.NewReader(body))
		req.Header.Set("X-GitHub-Delivery", guid)
		req.Header.Set("X-GitHub-Event", event)
		req.Header.Set("X-Hub-Signature-256", signed("whsec", []byte(body)))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			f.t.Fatal(err)
		}
		_ = res.Body.Close()
		a.Status, a.StatusCode = "OK", res.StatusCode
		if res.StatusCode >= 300 {
			a.Status = "Invalid HTTP Response: " + strconv.Itoa(res.StatusCode)
		}
	}
	f.attempts = slices.Insert(f.attempts, 0, a)
	slices.SortStableFunc(f.attempts, func(x, y fakeAttempt) int { return y.DeliveredAt.Compare(x.DeliveredAt) })
}

func (f *fakeHookAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/app/installations/9" {
		_, _ = w.Write([]byte(`{"id":9,"account":{"login":"acme"}}`))
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/app/installations/9/access_tokens" {
		var body struct {
			Permissions map[string]string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.minted = append(f.minted, body.Permissions)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"token":%q,"expires_at":%q}`, catchupToken, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+catchupToken {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	const list = "/orgs/acme/hooks/42/deliveries"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == list:
		from, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
		to := min(from+2, len(f.attempts))
		if to < len(f.attempts) {
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?per_page=100&cursor=%d>; rel="next"`, r.Host, list, to))
		}
		_ = json.NewEncoder(w).Encode(f.attempts[from:to])
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, list+"/") && strings.HasSuffix(r.URL.Path, "/attempts"):
		id, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, list+"/"), "/attempts"), 10, 64)
		i := slices.IndexFunc(f.attempts, func(a fakeAttempt) bool { return a.ID == id })
		if i < 0 {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		guid := f.attempts[i].GUID
		f.resent = append(f.resent, guid)
		p := f.payloads[guid]
		f.deliver(guid, p[0], p[1], time.Now(), true, true)
		w.WriteHeader(http.StatusAccepted)
	default:
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

func TestWebhookCatchupRedeliversMissedDeliveriesOnce(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	if _, err := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTenant(ctx, "tat", "TAT", false); err != nil {
		t.Fatal(err)
	}
	keel := httptest.NewServer(api.NewRouter(api.Info{Version: "test"}, api.Deps{Webhooks: &api.WebhookDeps{
		Leaks:      &leaks.Service{Store: s, WebhookSecret: []byte("whsec")},
		Governance: &githubgov.Receiver{Store: s, Owner: "acme", Policy: githubgov.Default(nil)},
	}}))
	t.Cleanup(keel.Close)
	gh := &fakeHookAPI{t: t, keel: keel.URL, payloads: map[string][2]string{}}
	github := httptest.NewServer(gh)
	t.Cleanup(github.Close)

	now := time.Now()
	team := func(slug string) string {
		return `{"action":"created","team":{"slug":"` + slug + `"},"organization":{"login":"acme"},"sender":{"login":"eve","type":"User"}}`
	}
	tatRepo := `{"action":"edited","repository":{"name":"tat-api","full_name":"acme/tat-api","custom_properties":{"keel-tenant":"tat"}},"organization":{"login":"acme"},"sender":{"login":"eve","type":"User"}}`
	pushProtectionOff := `{"action":"","repository":{"name":"pp","full_name":"acme/pp","security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"disabled"}}},` +
		`"changes":{"from":{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}},"organization":{"login":"acme"},"sender":{"login":"eve","type":"User"}}`
	member := `{"action":"added","member":{"login":"mallory"},"repository":{"name":"crm","full_name":"acme/crm"},"organization":{"login":"acme"},"sender":{"login":"eve","type":"User"}}`

	gh.deliver("old-1", "team", team("old"), now.Add(-30*time.Hour), false, false)
	gh.deliver("ok-1", "team", team("ok"), now.Add(-5*time.Hour), true, false)
	gh.deliver("foreign-ok", "team", `{"action":"created","team":{"slug":"x"},"organization":{"login":"other"}}`, now.Add(-270*time.Minute), true, false)
	gh.deliver("retry-ok", "team", team("retry"), now.Add(-4*time.Hour), false, false)
	gh.deliver("retry-ok", "team", team("retry"), now.Add(-210*time.Minute), true, true)
	gh.deliver("miss-1", "team", team("missed"), now.Add(-3*time.Hour), false, false)
	gh.deliver("rec-1", "repository", tatRepo, now.Add(-150*time.Minute), true, false)
	gh.mu.Lock()
	for i, a := range gh.attempts {
		if a.GUID == "rec-1" {
			gh.attempts[i].Status, gh.attempts[i].StatusCode = "timed out", 0
		}
	}
	gh.mu.Unlock()
	gh.deliver("miss-2", "security_and_analysis", pushProtectionOff, now.Add(-2*time.Hour), false, false)
	gh.deliver("stuck-1", "team", team("stuck"), now.Add(-100*time.Minute), false, false)
	gh.deliver("stuck-1", "team", team("stuck"), now.Add(-95*time.Minute), false, true)
	gh.deliver("stuck-1", "team", team("stuck"), now.Add(-90*time.Minute), false, true)
	gh.deliver("miss-3", "member", member, now.Add(-time.Hour), false, false)

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	app := ghapi.App{BaseURL: github.URL, ID: "123", Installation: 9, Owner: "acme", Key: key}
	job := githubgov.Catchup{Store: s, Org: "acme", HookID: 42, BaseURL: github.URL, Window: 24 * time.Hour,
		Token: app.Source(ghapi.Permissions{"organization_hooks": "write"}).Token}

	res, err := job.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"miss-1", "miss-2", "miss-3"}; !slices.Equal(gh.resent, want) {
		t.Fatalf("redelivered %v, want %v (oldest first; not ok-1, foreign-ok, retry-ok, rec-1, stuck-1 or old-1)", gh.resent, want)
	}
	if res.Redelivered != 3 {
		t.Fatalf("result %+v, want 3 redelivered", res)
	}

	su := storetest.Superuser(t, s)
	for _, guid := range []string{"ok-1", "retry-ok", "rec-1", "miss-1", "miss-2", "miss-3"} {
		var n int
		if err := su.QueryRow(ctx, `SELECT count(*) FROM activities WHERE source = 'github/org-webhook' AND event->'data'->>'status_detail' LIKE 'delivery ' || $1 || '%'`, guid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("delivery %s: %d activities, want exactly 1", guid, n)
		}
	}
	var findings int
	if err := su.QueryRow(ctx, `SELECT count(*) FROM findings WHERE kind = 'github_governance'`).Scan(&findings); err != nil || findings != 1 {
		t.Fatalf("github_governance findings %d, %v; want 1 from miss-2", findings, err)
	}

	res, err = job.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Redelivered != 0 || len(gh.resent) != 3 {
		t.Fatalf("second run redelivered %d (total %v), want none", res.Redelivered, gh.resent)
	}
	if len(gh.minted) != 1 || !maps.Equal(gh.minted[0], map[string]string{"organization_hooks": "write"}) {
		t.Fatalf("installation tokens minted %v, want one reused across runs with only organization_hooks:write", gh.minted)
	}

	broken := job
	broken.HookID = 7
	if _, err := broken.Run(ctx); err == nil {
		t.Fatal("unknown hook: no error")
	} else if strings.Contains(err.Error(), catchupToken) {
		t.Fatalf("error carries the token: %v", err)
	}
	if strings.Contains(logs.String(), catchupToken) {
		t.Fatalf("token logged:\n%s", logs.String())
	}
}

// A GitHub that accepts the connection and never answers must not hold the
// job, whose context lives as long as the server.
func TestWebhookCatchupGivesUpOnAHungGitHub(t *testing.T) {
	release := make(chan struct{})
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(github.Close)
	t.Cleanup(func() { close(release) })

	job := githubgov.Catchup{Org: "acme", HookID: 42, BaseURL: github.URL, Window: time.Hour,
		HTTP:  &http.Client{Timeout: 200 * time.Millisecond},
		Token: func(context.Context) (string, error) { return catchupToken, nil }}
	done := make(chan error, 1)
	go func() { _, err := job.Run(t.Context()); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("hung GitHub: no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("catch-up still waiting on a hung GitHub after 5s")
	}
}
