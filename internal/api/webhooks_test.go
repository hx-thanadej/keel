package api_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/githubgov"
	"github.com/hx-thanadej/keel/internal/leaks"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func signed(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestGitHubWebhookVerifiesSizeSignatureAndReplays(t *testing.T) {
	s := storetest.New(t)
	ctx := t.Context()
	if _, err := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.NewRouter(api.Info{Version: "test"}, api.Deps{Webhooks: &api.WebhookDeps{
		Leaks:      &leaks.Service{Store: s, WebhookSecret: []byte("whsec")},
		Governance: &githubgov.Receiver{Store: s, Owner: "acme", Policy: githubgov.Default(nil)},
	}}))
	t.Cleanup(srv.Close)
	post := func(delivery, event string, body []byte, signature string) int {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/webhooks/github", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Delivery", delivery)
		req.Header.Set("X-GitHub-Event", event)
		req.Header.Set("X-Hub-Signature-256", signature)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	activities := func() int {
		t.Helper()
		var n int
		if err := storetest.Superuser(t, s).QueryRow(ctx, `SELECT count(*) FROM activities WHERE source = 'github/org-webhook'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	body := []byte(`{"action":"created","team":{"slug":"crm"},"organization":{"login":"acme"},"sender":{"login":"eve","type":"User"}}`)
	if code := post("d-1", "team", body, signed("wrong", body)); code != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d, want 401", code)
	}
	if code := post("d-1", "team", body, ""); code != http.StatusUnauthorized {
		t.Fatalf("no signature: %d, want 401", code)
	}
	if n := activities(); n != 0 {
		t.Fatalf("unsigned delivery recorded %d activities", n)
	}

	big := []byte(`{"organization":{"login":"acme"},"pad":"` + strings.Repeat("x", 1<<20) + `"}`)
	if code := post("d-big", "team", big, signed("whsec", big)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: %d, want 413", code)
	}

	if code := post("d-1", "team", body, signed("whsec", body)); code != http.StatusAccepted {
		t.Fatalf("signed delivery: %d, want 202", code)
	}
	if code := post("d-1", "team", body, signed("whsec", body)); code != http.StatusOK {
		t.Fatalf("redelivery: %d, want 200", code)
	}
	if n := activities(); n != 1 {
		t.Fatalf("activities %d, want 1", n)
	}

	foreign := []byte(`{"action":"created","team":{"slug":"x"},"organization":{"login":"evil"}}`)
	if code := post("d-2", "team", foreign, signed("whsec", foreign)); code != http.StatusAccepted {
		t.Fatalf("foreign organisation: %d, want 202 (ignored)", code)
	}
	if n := activities(); n != 1 {
		t.Fatalf("foreign organisation recorded: %d activities", n)
	}

	ping := []byte(`{"zen":"Keep it logically awesome."}`)
	if code := post("d-3", "ping", ping, signed("whsec", ping)); code != http.StatusAccepted {
		t.Fatalf("ping: %d, want 202", code)
	}
}
