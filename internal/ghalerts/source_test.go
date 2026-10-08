package ghalerts_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/ghalerts"
	"github.com/hx-thanadej/keel/internal/ghapi"
)

func TestGitHubSourceMapsCodeScanningSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/crm/code-scanning/alerts" || r.URL.Query().Get("state") != "open" || r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("unexpected request %s %v", r.URL, r.Header)
		}
		_, _ = w.Write([]byte(`[{"number": 1, "rule": {"id": "go/sql-injection", "security_severity_level": "critical", "severity": "note", "description": "SQL injection"}, "tool": {"name": "CodeQL"},
			"most_recent_instance": {"location": {"path": "db.go", "start_line": 7}, "message": {"text": "bad"}}},
			{"number": 2, "rule": {"id": "go/xss", "security_severity_level": null, "severity": "warning"}, "tool": {"name": "CodeQL"}}]`))
	}))
	defer srv.Close()
	g := ghalerts.GitHub{Client: ghapi.Client{BaseURL: srv.URL, Token: "tok"}}
	got, err := g.CodeScanning(context.Background(), "acme/crm")
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if got[0].Severity != "critical" || got[1].Severity != "medium" || got[0].Tool != "codeql" || got[0].Path != "db.go" || got[0].Line != 7 || got[0].Number != 1 {
		t.Fatalf("%+v %+v", got[0], got[1])
	}
}

// cursorServer serves Dependabot-style cursor pages: it ignores "page" and
// pages only by the "after" cursor in its Link header, like GitHub's
// Dependabot alerts endpoint. next(after) returns the next cursor, or "".
// It answers 500 after 150 requests so a client that never stops fails.
func cursorServer(t *testing.T, sizes map[string]int, next func(after string) string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RawQuery)
		if len(seen) > 150 {
			w.WriteHeader(500)
			return
		}
		q := r.URL.Query()
		if q.Get("state") != "open" || q.Get("per_page") != "100" {
			t.Errorf("request lost its filters: %s", r.URL)
		}
		after := q.Get("after")
		if n := next(after); n != "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?state=open&per_page=100&after=%s>; rel="next", <%s%s?state=open&per_page=100&before=x>; rel="prev"`, srv.URL, r.URL.Path, n, srv.URL, r.URL.Path))
		}
		var parts []string
		for i := range sizes[after] {
			parts = append(parts, fmt.Sprintf(`{"number": %d, "security_advisory": {"ghsa_id": "GHSA-%s-%d", "severity": "low"}}`, i+1, after, i))
		}
		_, _ = fmt.Fprintf(w, "[%s]", strings.Join(parts, ","))
	})
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestGitHubSourceFollowsLinkCursor(t *testing.T) {
	srv, seen := cursorServer(t, map[string]int{"": 100, "c1": 100, "c2": 1}, func(after string) string {
		return map[string]string{"": "c1", "c1": "c2"}[after]
	})
	got, err := ghalerts.GitHub{Client: ghapi.Client{BaseURL: srv.URL}}.Dependabot(context.Background(), "acme/crm")
	if err != nil || len(got) != 201 || len(*seen) != 3 {
		t.Fatalf("%d alerts from %d requests %v, err %v", len(got), len(*seen), *seen, err)
	}
	if got[0].GHSA != "GHSA--0" || got[100].GHSA != "GHSA-c1-0" || got[200].GHSA != "GHSA-c2-0" {
		t.Fatalf("pages out of order: %s %s %s", got[0].GHSA, got[100].GHSA, got[200].GHSA)
	}
}

func TestGitHubSourceStopsAtPageCap(t *testing.T) {
	srv, seen := cursorServer(t, map[string]int{"": 1, "same": 1}, func(string) string { return "same" })
	_, err := ghalerts.GitHub{Client: ghapi.Client{BaseURL: srv.URL}}.Dependabot(context.Background(), "acme/crm")
	if !errors.Is(err, ghalerts.ErrTooManyPages) || len(*seen) != 100 {
		t.Fatalf("after %d requests: %v", len(*seen), err)
	}
}

func TestGitHubSourceRefusesNextLinkOnAnotherHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example/repos/acme/crm/dependabot/alerts?after=x>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	if _, err := (ghalerts.GitHub{Client: ghapi.Client{BaseURL: srv.URL, Token: "tok"}}).Dependabot(context.Background(), "acme/crm"); err == nil {
		t.Fatal("followed a next link to another host")
	}
}

func TestGitHubSourceDependabotAndSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/dependabot/alerts"):
			_, _ = w.Write([]byte(`[{"number": 3, "security_advisory": {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2026-1", "summary": "bad", "severity": "moderate"},
				"dependency": {"package": {"ecosystem": "npm", "name": "left-pad"}, "manifest_path": "package-lock.json"}}]`))
		case strings.HasSuffix(r.URL.Path, "/secret-scanning/alerts"):
			if r.URL.Query().Get("hide_secret") != "true" {
				t.Errorf("secret scanning list without hide_secret=true: %s", r.URL)
			}
			_, _ = w.Write([]byte(`[{"number": 9, "secret_type": "aws_access_key_id", "secret_type_display_name": "AWS Access Key ID", "secret": "AKIASUPERSECRET", "html_url": "https://github.com/acme/crm/security/secret-scanning/9"}]`))
		}
	}))
	defer srv.Close()
	g := ghalerts.GitHub{Client: ghapi.Client{BaseURL: srv.URL}}
	d, err := g.Dependabot(context.Background(), "acme/crm")
	if err != nil || len(d) != 1 || d[0].Severity != "medium" || d[0].CVE != "CVE-2026-1" || d[0].Package != "left-pad" || d[0].ManifestPath != "package-lock.json" {
		t.Fatalf("%+v %v", d, err)
	}
	s, err := g.SecretScanning(context.Background(), "acme/crm")
	if err != nil || len(s) != 1 || s[0].Number != 9 || s[0].Type != "aws_access_key_id" || strings.Contains(fmt.Sprintf("%+v", s), "AKIASUPERSECRET") {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestGitHubSourceMapsRefusals(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{403, `{"message": "Advanced Security must be enabled for this repository to use code scanning."}`, ghalerts.ErrNotEnabled},
		{404, `{"message": "Secret scanning is disabled on this repository."}`, ghalerts.ErrNotEnabled},
		{404, `{"message": "no analysis found"}`, ghalerts.ErrNotEnabled},
		{403, `{"message": "Resource not accessible by personal access token"}`, ghalerts.ErrForbidden},
		{404, `{"message": "Not Found"}`, ghalerts.ErrForbidden},
	} {
		t.Run(strconv.Itoa(tc.status)+tc.body[:20], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			g := ghalerts.GitHub{Client: ghapi.Client{BaseURL: srv.URL}}
			if _, err := g.CodeScanning(context.Background(), "acme/crm"); !errors.Is(err, tc.want) {
				t.Fatalf("code scanning: %v, want %v", err, tc.want)
			}
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	_, err := ghalerts.GitHub{Client: ghapi.Client{BaseURL: srv.URL}}.Dependabot(context.Background(), "acme/crm")
	if err == nil || errors.Is(err, ghalerts.ErrNotEnabled) || errors.Is(err, ghalerts.ErrForbidden) || ghapi.Status(err) != 500 {
		t.Fatalf("500 mapped to %v", err)
	}
}
