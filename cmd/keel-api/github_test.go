package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/ghapi/ghapitest"
)

// The permission each caller needs, from GitHub's "Permissions required for
// GitHub Apps" for every endpoint the caller uses (ADR-0020's table).
var (
	pullRequestWriter = ghapi.Permissions{"contents": "write", "pull_requests": "write", "metadata": "read"}
	wantPermissions   = map[string]ghapi.Permissions{
		"rightsizing": pullRequestWriter,
		"admission":   pullRequestWriter,
		"promotion":   pullRequestWriter,
		"alerts":      {"security_events": "read", "vulnerability_alerts": "read", "secret_scanning_alerts": "read"},
		"leaks":       {"secret_scanning_alerts": "read"},
		"templates":   {"administration": "write", "contents": "write", "metadata": "read", "organization_custom_properties": "write", "members": "read"},
		"decisions":   {"contents": "read"},
		"catalog":     {"contents": "read", "metadata": "read"},
		"catchup":     {"organization_hooks": "write"},
	}
	wantGovernance = map[[2]bool]ghapi.Permissions{ // [org, remediate]
		{true, false}:  {"organization_administration": "write", "organization_custom_properties": "read", "organization_plan": "read", "metadata": "read"},
		{true, true}:   {"organization_administration": "write", "organization_custom_properties": "admin", "organization_plan": "read", "administration": "write", "metadata": "read"},
		{false, false}: {"metadata": "read"},
		{false, true}:  {"administration": "write", "metadata": "read"},
	}
)

func TestEachGitHubCallerAsksOnlyForItsPermissions(t *testing.T) {
	for mode, wantGov := range wantGovernance {
		org, remediate := mode[0], mode[1]
		gh := ghapitest.NewServer(t, "acme", http.NotFoundHandler())
		tokens := newGitHubTokens(gh.App(), org, remediate)
		sources := map[string]*ghapi.TokenSource{
			"rightsizing": tokens.rightsizing, "admission": tokens.admission, "promotion": tokens.promotion,
			"governance": tokens.governance, "alerts": tokens.alerts, "leaks": tokens.leaks, "templates": tokens.templates,
			"decisions": tokens.decisions, "catalog": tokens.catalog, "catchup": tokens.catchup,
		}
		want := maps.Clone(wantPermissions)
		want["governance"] = wantGov
		if len(sources) != len(want) {
			t.Fatalf("%d token sources, %d expected", len(sources), len(want))
		}
		for name, src := range sources {
			before := len(gh.Asked())
			if _, err := src.Token(t.Context()); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			asked := gh.Asked()
			if len(asked) != before+1 {
				t.Fatalf("%s: %d mints, want 1", name, len(asked)-before)
			}
			if got := asked[len(asked)-1]; !maps.Equal(got, want[name]) {
				t.Errorf("org=%v remediate=%v %s asked %v, want exactly %v", org, remediate, name, got, want[name])
			}
		}
	}
}

func TestGitHubAppConfig(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	app := map[string]string{"KEEL_GITHUB_APP_ID": "123", "KEEL_GITHUB_APP_INSTALLATION_ID": "77", "KEEL_GITHUB_APP_PRIVATE_KEY": pemKey}
	for _, c := range []struct {
		name    string
		env     map[string]string
		enabled bool
		errHas  string
	}{
		{"no github integration", nil, false, ""},
		{"owner without the app", map[string]string{"KEEL_GITHUB_OWNER": "acme"}, false, "KEEL_GITHUB_APP_ID"},
		{"webhook without the app", map[string]string{"KEEL_GITHUB_WEBHOOK_SECRET": "s"}, false, "KEEL_GITHUB_APP_PRIVATE_KEY"},
		{"templates without the app", map[string]string{"KEEL_TEMPLATES": "svc=acme/tpl@abc"}, false, "KEEL_GITHUB_APP_INSTALLATION_ID"},
		{"app without an owner", app, false, "KEEL_GITHUB_OWNER"},
		{"partial app", map[string]string{"KEEL_GITHUB_OWNER": "acme", "KEEL_GITHUB_APP_ID": "123"}, false, "KEEL_GITHUB_APP_PRIVATE_KEY"},
		{"bad installation id", merge(app, map[string]string{"KEEL_GITHUB_OWNER": "acme", "KEEL_GITHUB_APP_INSTALLATION_ID": "x"}), false, "KEEL_GITHUB_APP_INSTALLATION_ID"},
		{"bad key", merge(app, map[string]string{"KEEL_GITHUB_OWNER": "acme", "KEEL_GITHUB_APP_PRIVATE_KEY": "nope"}), false, "KEEL_GITHUB_APP_PRIVATE_KEY"},
		{"configured", merge(app, map[string]string{"KEEL_GITHUB_OWNER": "acme"}), true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range []string{"KEEL_GITHUB_OWNER", "KEEL_GITHUB_WEBHOOK_SECRET", "KEEL_TEMPLATES", "KEEL_GITHUB_APP_ID", "KEEL_GITHUB_APP_INSTALLATION_ID", "KEEL_GITHUB_APP_PRIVATE_KEY"} {
				t.Setenv(k, c.env[k])
			}
			got, err := githubApp(nil)
			if c.errHas != "" {
				if err == nil || !strings.Contains(err.Error(), c.errHas) {
					t.Fatalf("error %v, want one naming %s", err, c.errHas)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (got != nil) != c.enabled {
				t.Fatalf("app %+v, want enabled=%v", got, c.enabled)
			}
			if c.enabled && (got.ID != "123" || got.Installation != 77 || got.Owner != "acme" || got.Key == nil) {
				t.Fatalf("app %+v", got)
			}
		})
	}
}

func merge(a, b map[string]string) map[string]string {
	out := maps.Clone(a)
	maps.Copy(out, b)
	return out
}

// No personal access token is read, configured or documented as config.
// ADR-0020 and the delivery runbook name them only for their revocation.
func TestNoGitHubPersonalAccessTokenRemains(t *testing.T) {
	names := []string{"KEEL_GITHUB_" + "ADMIN_TOKEN", "KEEL_GITHUB_" + "WRITE_TOKEN", "KEEL_GITHUB_" + "TOKEN"}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"docs/adr/0020-github-app-key-exception.md": true, "docs/runbooks/delivery.md": true}
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if allowed[filepath.ToSlash(rel)] {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for _, n := range names {
			if strings.Contains(string(b), n) {
				t.Errorf("%s mentions %s", rel, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned %d files under %s; the walk missed the repository", scanned, root)
	}
}
