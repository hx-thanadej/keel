// Package ghalerts syncs GitHub's own code scanning, Dependabot and secret
// scanning alerts into Findings (#121), so teams that rely on GitHub's
// scanners see them in the same inbox, with the same SLAs, as CI scans.
package ghalerts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hx-thanadej/keel/internal/ghapi"
)

// Fetch failures that mean "unknown", never "no alerts".
var (
	// ErrNotEnabled: the scanner is not enabled for the repository (for
	// private repositories that needs GitHub Advanced Security / Code
	// Security / Secret Protection).
	ErrNotEnabled = errors.New("not enabled for this repository")
	// ErrForbidden: the token may not read these alerts.
	ErrForbidden = errors.New("token may not read these alerts")
	// ErrTooManyPages: the list did not end within maxPages pages.
	ErrTooManyPages = fmt.Errorf("more than %d pages", maxPages)
)

// Analysis is GitHub's latest code scanning analysis of one tool and
// category on the repository's default branch.
type Analysis struct {
	ID        int64
	Tool      string // lowercased, as SARIF ingest names tools
	Category  string
	CommitSHA string
	Ref       string
	CreatedAt time.Time
	Error     string // GitHub's error for a failed analysis, else ""
}

// DismissedAlert is a code scanning alert dismissed on GitHub. Location is
// "path:line", as SARIF ingest writes a Finding's locations.
type DismissedAlert struct {
	Tool, RuleID, Location, Reason string
}

// DependabotAlert is an open Dependabot alert.
type DependabotAlert struct {
	Number       int
	GHSA, CVE    string
	Summary      string
	Severity     string
	Ecosystem    string
	Package      string
	ManifestPath string
}

// SecretAlert is an open secret scanning alert. It deliberately has no
// field for the secret value.
type SecretAlert struct {
	Number      int
	Type        string
	DisplayName string
	URL         string
}

// Source reads one repository ("owner/name") on GitHub.
type Source interface {
	Analyses(ctx context.Context, repo string) ([]Analysis, error)
	// SARIF downloads an analysis as the SARIF GitHub holds for it.
	SARIF(ctx context.Context, repo string, analysis int64) ([]byte, error)
	DismissedCodeAlerts(ctx context.Context, repo string) ([]DismissedAlert, error)
	Dependabot(ctx context.Context, repo string) ([]DependabotAlert, error)
	SecretScanning(ctx context.Context, repo string) ([]SecretAlert, error)
}

// GitHub is a Source on the REST API. The token needs read access to code
// scanning alerts (which covers analyses), Dependabot alerts and secret
// scanning alerts.
type GitHub struct {
	Client ghapi.Client
}

const (
	perPage  = 100
	maxPages = 100
)

// list fetches every item of a list endpoint into T, following the Link
// header: Dependabot alerts page only by cursor, and the others accept it
// too. At maxPages it returns what it read with ErrTooManyPages.
func list[T any](ctx context.Context, c ghapi.Client, path, query string) ([]T, error) {
	var all []T
	next := fmt.Sprintf("%s?per_page=%d&%s", path, perPage, query)
	for range maxPages {
		var got []T
		var err error
		next, err = c.DoList(ctx, next, &got)
		if err != nil {
			return nil, classify(err)
		}
		all = append(all, got...)
		if next == "" {
			return all, nil
		}
	}
	return all, fmt.Errorf("%s: %w", path, ErrTooManyPages)
}

// classify maps GitHub's "this feature is off" responses to ErrNotEnabled
// and other refusals to ErrForbidden; anything else is returned as is.
func classify(err error) error {
	st := ghapi.Status(err)
	if st != http.StatusForbidden && st != http.StatusNotFound {
		return err
	}
	var e *ghapi.Error
	_ = errors.As(err, &e)
	body := strings.ToLower(e.Body)
	for _, marker := range []string{"not enabled", "disabled", "advanced security", "code security", "secret protection", "no analysis found"} {
		if strings.Contains(body, marker) {
			return fmt.Errorf("%w: %v", ErrNotEnabled, err)
		}
	}
	return fmt.Errorf("%w: %v", ErrForbidden, err)
}

// Analyses implements Source: the newest analysis per tool and category
// on the default branch. GitHub lists analyses newest first and keeps every
// one, so only the newest maxPages pages are read: a category not analysed
// within them counts as gone.
func (g GitHub) Analyses(ctx context.Context, repo string) ([]Analysis, error) {
	var r struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := g.Client.Do(ctx, http.MethodGet, "/repos/"+repo, nil, &r); err != nil {
		return nil, classify(err)
	}
	if r.DefaultBranch == "" {
		return nil, fmt.Errorf("%s has no default branch", repo)
	}
	type wire struct {
		ID        int64     `json:"id"`
		Ref       string    `json:"ref"`
		CommitSHA string    `json:"commit_sha"`
		Category  string    `json:"category"`
		Error     string    `json:"error"`
		CreatedAt time.Time `json:"created_at"`
		Tool      struct {
			Name string `json:"name"`
		} `json:"tool"`
	}
	raw, err := list[wire](ctx, g.Client, "/repos/"+repo+"/code-scanning/analyses",
		"direction=desc&sort=created&ref="+url.QueryEscape("refs/heads/"+r.DefaultBranch))
	if err != nil && !errors.Is(err, ErrTooManyPages) {
		return nil, err
	}
	latest := map[[2]string]Analysis{}
	for _, w := range raw {
		a := Analysis{ID: w.ID, Tool: strings.ToLower(w.Tool.Name), Category: w.Category, CommitSHA: w.CommitSHA, Ref: w.Ref, CreatedAt: w.CreatedAt, Error: w.Error}
		k := [2]string{a.Tool, a.Category}
		if old, ok := latest[k]; !ok || a.CreatedAt.After(old.CreatedAt) {
			latest[k] = a
		}
	}
	out := make([]Analysis, 0, len(latest))
	for _, a := range latest {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		return out[i].Category < out[j].Category
	})
	return out, nil
}

// SARIF implements Source.
func (g GitHub) SARIF(ctx context.Context, repo string, analysis int64) ([]byte, error) {
	raw, err := g.Client.Get(ctx, fmt.Sprintf("/repos/%s/code-scanning/analyses/%d", repo, analysis), "application/sarif+json")
	if err != nil {
		return nil, classify(err)
	}
	return raw, nil
}

// DismissedCodeAlerts implements Source.
func (g GitHub) DismissedCodeAlerts(ctx context.Context, repo string) ([]DismissedAlert, error) {
	type wire struct {
		Rule struct {
			ID string `json:"id"`
		} `json:"rule"`
		Tool struct {
			Name string `json:"name"`
		} `json:"tool"`
		DismissedReason    string `json:"dismissed_reason"`
		MostRecentInstance struct {
			Location struct {
				Path      string `json:"path"`
				StartLine int    `json:"start_line"`
			} `json:"location"`
		} `json:"most_recent_instance"`
	}
	raw, err := list[wire](ctx, g.Client, "/repos/"+repo+"/code-scanning/alerts", "state=dismissed")
	if err != nil {
		return nil, err
	}
	out := make([]DismissedAlert, 0, len(raw))
	for _, w := range raw {
		loc := w.MostRecentInstance.Location.Path
		if n := w.MostRecentInstance.Location.StartLine; n > 0 {
			loc += ":" + strconv.Itoa(n)
		}
		out = append(out, DismissedAlert{Tool: strings.ToLower(w.Tool.Name), RuleID: w.Rule.ID, Location: loc, Reason: w.DismissedReason})
	}
	return out, nil
}

// Dependabot implements Source.
func (g GitHub) Dependabot(ctx context.Context, repo string) ([]DependabotAlert, error) {
	type wire struct {
		Number           int `json:"number"`
		SecurityAdvisory struct {
			GHSA     string `json:"ghsa_id"`
			CVE      string `json:"cve_id"`
			Summary  string `json:"summary"`
			Severity string `json:"severity"`
		} `json:"security_advisory"`
		Dependency struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			ManifestPath string `json:"manifest_path"`
		} `json:"dependency"`
	}
	raw, err := list[wire](ctx, g.Client, "/repos/"+repo+"/dependabot/alerts", "state=open")
	if err != nil {
		return nil, err
	}
	out := make([]DependabotAlert, 0, len(raw))
	for _, w := range raw {
		sev := strings.ToLower(w.SecurityAdvisory.Severity)
		if sev == "moderate" {
			sev = "medium"
		}
		out = append(out, DependabotAlert{Number: w.Number, GHSA: w.SecurityAdvisory.GHSA, CVE: w.SecurityAdvisory.CVE, Summary: w.SecurityAdvisory.Summary,
			Severity: sev, Ecosystem: w.Dependency.Package.Ecosystem, Package: w.Dependency.Package.Name, ManifestPath: w.Dependency.ManifestPath})
	}
	return out, nil
}

// SecretScanning implements Source. hide_secret keeps the secret value off
// the wire, and the wire type has no field for it either.
func (g GitHub) SecretScanning(ctx context.Context, repo string) ([]SecretAlert, error) {
	type wire struct {
		Number      int    `json:"number"`
		Type        string `json:"secret_type"`
		DisplayName string `json:"secret_type_display_name"`
		URL         string `json:"html_url"`
	}
	raw, err := list[wire](ctx, g.Client, "/repos/"+repo+"/secret-scanning/alerts", "state=open&hide_secret=true")
	if err != nil {
		return nil, err
	}
	out := make([]SecretAlert, 0, len(raw))
	for _, w := range raw {
		out = append(out, SecretAlert(w))
	}
	return out, nil
}
