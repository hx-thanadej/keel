// Package ghalerts syncs GitHub's own code scanning, Dependabot and secret
// scanning alerts into Findings (#121), so teams that rely on GitHub's
// scanners see them in the same inbox, with the same SLAs, as CI scans.
package ghalerts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

// CodeAlert is a GitHub code scanning alert, at its most recent instance.
type CodeAlert struct {
	Number          int
	State           string // open, dismissed or fixed
	DismissedReason string
	Tool            string // lowercased, as SARIF ingest names tools
	RuleID          string
	Severity        string
	Description     string
	Message         string
	Path            string
	Line            int
	URL             string
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
	OpenCodeAlerts(ctx context.Context, repo string) ([]CodeAlert, error)
	// ClosedCodeAlerts finds the alerts numbered numbers among the dismissed
	// and fixed ones. complete means both lists were read to the end (or
	// every number was found), so a number missing from closed is in neither.
	ClosedCodeAlerts(ctx context.Context, repo string, numbers []int) (closed map[int]CodeAlert, complete bool, err error)
	Dependabot(ctx context.Context, repo string) ([]DependabotAlert, error)
	SecretScanning(ctx context.Context, repo string) ([]SecretAlert, error)
}

// GitHub is a Source on the REST API. The token needs read access to code
// scanning alerts, Dependabot alerts and secret scanning alerts.
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
	err := walk(ctx, c, path, query, func(page []T) bool {
		all = append(all, page...)
		return true
	})
	return all, err
}

// walk hands each page of a list endpoint to page until page returns false
// or the list ends. At maxPages it stops with ErrTooManyPages.
func walk[T any](ctx context.Context, c ghapi.Client, path, query string, page func([]T) bool) error {
	next := fmt.Sprintf("%s?per_page=%d&%s", path, perPage, query)
	for range maxPages {
		var got []T
		var err error
		next, err = c.DoList(ctx, next, &got)
		if err != nil {
			return classify(err)
		}
		if !page(got) || next == "" {
			return nil
		}
	}
	return fmt.Errorf("%s: %w", path, ErrTooManyPages)
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

type codeAlertWire struct {
	Number          int    `json:"number"`
	State           string `json:"state"`
	DismissedReason string `json:"dismissed_reason"`
	HTMLURL         string `json:"html_url"`
	Rule            struct {
		ID                    string `json:"id"`
		Severity              string `json:"severity"`
		SecuritySeverityLevel string `json:"security_severity_level"`
		Description           string `json:"description"`
	} `json:"rule"`
	Tool struct {
		Name string `json:"name"`
	} `json:"tool"`
	MostRecentInstance struct {
		Location struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
		} `json:"location"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
	} `json:"most_recent_instance"`
}

func (w codeAlertWire) alert() CodeAlert {
	sev := strings.ToLower(w.Rule.SecuritySeverityLevel)
	if sev == "" {
		switch w.Rule.Severity {
		case "error":
			sev = "high"
		case "warning":
			sev = "medium"
		default:
			sev = "low"
		}
	}
	return CodeAlert{Number: w.Number, State: w.State, DismissedReason: w.DismissedReason, Tool: strings.ToLower(w.Tool.Name), RuleID: w.Rule.ID,
		Severity: sev, Description: w.Rule.Description, Message: w.MostRecentInstance.Message.Text,
		Path: w.MostRecentInstance.Location.Path, Line: w.MostRecentInstance.Location.StartLine, URL: w.HTMLURL}
}

// OpenCodeAlerts implements Source.
func (g GitHub) OpenCodeAlerts(ctx context.Context, repo string) ([]CodeAlert, error) {
	raw, err := list[codeAlertWire](ctx, g.Client, "/repos/"+repo+"/code-scanning/alerts", "state=open")
	if err != nil {
		return nil, err
	}
	out := make([]CodeAlert, 0, len(raw))
	for _, w := range raw {
		out = append(out, w.alert())
	}
	return out, nil
}

// ClosedCodeAlerts implements Source. Both lists are read most recently
// updated first, so an alert closed since the last sync is near the top and
// the walk stops once every number is found.
func (g GitHub) ClosedCodeAlerts(ctx context.Context, repo string, numbers []int) (map[int]CodeAlert, bool, error) {
	want := map[int]bool{}
	for _, n := range numbers {
		want[n] = true
	}
	closed := map[int]CodeAlert{}
	complete := true
	for _, state := range []string{"dismissed", "fixed"} {
		if len(closed) == len(want) {
			break
		}
		err := walk(ctx, g.Client, "/repos/"+repo+"/code-scanning/alerts", "state="+state+"&sort=updated&direction=desc", func(page []codeAlertWire) bool {
			for _, w := range page {
				if want[w.Number] {
					closed[w.Number] = w.alert()
				}
			}
			return len(closed) < len(want)
		})
		if errors.Is(err, ErrTooManyPages) {
			complete = false
			continue
		}
		if err != nil {
			return nil, false, err
		}
	}
	return closed, complete || len(closed) == len(want), nil
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
