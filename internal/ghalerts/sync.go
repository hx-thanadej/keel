package ghalerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/apply"
	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/store"
)

// Per alert type fetch status, recorded per Service.
const (
	StatusOK         = "ok"
	StatusNotEnabled = "not_enabled"
	StatusForbidden  = "forbidden"
	StatusError      = "error"
	// StatusSARIF: the fetch worked, but CI uploads SARIF for some of the
	// code scanning tools, so CI is their only source and their GitHub
	// alerts were skipped.
	StatusSARIF = "sarif"
)

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:ghalerts"}

// Syncer pulls open GitHub alerts for every Service with a repository.
type Syncer struct {
	Store  *store.Store
	Source Source
	Now    func() time.Time
}

// ServiceStatus is what one sync learned about one Service. A status other
// than ok means the alert type is unknown, not clean: nothing is resolved.
type ServiceStatus struct {
	Tenant         string `json:"tenant"`
	Service        string `json:"service"`
	Repository     string `json:"repository"`
	CodeScanning   string `json:"code_scanning"`
	Dependabot     string `json:"dependabot"`
	SecretScanning string `json:"secret_scanning"`
}

// Result is the outcome of one Run.
type Result struct {
	Services int             `json:"services"`
	Raised   int             `json:"raised"`
	Resolved int             `json:"resolved"`
	Statuses []ServiceStatus `json:"statuses"`
}

type svcRow struct {
	id, slug, project, team, repo string
	repoID                        *int64
}

// Run syncs every non-archived Service of every Tenant. A failing alert
// type is reported in the result, not fatal, so one repository without
// Advanced Security does not stop the rest.
func (s Syncer) Run(ctx context.Context) (Result, error) {
	var res Result
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return res, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return res, err
	}
	for _, tenant := range tenants {
		var svcs []svcRow
		if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT id::text, slug, project_id::text, team_id::text, repository, repository_id FROM services
				WHERE archived_at IS NULL AND repository <> '' ORDER BY slug`)
			if err != nil {
				return err
			}
			svcs, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (svcRow, error) {
				var v svcRow
				err := r.Scan(&v.id, &v.slug, &v.project, &v.team, &v.repo, &v.repoID)
				return v, err
			})
			return err
		}); err != nil {
			return res, err
		}
		for _, v := range svcs {
			repo, ok := normaliseRepo(v.repo)
			if !ok {
				continue // not a GitHub repository
			}
			st, err := s.syncService(ctx, tenant, v, repo, &res)
			if err != nil {
				return res, fmt.Errorf("sync %s: %w", v.slug, err)
			}
			res.Services++
			res.Statuses = append(res.Statuses, st)
		}
	}
	return res, nil
}

// normaliseRepo turns "owner/name", "github.com/owner/name" or a GitHub URL
// into "owner/name".
func normaliseRepo(r string) (string, bool) {
	r = strings.TrimSpace(r)
	if !strings.Contains(r, "://") && strings.HasPrefix(r, "github.com/") {
		r = "https://" + r
	}
	if strings.Contains(r, "://") {
		if u, err := url.Parse(r); err != nil || u.Host != "github.com" {
			return "", false
		}
		repo, err := apply.Repo(r)
		return repo, err == nil
	}
	return r, plainRepo.MatchString(r)
}

var plainRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// status maps a fetch error to a recorded status.
func status(err error) string {
	switch {
	case err == nil:
		return StatusOK
	case errors.Is(err, ErrNotEnabled):
		return StatusNotEnabled
	case errors.Is(err, ErrForbidden):
		return StatusForbidden
	}
	return StatusError
}

func (s Syncer) syncService(ctx context.Context, tenant string, v svcRow, repo string, res *Result) (ServiceStatus, error) {
	st := ServiceStatus{Tenant: tenant, Service: v.slug, Repository: repo}
	repoKey := repo
	if v.repoID != nil {
		repoKey = fmt.Sprint(*v.repoID) // immutable, survives renames
	}
	// All GitHub calls happen before the transaction.
	code, codeErr := s.Source.CodeScanning(ctx, repo)
	deps, depErr := s.Source.Dependabot(ctx, repo)
	secrets, secErr := s.Source.SecretScanning(ctx, repo)
	st.CodeScanning, st.Dependabot, st.SecretScanning = status(codeErr), status(depErr), status(secErr)

	var raised, resolved int
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		type group struct {
			ok    bool
			items []item
			tools []string // tools this type reports as; each is resolved separately
		}
		ciTools, err := sarifTools(ctx, tx, v.id)
		if err != nil {
			return err
		}
		var handovers []string
		handOver := func(tool string, to scans.Source) error {
			n, err := scans.HandOver(ctx, tx, v.id, tool, to)
			if n > 0 {
				dir := "GitHub to CI"
				if to == scans.SourceGitHub {
					dir = "CI to GitHub"
				}
				handovers = append(handovers, fmt.Sprintf("%s handed over from %s (%d)", tool, dir, n))
				resolved += n
			}
			return err
		}
		for _, tool := range sortedKeys(ciTools) {
			if err := handOver(tool, scans.SourceCI); err != nil {
				return err
			}
		}
		code, skipped := splitByTool(code, ciTools)
		if codeErr == nil && len(skipped) > 0 {
			st.CodeScanning = StatusSARIF
		}
		cs := group{ok: codeErr == nil, items: codeItems(code, v.id)}
		cs.tools = distinctTools(cs.items)
		if cs.ok {
			for _, tool := range cs.tools {
				if err := handOver(tool, scans.SourceGitHub); err != nil {
					return err
				}
			}
			known, err := githubTools(ctx, tx, v.id)
			if err != nil {
				return err
			}
			cs.tools = without(union(cs.tools, known), ciTools)
		}
		groups := []group{cs,
			{ok: depErr == nil, items: dependabotItems(deps, v.id), tools: []string{toolDependabot}},
			{ok: secErr == nil, items: secretItems(secrets, repoKey), tools: []string{toolSecrets}}}
		for _, g := range groups {
			if !g.ok {
				continue // unknown, not clean: keep what we have
			}
			byTool := map[string][]string{}
			for _, it := range g.items {
				byTool[it.tool] = append(byTool[it.tool], it.fingerprint)
				if it.vuln != "" {
					var suppressed bool
					if err := tx.QueryRow(ctx, `SELECT vex_suppressed($1, $2)`, it.vuln, v.id).Scan(&suppressed); err != nil {
						return err
					}
					if suppressed {
						continue // a VEX statement says this Service is not affected
					}
				}
				created, err := upsert(ctx, tx, tenant, v, it)
				if err != nil {
					return err
				}
				if created {
					raised++
				}
			}
			for _, tool := range g.tools {
				n, err := resolveAbsent(ctx, tx, v.id, tool, byTool[tool])
				if err != nil {
					return err
				}
				resolved += n
			}
		}
		detail := fmt.Sprintf("%s: code scanning %s (%d), dependabot %s (%d), secret scanning %s (%d); %d new, %d resolved",
			repo, detailStatus(st.CodeScanning, codeErr, skipped), len(code), detailStatus(st.Dependabot, depErr, nil), len(deps),
			detailStatus(st.SecretScanning, secErr, nil), len(secrets), raised, resolved)
		if len(handovers) > 0 {
			detail += "; " + strings.Join(handovers, ", ")
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/ghalerts", Type: "keel.ghalerts.synced", Subject: "service/" + v.id,
			Operation: "SyncGitHubAlerts", Kind: activity.Update, Actor: keelActor, Outcome: activity.Success,
			Resources:    []activity.Resource{{Type: "service", UID: v.id, OwnerTeam: v.team}},
			StatusDetail: detail})
		return err
	})
	res.Raised += raised
	res.Resolved += resolved
	return st, err
}

// sarifTools lists the tools for which CI is the source (scans.Source): a
// full SARIF upload for the Service in the last 30 days. A diff upload
// resolves nothing, so it never takes a tool over.
func sarifTools(ctx context.Context, tx pgx.Tx, service string) (map[string]bool, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT t FROM scan_runs, unnest(string_to_array(tool, ',')) AS t
		WHERE service_id = $1 AND scope = 'full' AND created_at > now() - interval '30 days'`, service)
	if err != nil {
		return nil, err
	}
	tools, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := map[string]bool{}
	for _, t := range tools {
		out[t] = true
	}
	return out, err
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// splitByTool separates the alerts of tools CI already uploads.
func splitByTool(alerts []CodeAlert, ci map[string]bool) (keep []CodeAlert, skipped map[string]int) {
	for _, a := range alerts {
		if !ci[a.Tool] {
			keep = append(keep, a)
			continue
		}
		if skipped == nil {
			skipped = map[string]int{}
		}
		skipped[a.Tool]++
	}
	return keep, skipped
}

func without(tools []string, drop map[string]bool) []string {
	var out []string
	for _, t := range tools {
		if !drop[t] {
			out = append(out, t)
		}
	}
	return out
}

// detailStatus is a status as the Activity shows it: which tools were left
// to CI, or a short reason for an error.
func detailStatus(st string, err error, skipped map[string]int) string {
	switch st {
	case StatusSARIF:
		tools := make([]string, 0, len(skipped))
		for t, n := range skipped {
			tools = append(tools, fmt.Sprintf("%d %s", n, t))
		}
		sort.Strings(tools)
		return fmt.Sprintf("%s (skipped %s: CI uploads SARIF)", st, strings.Join(tools, ", "))
	case StatusError:
		return fmt.Sprintf("%s (%s)", st, reason(err))
	}
	return st
}

// reason is a short, sanitised description of a fetch error: the HTTP
// status and GitHub's message, never the raw body.
func reason(err error) string {
	var r string
	var e *ghapi.Error
	switch {
	case errors.As(err, &e):
		var body struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal([]byte(e.Body), &body)
		r = fmt.Sprintf("HTTP %d", e.Status)
		if body.Message != "" {
			r += ": " + body.Message
		}
	case errors.Is(err, context.DeadlineExceeded):
		r = "timeout"
	case errors.Is(err, ErrTooManyPages):
		r = ErrTooManyPages.Error()
	default:
		r = "request failed"
	}
	r = strings.Map(func(c rune) rune {
		if unicode.IsControl(c) {
			return ' '
		}
		return c
	}, r)
	if rs := []rune(r); len(rs) > 120 {
		r = string(rs[:120])
	}
	return r
}

func distinctTools(items []item) []string {
	var out []string
	for _, it := range items {
		out = union(out, []string{it.tool})
	}
	return out
}

func union(a, b []string) []string {
	for _, x := range b {
		found := false
		for _, y := range a {
			found = found || x == y
		}
		if !found {
			a = append(a, x)
		}
	}
	return a
}

// githubTools lists the code scanning tools GitHub has reported for the
// Service's open Findings, so a tool whose alerts all disappeared still
// gets its Findings resolved even though this fetch no longer names it.
func githubTools(ctx context.Context, tx pgx.Tx, service string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT t FROM findings, jsonb_array_elements_text(detail->'github_tools') AS t
		WHERE service_id = $1 AND status = 'open' AND jsonb_typeof(detail->'github_tools') = 'array' AND t NOT IN ($2, $3)`, service, toolDependabot, toolSecrets)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// upsert raises the Finding or adds GitHub to an existing one. detail.tools
// merges with other scanners; detail.github_tools records which tools GitHub
// itself reported, so resolution never strips a tool that only CI reports.
func upsert(ctx context.Context, tx pgx.Tx, tenant string, v svcRow, it item) (bool, error) {
	it.detail["tools"] = []string{it.tool}
	it.detail["github_tools"] = []string{it.tool}
	it.detail["source"] = "github"
	it.detail["service"] = v.slug
	detail, err := json.Marshal(it.detail)
	if err != nil {
		return false, err
	}
	title := fmt.Sprintf("%s in %s: %s", it.rule, v.slug, it.title)
	var inserted bool
	err = tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, owner_team_id, service_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET
		    last_seen_at = now(),
		    detail = CASE WHEN findings.detail->>'source' = 'github' THEN findings.detail || excluded.detail ELSE findings.detail END
		        || jsonb_build_object(
		            'tools', (SELECT jsonb_agg(DISTINCT t) FROM jsonb_array_elements(coalesce(findings.detail->'tools', '[]') || (excluded.detail->'tools')) AS t),
		            'github_tools', (SELECT jsonb_agg(DISTINCT t) FROM jsonb_array_elements(coalesce(findings.detail->'github_tools', '[]') || (excluded.detail->'github_tools')) AS t)),
		    severity = CASE WHEN array_position(ARRAY['critical','high','medium','low'], excluded.severity) < array_position(ARRAY['critical','high','medium','low'], findings.severity)
		                    THEN excluded.severity ELSE findings.severity END
		RETURNING (xmax = 0)`, tenant, it.kind, it.fingerprint, it.severity, title, detail, v.project, v.team, v.id).Scan(&inserted)
	return inserted, err
}

// resolveAbsent resolves the Service's open Findings that GitHub reported
// under tool but no longer lists. Findings that GitHub never reported under
// that tool (a CI scan by a tool with the same name) are passed to
// scans.ResolveAbsent as "current" so they are left alone.
func resolveAbsent(ctx context.Context, tx pgx.Tx, service, tool string, current []string) (int, error) {
	if current == nil {
		current = []string{} // a nil slice is SQL NULL
	}
	keep := append([]string{}, current...)
	rows, err := tx.Query(ctx, `SELECT fingerprint FROM findings WHERE service_id = $1 AND status = 'open'
		AND NOT (coalesce(detail->'github_tools', '[]') ? $2)`, service, tool)
	if err != nil {
		return 0, err
	}
	others, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	keep = append(keep, others...)
	n, err := scans.ResolveAbsent(ctx, tx, service, tool, keep)
	if err != nil {
		return 0, err
	}
	// Findings still open for other tools no longer carry this one from GitHub.
	_, err = tx.Exec(ctx, `UPDATE findings SET detail = jsonb_set(detail, '{github_tools}', (detail->'github_tools') - $2)
		WHERE service_id = $1 AND status = 'open' AND detail->'github_tools' ? $2 AND NOT (fingerprint = ANY ($3::text[]))`, service, tool, current)
	return n, err
}
