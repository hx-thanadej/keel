package ghalerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
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
	// All GitHub calls happen before any write.
	code, codeErr := s.fetchCode(ctx, tenant, v.id, repo)
	deps, depErr := s.Source.Dependabot(ctx, repo)
	secrets, secErr := s.Source.SecretScanning(ctx, repo)
	st.CodeScanning, st.Dependabot, st.SecretScanning = status(codeErr), status(depErr), status(secErr)

	var raised, resolved int
	codeDetail := detailStatus(st.CodeScanning, codeErr)
	if codeErr == nil {
		r, n, err := s.applyCode(ctx, tenant, v.id, code)
		if err != nil {
			return st, err
		}
		raised += r
		resolved += n
		codeDetail += " " + code.summary()
	}
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		type group struct {
			ok    bool
			items []item
			tool  string
		}
		for _, g := range []group{
			{ok: depErr == nil, items: dependabotItems(deps, v.id), tool: toolDependabot},
			{ok: secErr == nil, items: secretItems(secrets, repoKey), tool: toolSecrets},
		} {
			if !g.ok {
				continue // unknown, not clean: keep what we have
			}
			current := []string{}
			for _, it := range g.items {
				current = append(current, it.fingerprint)
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
			n, err := scans.ResolveAbsent(ctx, tx, v.id, g.tool, current)
			if err != nil {
				return err
			}
			resolved += n
		}
		detail := fmt.Sprintf("%s: code scanning %s, dependabot %s (%d), secret scanning %s (%d); %d new, %d resolved",
			repo, codeDetail, detailStatus(st.Dependabot, depErr), len(deps),
			detailStatus(st.SecretScanning, secErr), len(secrets), raised, resolved)
		_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/ghalerts", Type: "keel.ghalerts.synced", Subject: "service/" + v.id,
			Operation: "SyncGitHubAlerts", Kind: activity.Update, Actor: keelActor, Outcome: activity.Success,
			Resources:    []activity.Resource{{Type: "service", UID: v.id, OwnerTeam: v.team}},
			StatusDetail: detail})
		return err
	})
	res.Raised += raised
	res.Resolved += resolved
	return st, err
}

// codeScan is what one sync fetched from GitHub code scanning.
type codeScan struct {
	ingest    []toolSARIF      // tools with an analysis Keel has not ingested
	unchanged []string         // tools whose latest analyses Keel already ingested
	failed    []string         // tools whose latest analysis failed on GitHub: left as they are
	dismissed []DismissedAlert // alerts dismissed on GitHub
}

// toolSARIF is the latest analysis of every category of one tool, merged
// into one SARIF log so a full ingest never resolves another category's
// results.
type toolSARIF struct {
	tool           string
	ids            []int64
	categories     []string // set when the analyses list was truncated: resolve only these
	commitSHA, ref string
	sarif          []byte
	dismissed      []string // fingerprints of results dismissed on GitHub
}

func (c codeScan) summary() string {
	var parts []string
	for _, t := range c.ingest {
		parts = append(parts, fmt.Sprintf("ingested %s (%d analyses)", t.tool, len(t.ids)))
	}
	if len(c.unchanged) > 0 {
		parts = append(parts, "unchanged "+strings.Join(c.unchanged, ", "))
	}
	if len(c.failed) > 0 {
		parts = append(parts, "kept "+strings.Join(c.failed, ", ")+": latest analysis failed on GitHub")
	}
	parts = append(parts, fmt.Sprintf("%d dismissed on GitHub", len(c.dismissed)))
	return "(" + strings.Join(parts, "; ") + ")"
}

// fetchCode reads the latest analysis per tool and category and downloads
// the SARIF of each tool with an analysis Keel has not ingested yet. Any
// failed call fails the whole alert type, so nothing is resolved on a
// partial view.
func (s Syncer) fetchCode(ctx context.Context, tenant, service, repo string) (codeScan, error) {
	var c codeScan
	analyses, truncated, err := s.Source.Analyses(ctx, repo)
	if err != nil {
		return c, err
	}
	if c.dismissed, err = s.Source.DismissedCodeAlerts(ctx, repo); err != nil {
		return c, err
	}
	ids := make([]int64, 0, len(analyses))
	byTool := map[string][]Analysis{}
	var tools []string
	for _, a := range analyses {
		ids = append(ids, a.ID)
		if byTool[a.Tool] == nil {
			tools = append(tools, a.Tool)
		}
		byTool[a.Tool] = append(byTool[a.Tool], a)
	}
	var seen map[int64]bool
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT a FROM scan_runs, unnest(github_analysis_ids) AS a WHERE service_id = $1 AND a = ANY ($2)`, service, ids)
		if err != nil {
			return err
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		seen = map[int64]bool{}
		for _, id := range got {
			seen[id] = true
		}
		return err
	}); err != nil {
		return c, err
	}
	for _, tool := range tools {
		as := byTool[tool]
		if slices.ContainsFunc(as, func(a Analysis) bool { return a.Error != "" }) {
			c.failed = append(c.failed, tool)
			continue
		}
		if !slices.ContainsFunc(as, func(a Analysis) bool { return !seen[a.ID] }) {
			c.unchanged = append(c.unchanged, tool)
			continue
		}
		t := toolSARIF{tool: tool}
		var runs []map[string]any
		var newest time.Time
		for _, a := range as {
			raw, err := s.Source.SARIF(ctx, repo, a.ID)
			if err != nil {
				return c, err
			}
			var log struct {
				Runs []map[string]any `json:"runs"`
			}
			if err := json.Unmarshal(raw, &log); err != nil {
				return c, fmt.Errorf("analysis %d: not SARIF JSON: %w", a.ID, err)
			}
			for _, run := range log.Runs {
				// The category GitHub filed the analysis under, as SARIF writes it.
				run["automationDetails"] = map[string]any{"id": a.Category + "/"}
				runs = append(runs, run)
			}
			if truncated {
				// A category outside the window may still exist: its Findings stay open.
				t.categories = append(t.categories, a.Category)
			}
			t.ids = append(t.ids, a.ID)
			if a.CreatedAt.After(newest) {
				newest, t.commitSHA, t.ref = a.CreatedAt, a.CommitSHA, a.Ref
			}
		}
		if t.sarif, err = json.Marshal(map[string]any{"version": "2.1.0", "runs": runs}); err != nil {
			return c, err
		}
		got, results, err := scans.ParseSARIF(t.sarif, service)
		// A full scan resolves per tool, so the SARIF must name only this one.
		if err == nil && (len(got) == 0 || slices.ContainsFunc(got, func(g string) bool { return g != tool })) {
			err = fmt.Errorf("SARIF runs are %v, want %s only", got, tool)
		}
		if err != nil {
			return c, fmt.Errorf("%s analyses %v: %w", tool, t.ids, err)
		}
		for _, r := range results {
			locs, _ := r.Detail["locations"].([]string)
			if slices.ContainsFunc(c.dismissed, func(d DismissedAlert) bool { return d.covers(tool, r.RuleID, locs) }) {
				t.dismissed = append(t.dismissed, r.Fingerprint)
			}
		}
		c.ingest = append(c.ingest, t)
	}
	return c, nil
}

// applyCode resolves the Findings of alerts dismissed on GitHub, then
// ingests each new SARIF as a full scan of its tool. Dismissals go first so
// their Findings carry GitHub's reason, and the ingest leaves dismissed
// results out so it never raises them again.
func (s Syncer) applyCode(ctx context.Context, tenant, service string, c codeScan) (raised, resolved int, err error) {
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		for _, d := range c.dismissed {
			n, err := dismiss(ctx, tx, service, d)
			if err != nil {
				return err
			}
			resolved += n
		}
		return nil
	}); err != nil {
		return 0, 0, err
	}
	for _, t := range c.ingest {
		run, err := scans.Service{Store: s.Store}.Ingest(ctx, tenant, service, scans.Upload{Scope: "full", CommitSHA: t.commitSHA, Ref: t.ref,
			SARIF: t.sarif, Dismissed: t.dismissed, GitHubAnalysisIDs: t.ids, Categories: t.categories}, keelActor)
		if err != nil {
			return 0, 0, fmt.Errorf("%s analyses %v: %w", t.tool, t.ids, err)
		}
		raised += run.Raised
		resolved += run.Resolved
	}
	return raised, resolved, nil
}

// covers reports whether d is the alert of a result of tool and rule at one
// of locs (a Finding's detail.locations).
func (d DismissedAlert) covers(tool, rule string, locs []string) bool {
	return d.Tool == tool && d.RuleID == rule && slices.ContainsFunc(locs, func(l string) bool { return d.Location.Matches(scans.ParseLocation(l)) })
}

// dismiss takes d's tool off the open Findings at its rule and location and
// resolves those no other tool still reports.
func dismiss(ctx context.Context, tx pgx.Tx, service string, d DismissedAlert) (int, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, coalesce(detail->'locations', '[]') FROM findings
		WHERE service_id = $1 AND status = 'open' AND detail->'tools' ? $2 AND detail->>'rule_id' = $3`, service, d.Tool, d.RuleID)
	if err != nil {
		return 0, err
	}
	var id string
	var locs []string
	var ids []string
	if _, err := pgx.ForEachRow(rows, []any{&id, &locs}, func() error {
		if d.covers(d.Tool, d.RuleID, locs) {
			ids = append(ids, id)
		}
		return nil
	}); err != nil || len(ids) == 0 {
		return 0, err
	}
	var n int
	err = tx.QueryRow(ctx, `WITH d AS (UPDATE findings SET
		    detail = jsonb_set(detail, '{tools}', (detail->'tools') - $1),
		    status = CASE WHEN (detail->'tools') - $1 = '[]' THEN 'resolved' ELSE status END,
		    resolved_at = CASE WHEN (detail->'tools') - $1 = '[]' THEN now() ELSE resolved_at END,
		    resolution = CASE WHEN (detail->'tools') - $1 = '[]' THEN $3 ELSE resolution END
		WHERE id = ANY ($2::uuid[])
		RETURNING status)
		SELECT count(*) FILTER (WHERE status = 'resolved') FROM d`, d.Tool, ids, "dismissed on GitHub: "+d.Reason).Scan(&n)
	return n, err
}

// detailStatus is a status as the Activity shows it, with a short reason
// for an error.
func detailStatus(st string, err error) string {
	if st == StatusError {
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

// upsert raises the Finding or adds the alert's tool to an existing one, so
// a CVE Trivy also reports stays one Finding.
func upsert(ctx context.Context, tx pgx.Tx, tenant string, v svcRow, it item) (bool, error) {
	it.detail["tools"] = []string{it.tool}
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
		    detail = findings.detail || jsonb_build_object(
		        'tools', (SELECT jsonb_agg(DISTINCT t) FROM jsonb_array_elements(coalesce(findings.detail->'tools', '[]') || (excluded.detail->'tools')) AS t)),
		    severity = CASE WHEN array_position(ARRAY['critical','high','medium','low'], excluded.severity) < array_position(ARRAY['critical','high','medium','low'], findings.severity)
		                    THEN excluded.severity ELSE findings.severity END
		RETURNING (xmax = 0)`, tenant, it.kind, it.fingerprint, it.severity, title, detail, v.project, v.team, v.id).Scan(&inserted)
	return inserted, err
}
