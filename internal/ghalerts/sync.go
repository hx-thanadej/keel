package ghalerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
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
	// StatusKeel: the Service takes code scanning from CI's SARIF, so
	// GitHub code scanning is not synced.
	StatusKeel = "keel"
	// StatusNoRepositoryID: the Service takes code scanning from GitHub but
	// has no repository id to key its alerts by, so nothing is synced.
	StatusNoRepositoryID = "no_repository_id"
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
	codeSource                    string
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
			rows, err := tx.Query(ctx, `SELECT id::text, slug, project_id::text, team_id::text, repository, repository_id, code_scanning_source FROM services
				WHERE archived_at IS NULL AND repository <> '' ORDER BY slug`)
			if err != nil {
				return err
			}
			svcs, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (svcRow, error) {
				var v svcRow
				err := r.Scan(&v.id, &v.slug, &v.project, &v.team, &v.repo, &v.repoID, &v.codeSource)
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
	var code codeScan
	var codeErr error
	switch {
	case v.codeSource != scans.SourceGitHub:
		st.CodeScanning = StatusKeel
	case v.repoID == nil:
		st.CodeScanning = StatusNoRepositoryID
	default:
		code, codeErr = s.fetchCode(ctx, tenant, v, repo)
		st.CodeScanning = status(codeErr)
	}
	deps, depErr := s.Source.Dependabot(ctx, repo)
	secrets, secErr := s.Source.SecretScanning(ctx, repo)
	st.Dependabot, st.SecretScanning = status(depErr), status(secErr)

	var raised, resolved int
	codeDetail := detailStatus(st.CodeScanning, codeErr)
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if st.CodeScanning == StatusOK {
			// The lock orders this against SetCodeScanningSource, which
			// resolves GitHub's Findings when the Service leaves GitHub.
			if err := tx.QueryRow(ctx, `SELECT code_scanning_source FROM services WHERE id = $1 FOR SHARE`, v.id).Scan(&v.codeSource); err != nil {
				return err
			}
			if v.codeSource != scans.SourceGitHub {
				st.CodeScanning, codeDetail = StatusKeel, StatusKeel
			}
		}
		if st.CodeScanning == StatusOK {
			for _, a := range code.open {
				created, err := raise(ctx, tx, tenant, v, codeItem(a, *v.repoID))
				if err != nil {
					return err
				}
				if created {
					raised++
				}
			}
			for fp, resolution := range code.closed {
				tag, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now(), resolution = $3
					WHERE service_id = $1 AND fingerprint = $2 AND status = 'open'`, v.id, fp, resolution)
				if err != nil {
					return err
				}
				resolved += int(tag.RowsAffected())
			}
			codeDetail += fmt.Sprintf(" (%d open, %d closed)", len(code.open), len(code.closed))
		}
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
				created, err := raise(ctx, tx, tenant, v, it)
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

// codeScan is what one sync learned from GitHub code scanning.
type codeScan struct {
	open   []CodeAlert
	closed map[string]string // fingerprint of an open Finding whose alert closed → its resolution
}

// fetchCode lists the open alerts and looks up why each open Finding whose
// alert is no longer open closed. A Finding whose alert is in no list
// stays open unless both closed lists were read to the end.
func (s Syncer) fetchCode(ctx context.Context, tenant string, v svcRow, repo string) (codeScan, error) {
	c := codeScan{closed: map[string]string{}}
	var err error
	if c.open, err = s.Source.OpenCodeAlerts(ctx, repo); err != nil {
		return c, err
	}
	var findings []string
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT fingerprint FROM findings WHERE service_id = $1 AND status = 'open' AND detail->'tools' ? $2`, v.id, scans.GitHubCodeScanningTool)
		if err != nil {
			return err
		}
		findings, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil {
		return c, err
	}
	open := map[string]bool{}
	for _, a := range c.open {
		open[codeFingerprint(*v.repoID, a.Number)] = true
	}
	prefix := codePrefix(*v.repoID)
	byNumber := map[int]string{}
	for _, fp := range findings {
		if open[fp] {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(fp, prefix))
		if !strings.HasPrefix(fp, prefix) || err != nil {
			c.closed[fp] = "no longer on GitHub" // an alert of the Service's previous repository
			continue
		}
		byNumber[n] = fp
	}
	if len(byNumber) == 0 {
		return c, nil
	}
	closed, complete, err := s.Source.ClosedCodeAlerts(ctx, repo, slices.Sorted(maps.Keys(byNumber)))
	if err != nil {
		return c, err
	}
	for n, fp := range byNumber {
		a, ok := closed[n]
		switch {
		case ok && a.State == "dismissed":
			c.closed[fp] = "dismissed on GitHub: " + a.DismissedReason
		case ok:
			c.closed[fp] = a.State + " on GitHub"
		case complete:
			c.closed[fp] = "no longer on GitHub"
		}
	}
	return c, nil
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

// raise upserts it unless a VEX statement says the Service is not affected.
func raise(ctx context.Context, tx pgx.Tx, tenant string, v svcRow, it item) (bool, error) {
	if it.vuln != "" {
		var suppressed bool
		if err := tx.QueryRow(ctx, `SELECT vex_suppressed($1, $2)`, it.vuln, v.id).Scan(&suppressed); err != nil || suppressed {
			return false, err
		}
	}
	return upsert(ctx, tx, tenant, v, it)
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
	refresh := []byte("{}")
	if it.own {
		refresh = detail
	}
	title := fmt.Sprintf("%s in %s: %s", it.rule, v.slug, it.title)
	var inserted bool
	err = tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, owner_team_id, service_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET
		    last_seen_at = now(),
		    detail = findings.detail || $10::jsonb || jsonb_build_object(
		        'tools', (SELECT jsonb_agg(DISTINCT t) FROM jsonb_array_elements(coalesce(findings.detail->'tools', '[]') || (excluded.detail->'tools')) AS t)),
		    severity = CASE WHEN array_position(ARRAY['critical','high','medium','low'], excluded.severity) < array_position(ARRAY['critical','high','medium','low'], findings.severity)
		                    THEN excluded.severity ELSE findings.severity END
		RETURNING (xmax = 0)`, tenant, it.kind, it.fingerprint, it.severity, title, detail, v.project, v.team, v.id, refresh).Scan(&inserted)
	return inserted, err
}
