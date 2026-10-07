package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// Finding is one item in a Tenant's Findings inbox.
type Finding struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Severity      string          `json:"severity"`
	Status        string          `json:"status"`
	Title         string          `json:"title"`
	Detail        json.RawMessage `json:"detail"`
	ProjectID     *string         `json:"project_id"`
	EnvironmentID *string         `json:"environment_id"`
	OwnerTeamID   *string         `json:"owner_team_id"`
	FirstSeenAt   time.Time       `json:"first_seen_at"`
	LastSeenAt    time.Time       `json:"last_seen_at"`
	ResolvedAt    *time.Time      `json:"resolved_at"`
	Resolution    *string         `json:"resolution"`
	DueAt         *time.Time      `json:"due_at"`
	OverdueAt     *time.Time      `json:"overdue_at"`
}

const findingCols = `id::text, kind, severity, status, title, detail, project_id::text, environment_id::text, owner_team_id::text, first_seen_at, last_seen_at, resolved_at, resolution, due_at, overdue_at`

func mountFindings(mux Mux, a auth.Authenticator, c *catalog.Service, az catalog.Authorizer) {
	allow := func(r *http.Request, p auth.Principal, action, tenant string) error {
		d, err := az.Decide(r.Context(), authz.Request{Principal: p, Action: action, Resource: authz.Resource{Type: "finding", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !d.Allow {
			return catalog.ErrForbidden
		}
		return nil
	}
	mux.Handle("GET /v1/tenants/{tenant}/findings", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		if err := allow(r, p, "finding.read", tenant); err != nil {
			return err
		}
		status := r.URL.Query().Get("status")
		if status == "" {
			status = "open"
		}
		if status != "open" && status != "resolved" && status != "all" {
			return errors.Join(catalog.ErrInvalid, errors.New("status is open, resolved or all"))
		}
		q := r.URL.Query()
		owner := q.Get("owner")
		if owner != "" && !catalog.ValidID(owner) {
			return errors.Join(catalog.ErrInvalid, errors.New("owner must be a team uuid"))
		}
		overdue := q.Get("overdue") == "true"
		var out []Finding
		err := c.Store().InTenant(r.Context(), tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(r.Context(), `SELECT `+findingCols+` FROM findings
				WHERE ($1 = 'all' OR status = $1) AND ($2 = '' OR kind = $2) AND ($3 = '' OR owner_team_id::text = $3)
				  AND (NOT $4 OR (status = 'open' AND due_at < now()))
				ORDER BY (status = 'open' AND due_at < now()) DESC, array_position(ARRAY['critical','high','medium','low'], severity), due_at NULLS LAST, last_seen_at DESC LIMIT 200`,
				status, q.Get("kind"), owner, overdue)
			if err != nil {
				return err
			}
			out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Finding])
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("POST /v1/tenants/{tenant}/findings/{finding}/resolve", authed(a, []string{"tenant", "finding"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant, id := r.PathValue("tenant"), r.PathValue("finding")
		if err := allow(r, p, "finding.resolve", tenant); err != nil {
			return err
		}
		var in struct{ Resolution string }
		if err := decode(r, &in); err != nil {
			return err
		}
		if in.Resolution == "" {
			return errors.Join(catalog.ErrInvalid, errors.New("resolution is required"))
		}
		var f Finding
		err := c.Store().InTenant(r.Context(), tenant, func(tx pgx.Tx) error {
			err := tx.QueryRow(r.Context(), `UPDATE findings SET status = 'resolved', resolved_at = now(), resolution = $2
				WHERE id = $1 AND status = 'open' RETURNING `+findingCols, id, in.Resolution).
				Scan(&f.ID, &f.Kind, &f.Severity, &f.Status, &f.Title, &f.Detail, &f.ProjectID, &f.EnvironmentID, &f.OwnerTeamID, &f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.Resolution, &f.DueAt, &f.OverdueAt)
			if err != nil {
				return err
			}
			_, err = activity.Record(r.Context(), tx, activity.Activity{TenantID: tenant, Source: "keel/findings", Type: "keel.finding.resolved",
				Subject: "finding/" + id, Operation: "ResolveFinding", Kind: activity.Update, Actor: actor(p), Outcome: activity.Success,
				Resources: []activity.Resource{{Type: "finding", UID: id}}, Why: activity.Why{Reason: in.Resolution}})
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return catalog.ErrNotFound
		}
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, f)
		return nil
	}))
}
