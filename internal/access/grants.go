package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// GrantDecision is the policy's answer for a grant.
type GrantDecision struct {
	Allow     bool     `json:"allow"`
	Reasons   []string `json:"reasons"`
	Approvals []string `json:"approvals"`
	Policy    string   `json:"policy"`
}

// Approval is one approver's sign-off.
type Approval struct {
	Role string    `json:"role"`
	By   string    `json:"by"`
	At   time.Time `json:"at"`
}

// Grant is a time-boxed role assignment.
type Grant struct {
	ID          string        `json:"id"`
	RoleID      string        `json:"role_id"`
	Requester   string        `json:"requester"`
	Reason      string        `json:"reason"`
	Hours       int           `json:"hours"`
	State       string        `json:"state"`
	Decision    GrantDecision `json:"decision"`
	Approvals   []Approval    `json:"approvals"`
	Error       *string       `json:"error"`
	CreatedAt   time.Time     `json:"created_at"`
	ActivatedAt *time.Time    `json:"activated_at"`
	ExpiresAt   *time.Time    `json:"expires_at"`
	EndedAt     *time.Time    `json:"ended_at"`
	EndedBy     *string       `json:"ended_by"`
}

const grantCols = `id::text, role_id::text, requester, reason, hours, state, decision, approvals, error, created_at, activated_at, expires_at, ended_at, ended_by`

func scanGrant(r pgx.Row) (Grant, error) {
	var g Grant
	var d, a []byte
	err := r.Scan(&g.ID, &g.RoleID, &g.Requester, &g.Reason, &g.Hours, &g.State, &d, &a, &g.Error, &g.CreatedAt, &g.ActivatedAt, &g.ExpiresAt, &g.EndedAt, &g.EndedBy)
	_ = json.Unmarshal(d, &g.Decision)
	_ = json.Unmarshal(a, &g.Approvals)
	if g.Approvals == nil {
		g.Approvals = []Approval{}
	}
	return g, err
}

// Register adds the grant expiry worker.
func (s *Service) Register(w *river.Workers) { river.AddWorker(w, &expireGrant{s: s}) }

// SetClient gives the Service its River client for expiry timers.
func (s *Service) SetClient(c *river.Client[pgx.Tx]) { s.river = c }

type expireArgs struct {
	Tenant  string `json:"tenant"`
	GrantID string `json:"grant_id"`
}

func (expireArgs) Kind() string { return "keel_access_grant_expire" }

// target is what an assignment needs about the role.
type target struct {
	role                      Role
	envName, account, project string
	cloudAccount              string // Catalog id of account, "" when the Environment has none
	requiresApproval          bool
}

func (s *Service) target(ctx context.Context, tx pgx.Tx, roleID string) (target, error) {
	var t target
	var err error
	if t.role, err = scanRole(tx.QueryRow(ctx, `SELECT `+roleCols+` FROM access_roles WHERE id = $1`, roleID)); errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	} else if err != nil {
		return t, err
	}
	err = tx.QueryRow(ctx, `SELECT e.name, e.project_id::text, e.requires_approval, coalesce(a.external_id, ''), coalesce(a.id::text, '')
		FROM environments e LEFT JOIN cloud_accounts a ON a.environment_id = e.id AND a.provider = 'tencent' AND a.archived_at IS NULL
		WHERE e.id = $1`, t.role.EnvironmentID).Scan(&t.envName, &t.project, &t.requiresApproval, &t.account, &t.cloudAccount)
	return t, err
}

// RequestGrant asks for a role for some hours. The policy denies, approves at
// once (read-only outside production) or names the approvals needed.
func (s *Service) RequestGrant(ctx context.Context, tenant, roleID string, hours int, reason string, p auth.Principal) (Grant, error) {
	if p.Kind != auth.KindHuman {
		return Grant{}, fmt.Errorf("%w: Access Grants are for people", ErrInvalid)
	}
	var g Grant
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		t, err := s.target(ctx, tx, roleID)
		if err != nil {
			return err
		}
		tmpl := Templates[t.role.Template]
		d, err := eval[GrantDecision](ctx, s.grant, map[string]any{
			"tenant_id": tenant, "requester": p, "role": map[string]any{"team_id": t.role.TeamID, "state": t.role.State},
			"template": tmpl, "environment": map[string]any{"prod": isProd(t.envName)}, "hours": hours, "reason": reason,
			"tenant_requires_approval": t.requiresApproval,
		})
		if err != nil {
			return err
		}
		if d.Approvals == nil {
			d.Approvals = []string{}
		}
		state := "requested"
		if !d.Allow {
			state = "denied"
		}
		raw, _ := json.Marshal(d)
		h := min(max(hours, 1), 12)
		if g, err = scanGrant(tx.QueryRow(ctx, `INSERT INTO access_grants (tenant_id, role_id, requester, reason, hours, state, decision, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING `+grantCols, tenant, roleID, p.Subject, reason, h, state, raw, s.Now().UTC())); err != nil {
			return err
		}
		outcome := activity.Success
		detail := fmt.Sprintf("%s in %s for %dh: %s", t.role.Template, t.envName, h, state)
		if !d.Allow {
			outcome, detail = activity.Failure, detail+" ("+strings.Join(d.Reasons, "; ")+")"
		} else if len(d.Approvals) > 0 {
			detail += " — needs " + strings.Join(d.Approvals, " + ")
		}
		return record(ctx, tx, tenant, "keel.access.grant_requested", "RequestAccessGrant", "access_grant/"+g.ID, activity.Create, outcome, actorOf(p), detail+" ["+d.Policy+"]",
			activity.Resource{Type: "access_grant", UID: g.ID}, activity.Resource{Type: "access_role", UID: roleID})
	})
	if err != nil || g.State != "requested" || len(g.Decision.Approvals) > 0 {
		return g, err
	}
	return s.activate(ctx, tenant, g.ID)
}

func actorOf(p auth.Principal) activity.Actor {
	return activity.Actor{Type: activity.ActorHuman, UID: p.Subject, Session: &activity.Session{Issuer: p.Issuer, MFA: p.MFA}}
}

// holds reports whether the principal holds role in the tenant.
func holds(p auth.Principal, tenant, role string) bool {
	for _, b := range p.Bindings {
		if b.TenantID == tenant && b.Role == role && (p.Home || p.TenantID == tenant) {
			return true
		}
	}
	return false
}

// Approve records one approval; when every required approval is in, the
// grant becomes active.
func (s *Service) Approve(ctx context.Context, tenant, id string, p auth.Principal) (Grant, error) {
	var g Grant
	ready := false
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		cur, err := scanGrant(tx.QueryRow(ctx, `SELECT `+grantCols+` FROM access_grants WHERE id = $1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if cur.State != "requested" {
			return ErrState
		}
		if cur.Requester == p.Subject {
			return fmt.Errorf("%w: requesters cannot approve their own access", ErrState)
		}
		done := map[string]bool{}
		for _, a := range cur.Approvals {
			if a.By == p.Subject {
				return fmt.Errorf("%w: one person gives one approval", ErrState)
			}
			done[a.Role] = true
		}
		var as string
		for _, need := range cur.Decision.Approvals {
			if !done[need] && holds(p, tenant, need) {
				as = need
				break
			}
		}
		if as == "" {
			return fmt.Errorf("%w: needs %s; you hold none of the outstanding approvals", ErrState, strings.Join(cur.Decision.Approvals, " + "))
		}
		cur.Approvals = append(cur.Approvals, Approval{Role: as, By: p.Subject, At: s.Now().UTC()})
		raw, _ := json.Marshal(cur.Approvals)
		if g, err = scanGrant(tx.QueryRow(ctx, `UPDATE access_grants SET approvals = $2 WHERE id = $1 RETURNING `+grantCols, id, raw)); err != nil {
			return err
		}
		ready = len(g.Approvals) == len(g.Decision.Approvals)
		return record(ctx, tx, tenant, "keel.access.grant_approved", "ApproveAccessGrant", "access_grant/"+id, activity.Update, activity.Success, actorOf(p),
			fmt.Sprintf("approved as %s (%d of %d)", as, len(g.Approvals), len(g.Decision.Approvals)), activity.Resource{Type: "access_grant", UID: id})
	})
	if err != nil || !ready {
		return g, err
	}
	return s.activate(ctx, tenant, id)
}

// Reject refuses a requested grant.
func (s *Service) Reject(ctx context.Context, tenant, id, why string, p auth.Principal) (Grant, error) {
	if strings.TrimSpace(why) == "" {
		return Grant{}, fmt.Errorf("%w: say why", ErrInvalid)
	}
	var g Grant
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		g, err = scanGrant(tx.QueryRow(ctx, `UPDATE access_grants SET state = 'rejected', ended_at = $3, ended_by = $2 WHERE id = $1 AND state = 'requested' AND requester <> $2 RETURNING `+grantCols, id, p.Subject, s.Now().UTC()))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrState
		}
		if err != nil {
			return err
		}
		return record(ctx, tx, tenant, "keel.access.grant_rejected", "RejectAccessGrant", "access_grant/"+id, activity.Update, activity.Success, actorOf(p), why, activity.Resource{Type: "access_grant", UID: id})
	})
	return g, err
}

// activate assigns the role and schedules its removal.
func (s *Service) activate(ctx context.Context, tenant, id string) (Grant, error) {
	var g Grant
	var t target
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if g, err = scanGrant(tx.QueryRow(ctx, `SELECT `+grantCols+` FROM access_grants WHERE id = $1`, id)); err != nil {
			return err
		}
		t, err = s.target(ctx, tx, g.RoleID)
		return err
	}); err != nil {
		return g, err
	}
	principal, assignErr := s.assign(ctx, tenant, t, g)
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if assignErr != nil {
			if g, err = scanGrant(tx.QueryRow(ctx, `UPDATE access_grants SET state = 'failed', error = $2 WHERE id = $1 RETURNING `+grantCols, id, assignErr.Error())); err != nil {
				return err
			}
			return record(ctx, tx, tenant, "keel.access.grant_failed", "ActivateAccessGrant", "access_grant/"+id, activity.Update, activity.Failure, keelActor, assignErr.Error(), activity.Resource{Type: "access_grant", UID: id})
		}
		now := s.Now().UTC()
		exp := now.Add(time.Duration(g.Hours) * time.Hour)
		if g, err = scanGrant(tx.QueryRow(ctx, `UPDATE access_grants SET state = 'active', principal_id = $2, activated_at = $3, expires_at = $4 WHERE id = $1 RETURNING `+grantCols, id, principal, now, exp)); err != nil {
			return err
		}
		if s.river == nil {
			return errors.New("access grants have no River client for expiry")
		}
		if _, err := s.river.InsertTx(ctx, tx, expireArgs{Tenant: tenant, GrantID: id}, &river.InsertOpts{ScheduledAt: exp, MaxAttempts: 25}); err != nil {
			return err
		}
		return record(ctx, tx, tenant, "keel.access.grant_active", "ActivateAccessGrant", "access_grant/"+id, activity.Update, activity.Success, keelActor,
			fmt.Sprintf("%s holds %s in %s (%s) until %s", g.Requester, t.role.Template, t.envName, t.account, exp.Format(time.RFC3339)), activity.Resource{Type: "access_grant", UID: id})
	})
	if err == nil && errors.Is(assignErr, catalog.ErrClientOwned) {
		return g, assignErr
	}
	return g, err
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:access"}

func (s *Service) assign(ctx context.Context, tenant string, t target, g Grant) (string, error) {
	if t.cloudAccount != "" {
		if err := catalog.RequirePlatformOwned(ctx, s.Store, tenant, t.cloudAccount, "AssignAccessGrant", keelActor); err != nil {
			return "", err
		}
	}
	if s.Directory == nil {
		return "", errors.New("identity Center is not configured (KEEL_CIC_ZONE_ID)")
	}
	if t.role.RoleConfiguration == nil {
		return "", errors.New("the role has no Identity Center role configuration yet")
	}
	acct, err := strconv.ParseInt(t.account, 10, 64)
	if err != nil {
		return "", fmt.Errorf("the Environment has no Tencent account")
	}
	email := strings.TrimPrefix(g.Requester, "user:")
	user, ok, err := s.Directory.UserID(ctx, email)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("no Identity Center user with email %s", email)
	}
	return user, s.Directory.Assign(ctx, *t.role.RoleConfiguration, acct, user)
}

// Revoke ends an active grant early.
func (s *Service) Revoke(ctx context.Context, tenant, id, why string, by activity.Actor) (Grant, error) {
	return s.end(ctx, tenant, id, "revoked", why, by)
}

func (s *Service) end(ctx context.Context, tenant, id, state, why string, by activity.Actor) (Grant, error) {
	var g Grant
	var t target
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if g, err = scanGrant(tx.QueryRow(ctx, `SELECT `+grantCols+` FROM access_grants WHERE id = $1`, id)); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if g.State != "active" {
			return ErrState
		}
		t, err = s.target(ctx, tx, g.RoleID)
		return err
	}); err != nil {
		return g, err
	}
	var principal string
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(principal_id, '') FROM access_grants WHERE id = $1`, id).Scan(&principal)
	}); err != nil {
		return g, err
	}
	acct, _ := strconv.ParseInt(t.account, 10, 64)
	if s.Directory != nil && t.role.RoleConfiguration != nil {
		var err error
		if t.cloudAccount != "" {
			err = catalog.RequirePlatformOwned(ctx, s.Store, tenant, t.cloudAccount, "UnassignAccessGrant", keelActor)
		}
		switch {
		case errors.Is(err, catalog.ErrClientOwned):
			why += "; the account became client-owned, so its owner removes the assignment"
		case err != nil:
			return g, err
		default:
			if err := s.Directory.Unassign(ctx, *t.role.RoleConfiguration, acct, principal); err != nil {
				return g, err // retried: the role must not outlive the grant
			}
		}
	}
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if g, err = scanGrant(tx.QueryRow(ctx, `UPDATE access_grants SET state = $2, ended_at = $4, ended_by = $3 WHERE id = $1 AND state = 'active' RETURNING `+grantCols, id, state, by.UID, s.Now().UTC())); err != nil {
			return err
		}
		return record(ctx, tx, tenant, "keel.access.grant_"+state, "EndAccessGrant", "access_grant/"+id, activity.Update, activity.Success, by,
			fmt.Sprintf("%s no longer holds %s in %s: %s", g.Requester, t.role.Template, t.envName, why), activity.Resource{Type: "access_grant", UID: id})
	})
	return g, err
}

// Grants lists grants, newest first.
func (s *Service) Grants(ctx context.Context, tenant, state string) ([]Grant, error) {
	var out []Grant
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+grantCols+` FROM access_grants WHERE ($1 = '' OR state = $1) ORDER BY created_at DESC LIMIT 500`, state)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Grant, error) { return scanGrant(r) })
		return err
	})
	return out, err
}

type expireGrant struct {
	river.WorkerDefaults[expireArgs]
	s *Service
}

func (w *expireGrant) Work(ctx context.Context, job *river.Job[expireArgs]) error {
	_, err := w.s.end(ctx, job.Args.Tenant, job.Args.GrantID, "expired", "time box ended", keelActor)
	if errors.Is(err, ErrState) || errors.Is(err, ErrNotFound) {
		return nil // already revoked
	}
	return err
}
