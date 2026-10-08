// Package exceptions records approved, time-boxed permission for Findings
// to stand (#108). An Exception always has an approver other than the
// requester and an expiry of at most 90 days; a durable River timer expires
// it, after which its Findings count again at every gate.
package exceptions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// MaxDuration is the longest an Exception may run.
const MaxDuration = 90 * 24 * time.Hour

var (
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = errors.New("exception not found")
	ErrState    = errors.New("exception is not in a state that allows this")
)

// Exception is one record.
type Exception struct {
	ID           string     `json:"id"`
	ProjectID    *string    `json:"project_id"`
	FindingIDs   []string   `json:"finding_ids"`
	Fingerprint  string     `json:"fingerprint"`
	Reason       string     `json:"reason"`
	State        string     `json:"state"`
	RequestedBy  string     `json:"requested_by"`
	DecidedBy    *string    `json:"decided_by"`
	DecisionNote *string    `json:"decision_note"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	DecidedAt    *time.Time `json:"decided_at"`
	ApprovedAt   *time.Time `json:"approved_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
}

// Request is what a requester submits.
type Request struct {
	ProjectID   *string   `json:"project_id"`
	FindingIDs  []string  `json:"finding_ids"`
	Fingerprint string    `json:"fingerprint"`
	Reason      string    `json:"reason"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Service manages Exceptions.
type Service struct {
	Store  *store.Store
	Now    func() time.Time
	client *river.Client[pgx.Tx]
}

// New returns a Service.
func New(st *store.Store) *Service { return &Service{Store: st, Now: time.Now} }

// Register adds the expiry timer worker.
func (s *Service) Register(w *river.Workers) { river.AddWorker(w, &expireWorker{s: s}) }

// SetClient gives the Service the River client for timers.
func (s *Service) SetClient(c *river.Client[pgx.Tx]) { s.client = c }

type expireArgs struct {
	Tenant      string `json:"tenant"`
	ExceptionID string `json:"exception_id"`
}

func (expireArgs) Kind() string { return "keel_exception_expire" }

const cols = `id::text, project_id::text, finding_ids::text[], fingerprint, reason, state, requested_by, decided_by, decision_note, expires_at, created_at, decided_at, approved_at, revoked_at`

func scan(r pgx.Row) (Exception, error) {
	var e Exception
	err := r.Scan(&e.ID, &e.ProjectID, &e.FindingIDs, &e.Fingerprint, &e.Reason, &e.State, &e.RequestedBy, &e.DecidedBy, &e.DecisionNote, &e.ExpiresAt, &e.CreatedAt, &e.DecidedAt, &e.ApprovedAt, &e.RevokedAt)
	return e, err
}

func record(ctx context.Context, tx pgx.Tx, tenant, id, typ, op string, kind activity.Kind, outcome activity.Outcome, by activity.Actor, detail string) error {
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/exceptions", Type: typ, Subject: "exception/" + id, Operation: op,
		Kind: kind, Actor: by, Outcome: outcome, Resources: []activity.Resource{{Type: "exception", UID: id}}, StatusDetail: detail, Why: activity.Why{Reason: detail}})
	return err
}

// Create records a request for an Exception.
func (s *Service) Create(ctx context.Context, tenant string, r Request, by activity.Actor) (Exception, error) {
	now := s.Now()
	switch {
	case len(strings.TrimSpace(r.Reason)) < 10:
		return Exception{}, fmt.Errorf("%w: a reason of at least 10 characters is required", ErrInvalid)
	case len(r.FindingIDs) == 0 && r.Fingerprint == "":
		return Exception{}, fmt.Errorf("%w: name findings or a fingerprint prefix", ErrInvalid)
	case !r.ExpiresAt.After(now):
		return Exception{}, fmt.Errorf("%w: expires_at must be in the future", ErrInvalid)
	case r.ExpiresAt.Sub(now) > MaxDuration:
		return Exception{}, fmt.Errorf("%w: exceptions last at most 90 days", ErrInvalid)
	}
	if r.FindingIDs == nil {
		r.FindingIDs = []string{}
	}
	var e Exception
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if len(r.FindingIDs) > 0 {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE id = ANY ($1::uuid[])`, r.FindingIDs).Scan(&n); err != nil {
				return fmt.Errorf("%w: finding ids: %v", ErrInvalid, err)
			}
			if n != len(r.FindingIDs) {
				return ErrNotFound
			}
		}
		var err error
		e, err = scan(tx.QueryRow(ctx, `INSERT INTO exceptions (tenant_id, project_id, finding_ids, fingerprint, reason, requested_by, expires_at)
			VALUES ($1, $2, $3::uuid[], $4, $5, $6, $7) RETURNING `+cols, tenant, r.ProjectID, r.FindingIDs, r.Fingerprint, r.Reason, by.UID, r.ExpiresAt))
		if err != nil {
			return err
		}
		return record(ctx, tx, tenant, e.ID, "keel.exception.requested", "RequestException", activity.Create, activity.Success, by,
			fmt.Sprintf("until %s: %s", r.ExpiresAt.UTC().Format(time.RFC3339), r.Reason))
	})
	return e, err
}

// Approve grants a requested Exception and schedules its expiry.
func (s *Service) Approve(ctx context.Context, tenant, id, note string, by activity.Actor) (Exception, error) {
	return s.decide(ctx, tenant, id, "approved", note, by)
}

// Reject declines a requested Exception.
func (s *Service) Reject(ctx context.Context, tenant, id, note string, by activity.Actor) (Exception, error) {
	if note == "" {
		return Exception{}, fmt.Errorf("%w: say why", ErrInvalid)
	}
	return s.decide(ctx, tenant, id, "rejected", note, by)
}

func (s *Service) decide(ctx context.Context, tenant, id, to, note string, by activity.Actor) (Exception, error) {
	var e Exception
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		cur, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM exceptions WHERE id = $1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if cur.State != "requested" {
			return ErrState
		}
		if cur.RequestedBy == by.UID {
			return fmt.Errorf("%w: the requester cannot decide their own exception", ErrState)
		}
		if to == "approved" && !cur.ExpiresAt.After(s.Now()) {
			return fmt.Errorf("%w: it would already have expired; request a new one", ErrState)
		}
		e, err = scan(tx.QueryRow(ctx, `UPDATE exceptions SET state = $2, decided_by = $3, decision_note = nullif($4, ''), decided_at = now(),
			approved_at = CASE WHEN $2 = 'approved' THEN now() END WHERE id = $1 RETURNING `+cols,
			id, to, by.UID, note))
		if err != nil {
			return err
		}
		if to == "approved" {
			if s.client == nil {
				return errors.New("exceptions have no River client for expiry timers")
			}
			if _, err := s.client.InsertTx(ctx, tx, expireArgs{Tenant: tenant, ExceptionID: id}, &river.InsertOpts{ScheduledAt: e.ExpiresAt, MaxAttempts: 25}); err != nil {
				return err
			}
		}
		return record(ctx, tx, tenant, id, "keel.exception."+to, "DecideException", activity.Update, activity.Success, by, orDefault(note, to))
	})
	return e, err
}

// Revoke ends an approved Exception early.
func (s *Service) Revoke(ctx context.Context, tenant, id, note string, by activity.Actor) (Exception, error) {
	if note == "" {
		return Exception{}, fmt.Errorf("%w: say why", ErrInvalid)
	}
	var e Exception
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		e, err = scan(tx.QueryRow(ctx, `UPDATE exceptions SET state = 'revoked', decision_note = $2, revoked_at = now() WHERE id = $1 AND state = 'approved' RETURNING `+cols, id, note))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrState
		}
		if err != nil {
			return err
		}
		return record(ctx, tx, tenant, id, "keel.exception.revoked", "RevokeException", activity.Update, activity.Success, by, note)
	})
	return e, err
}

// List returns Exceptions, newest first.
func (s *Service) List(ctx context.Context, tenant, state string) ([]Exception, error) {
	var out []Exception
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+cols+` FROM exceptions WHERE ($1 = '' OR state = $1) ORDER BY created_at DESC LIMIT 200`, state)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Exception, error) { return scan(r) })
		return err
	})
	return out, err
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:exceptions"}

type expireWorker struct {
	river.WorkerDefaults[expireArgs]
	s *Service
}

// Work expires the Exception (if still approved) and marks the Findings it
// covered, which now count again at every gate.
func (w *expireWorker) Work(ctx context.Context, job *river.Job[expireArgs]) error {
	a := job.Args
	return w.s.Store.InTenant(ctx, a.Tenant, func(tx pgx.Tx) error {
		e, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM exceptions WHERE id = $1 FOR UPDATE`, a.ExceptionID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if e.State != "approved" {
			return nil // revoked or already expired
		}
		if e.ExpiresAt.After(w.s.Now()) {
			return river.JobSnooze(time.Until(e.ExpiresAt) + time.Second)
		}
		if _, err := tx.Exec(ctx, `UPDATE exceptions SET state = 'expired' WHERE id = $1`, e.ID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE findings f SET detail = f.detail || jsonb_build_object('exception_lapsed', $1::text), last_seen_at = now()
			WHERE f.status = 'open' AND (f.id = ANY ($2::uuid[]) OR ($3 <> '' AND starts_with(f.fingerprint, $3)))
			  AND ($4::uuid IS NULL OR f.project_id = $4)`, e.ID, e.FindingIDs, e.Fingerprint, e.ProjectID)
		if err != nil {
			return err
		}
		return record(ctx, tx, a.Tenant, e.ID, "keel.exception.expired", "ExpireException", activity.Update, activity.Success, keelActor,
			fmt.Sprintf("expired; %d open Finding(s) count again at gates", tag.RowsAffected()))
	})
}
