package pdpa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
)

// State is where a breach is on its clock. The timed states run in order
// declared → warning → deadline as time passes from aware_at; recording the
// PDPC notification (notified) or closing the breach without one (closed)
// ends it from any of them.
type State string

const (
	Declared State = "declared"
	Warning  State = "warning"
	Deadline State = "deadline"
	Notified State = "notified"
	Closed   State = "closed"
)

// PDPA s.37(4): notify the PDPC within 72 hours of becoming aware. Keel warns
// at 48 hours.
const (
	WarnAfter    = 48 * time.Hour
	NotifyWithin = 72 * time.Hour
)

// timed lists the clock states in order, each with when it starts and the
// Finding entering it raises. Declared raises none: the declaration itself
// is the Activity.
var timed = []struct {
	state    State
	after    time.Duration
	severity string
	title    string
}{
	{Declared, 0, "", ""},
	{Warning, WarnAfter, "high", "PDPA breach %q: notify the PDPC by %s"},
	{Deadline, NotifyWithin, "critical", "PDPA breach %q: PDPC notification deadline %s has passed"},
}

func rank(s State) int {
	for i, t := range timed {
		if t.state == s {
			return i
		}
	}
	return -1
}

// Ended reports whether s is a terminal state.
func (s State) Ended() bool { return s == Notified || s == Closed }

// due is the timed state a breach the PDPC has not been told about should
// be in at now.
func due(aware, now time.Time) int {
	at := 0
	for i, t := range timed {
		if !now.Before(aware.Add(t.after)) {
			at = i
		}
	}
	return at
}

// Breach is a personal data breach record.
type Breach struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Description   string     `json:"description"`
	State         State      `json:"state"`
	AwareAt       time.Time  `json:"aware_at"`
	NotifyBy      time.Time  `json:"notify_by"`
	DeclaredAt    time.Time  `json:"declared_at"`
	DeclaredBy    string     `json:"declared_by"`
	NotifiedAt    *time.Time `json:"notified_at,omitempty"`
	PDPCReference string     `json:"pdpc_reference,omitempty"`
	CloseReason   string     `json:"close_reason,omitempty"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	EndedBy       string     `json:"ended_by,omitempty"`
}

func breaches(ctx context.Context, tx pgx.Tx, where string, args ...any) ([]Breach, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, title, description, state, aware_at, declared_at, declared_by, notified_at, pdpc_reference, close_reason, ended_at, ended_by
		FROM pdpa_breaches WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Breach, error) {
		var b Breach
		err := r.Scan(&b.ID, &b.Title, &b.Description, &b.State, &b.AwareAt, &b.DeclaredAt, &b.DeclaredBy, &b.NotifiedAt, &b.PDPCReference, &b.CloseReason, &b.EndedAt, &b.EndedBy)
		b.NotifyBy = b.AwareAt.Add(NotifyWithin)
		return b, err
	})
}

func breach(ctx context.Context, tx pgx.Tx, id string) (Breach, error) {
	list, err := breaches(ctx, tx, `id::text = $1 FOR UPDATE`, id)
	if err != nil {
		return Breach{}, err
	}
	if len(list) == 0 {
		return Breach{}, ErrNotFound
	}
	return list[0], nil
}

// Declaration starts a breach clock. AwareAt defaults to now and may be
// earlier, never later.
type Declaration struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	AwareAt     *time.Time `json:"aware_at"`
}

// Declare records a breach and starts its clock, moving it straight to the
// state its awareness time has reached.
func (s Service) Declare(ctx context.Context, tenant string, in Declaration, by activity.Actor) (Breach, error) {
	now := s.now()
	in.Title = strings.TrimSpace(in.Title)
	if in.Title == "" || len(in.Title) > 200 {
		return Breach{}, fmt.Errorf("%w: title is 1 to 200 characters", ErrInvalid)
	}
	aware := now
	if in.AwareAt != nil {
		aware = in.AwareAt.UTC()
	}
	if aware.After(now) {
		return Breach{}, fmt.Errorf("%w: aware_at is in the future", ErrInvalid)
	}
	var out Breach
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO pdpa_breaches (tenant_id, title, description, aware_at, declared_at, declared_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
			tenant, in.Title, in.Description, aware, now, by.UID).Scan(&id); err != nil {
			return err
		}
		if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/pdpa", Type: "keel.pdpa.breach.declared", Subject: "pdpa_breach/" + id,
			Operation: "DeclareBreach", Kind: activity.Create, Actor: by, Outcome: activity.Success, Time: now,
			StatusDetail: fmt.Sprintf("%s: aware %s, notify the PDPC by %s", in.Title, aware.Format(time.RFC3339), aware.Add(NotifyWithin).Format(time.RFC3339))}); err != nil {
			return err
		}
		b, err := breach(ctx, tx, id)
		if err != nil {
			return err
		}
		if out, _, err = advance(ctx, tx, tenant, b, now); err != nil {
			return err
		}
		return nil
	})
	return out, err
}

// advance moves an open breach to the state now has reached, raising that
// state's Finding and resolving the previous one. It reports whether the
// breach moved.
func advance(ctx context.Context, tx pgx.Tx, tenant string, b Breach, now time.Time) (Breach, bool, error) {
	from, to := rank(b.State), due(b.AwareAt, now)
	if b.State.Ended() || to <= from {
		return b, false, nil
	}
	t := timed[to]
	b.State = t.state
	if _, err := tx.Exec(ctx, `UPDATE pdpa_breaches SET state = $2 WHERE id = $1`, b.ID, b.State); err != nil {
		return b, false, err
	}
	if err := resolveBreachFindings(ctx, tx, b.ID, now, "superseded by "+string(b.State)); err != nil {
		return b, false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at, last_seen_at)
		VALUES ($1, 'pdpa_breach', $2, $3, $4, jsonb_build_object('breach', $5::text, 'state', $6::text, 'aware_at', $7::timestamptz, 'notify_by', $8::timestamptz, 'law', 'PDPA s.37(4)'), $9, $9)`,
		tenant, "pdpa_breach:"+b.ID+":"+string(b.State), t.severity, fmt.Sprintf(t.title, b.Title, b.NotifyBy.Format("2 Jan 15:04 MST")),
		b.ID, string(b.State), b.AwareAt, b.NotifyBy, now); err != nil {
		return b, false, err
	}
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/pdpa", Type: "keel.pdpa.breach." + string(b.State), Subject: "pdpa_breach/" + b.ID,
		Operation: "AdvanceBreachClock", Kind: activity.Update, Actor: keelActor, Outcome: activity.Failure, Time: now,
		StatusDetail: fmt.Sprintf("%s: PDPC not yet notified, deadline %s", b.Title, b.NotifyBy.Format(time.RFC3339))})
	return b, true, err
}

func resolveBreachFindings(ctx context.Context, tx pgx.Tx, id string, now time.Time, why string) error {
	_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = $3
		WHERE kind = 'pdpa_breach' AND status = 'open' AND starts_with(fingerprint, $1)`, "pdpa_breach:"+id+":", now, why)
	return err
}

// RunClock advances every open breach in every Tenant and returns how many
// moved.
func (s Service) RunClock(ctx context.Context) (int, error) {
	list, err := tenants(ctx, s.Store)
	if err != nil {
		return 0, err
	}
	now, moved := s.now(), 0
	for _, tenant := range list {
		err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			open, err := breaches(ctx, tx, `state IN ('declared', 'warning', 'deadline') FOR UPDATE`)
			if err != nil {
				return err
			}
			for _, b := range open {
				_, ok, err := advance(ctx, tx, tenant, b, now)
				if err != nil {
					return err
				}
				if ok {
					moved++
				}
			}
			return nil
		})
		if err != nil {
			return moved, fmt.Errorf("tenant %s: %w", tenant, err)
		}
	}
	return moved, nil
}

// Notification records that the PDPC was notified.
type Notification struct {
	Reference  string     `json:"reference"`
	NotifiedAt *time.Time `json:"notified_at"`
}

// Notify ends a breach's clock with the PDPC notification.
func (s Service) Notify(ctx context.Context, tenant, id string, in Notification, by activity.Actor) (Breach, error) {
	now := s.now()
	in.Reference = strings.TrimSpace(in.Reference)
	if in.Reference == "" {
		return Breach{}, fmt.Errorf("%w: the PDPC notification reference is required", ErrInvalid)
	}
	at := now
	if in.NotifiedAt != nil {
		at = in.NotifiedAt.UTC()
	}
	if at.After(now) {
		return Breach{}, fmt.Errorf("%w: notified_at is in the future", ErrInvalid)
	}
	return s.end(ctx, tenant, id, now, by, func(tx pgx.Tx, b *Breach) (string, error) {
		if at.Before(b.AwareAt) {
			return "", fmt.Errorf("%w: notified_at is before aware_at", ErrInvalid)
		}
		b.State, b.NotifiedAt, b.PDPCReference = Notified, &at, in.Reference
		late := ""
		if at.After(b.NotifyBy) {
			late = fmt.Sprintf(", %s after the deadline", at.Sub(b.NotifyBy).Round(time.Minute))
		}
		_, err := tx.Exec(ctx, `UPDATE pdpa_breaches SET state = 'notified', notified_at = $2, pdpc_reference = $3, ended_at = $4, ended_by = $5 WHERE id = $1`, b.ID, at, in.Reference, now, by.UID)
		return fmt.Sprintf("PDPC notified %s (reference %s)%s", at.Format(time.RFC3339), in.Reference, late), err
	})
}

// Close ends a breach without notifying the PDPC, for a breach assessed as
// unlikely to put people's rights at risk. The reason is required.
func (s Service) Close(ctx context.Context, tenant, id, reason string, by activity.Actor) (Breach, error) {
	now := s.now()
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return Breach{}, fmt.Errorf("%w: a reason is required to close without notifying", ErrInvalid)
	}
	return s.end(ctx, tenant, id, now, by, func(tx pgx.Tx, b *Breach) (string, error) {
		b.State, b.CloseReason = Closed, reason
		_, err := tx.Exec(ctx, `UPDATE pdpa_breaches SET state = 'closed', close_reason = $2, ended_at = $3, ended_by = $4 WHERE id = $1`, b.ID, reason, now, by.UID)
		return "closed without PDPC notification: " + reason, err
	})
}

func (s Service) end(ctx context.Context, tenant, id string, now time.Time, by activity.Actor, apply func(pgx.Tx, *Breach) (string, error)) (Breach, error) {
	var b Breach
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		if b, err = breach(ctx, tx, id); err != nil {
			return err
		}
		if b.State.Ended() {
			return fmt.Errorf("%w: %s", ErrState, b.State)
		}
		detail, err := apply(tx, &b)
		if err != nil {
			return err
		}
		b.EndedAt, b.EndedBy = &now, by.UID
		if err := resolveBreachFindings(ctx, tx, b.ID, now, detail); err != nil {
			return err
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/pdpa", Type: "keel.pdpa.breach." + string(b.State), Subject: "pdpa_breach/" + b.ID,
			Operation: "EndBreachClock", Kind: activity.Update, Actor: by, Outcome: activity.Success, Time: now, StatusDetail: b.Title + ": " + detail})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return b, ErrNotFound
	}
	return b, err
}
