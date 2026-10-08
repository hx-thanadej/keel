// Package breakglass keeps the emergency path honest (#135, ADR-0006): the
// provider-native admin identities outside SSO are registered, any use seen
// in CloudAudit becomes a critical Finding that only a post-mortem closes,
// and a drill is due every 90 days.
package breakglass

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// DrillEvery is how often each identity must be exercised.
const DrillEvery = 90 * 24 * time.Hour

var (
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = errors.New("not found")
)

// Identity is a registered break-glass identity.
type Identity struct {
	ID          string     `json:"id"`
	Provider    string     `json:"provider"`
	Account     string     `json:"account"`
	PrincipalID string     `json:"principal_id"`
	Name        string     `json:"name"`
	Holder      string     `json:"holder"`
	HardwareMFA bool       `json:"hardware_mfa"`
	LastDrillAt *time.Time `json:"last_drill_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Event is one audited API call by an identity.
type Event struct {
	ID, Name, SourceIP string
	At                 time.Time
}

// Audit reads an account's audit log.
type Audit interface {
	Events(ctx context.Context, principalID string, since time.Time) ([]Event, error)
}

// Service manages the registry (in the home Tenant).
type Service struct {
	Store *store.Store
	Audit func(account string) (Audit, error)
	Now   func() time.Time
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s Service) home(ctx context.Context) (string, error) {
	var h *string
	if err := s.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&h); err != nil {
		return "", err
	}
	if h == nil {
		return "", errors.New("no home tenant")
	}
	return *h, nil
}

const idCols = `id::text, provider, account, principal_id, name, holder, hardware_mfa, last_drill_at, created_at`

func scanID(r pgx.Row) (Identity, error) {
	var i Identity
	err := r.Scan(&i.ID, &i.Provider, &i.Account, &i.PrincipalID, &i.Name, &i.Holder, &i.HardwareMFA, &i.LastDrillAt, &i.CreatedAt)
	return i, err
}

func record(ctx context.Context, tx pgx.Tx, tenant, typ, op, subject string, by activity.Actor, outcome activity.Outcome, detail string) error {
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/breakglass", Type: typ, Subject: subject, Operation: op,
		Kind: activity.Update, Actor: by, Outcome: outcome, StatusDetail: detail, Why: activity.Why{Reason: detail}})
	return err
}

// Register adds an identity. Hardware MFA is required.
func (s Service) Register(ctx context.Context, in Identity, by activity.Actor) (Identity, error) {
	if !in.HardwareMFA {
		return Identity{}, fmt.Errorf("%w: break-glass identities need hardware MFA", ErrInvalid)
	}
	if in.Account == "" || in.PrincipalID == "" || in.Name == "" || in.Holder == "" {
		return Identity{}, fmt.Errorf("%w: account, principal_id, name and holder are required", ErrInvalid)
	}
	if in.Provider == "" {
		in.Provider = "tencent"
	}
	home, err := s.home(ctx)
	if err != nil {
		return Identity{}, err
	}
	var out Identity
	err = s.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		var err error
		if out, err = scanID(tx.QueryRow(ctx, `INSERT INTO breakglass_identities (tenant_id, provider, account, principal_id, name, holder, hardware_mfa, created_by, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8) RETURNING `+idCols, home, in.Provider, in.Account, in.PrincipalID, in.Name, in.Holder, by.UID, s.now())); err != nil {
			return err
		}
		return record(ctx, tx, home, "keel.breakglass.registered", "RegisterBreakGlass", "breakglass/"+out.ID, by, activity.Success,
			fmt.Sprintf("%s in %s, held by %s", in.Name, in.Account, in.Holder))
	})
	return out, err
}

// List returns active identities.
func (s Service) List(ctx context.Context) ([]Identity, error) {
	home, err := s.home(ctx)
	if err != nil {
		return nil, err
	}
	var out []Identity
	err = s.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+idCols+` FROM breakglass_identities WHERE retired_at IS NULL ORDER BY account, name`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Identity, error) { return scanID(r) })
		return err
	})
	return out, err
}

// Names returns the break-glass user names in one account (for the
// standing-access report).
func (s Service) Names(ctx context.Context, _ string, account string) (map[string]bool, error) {
	ids, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, i := range ids {
		if i.Account == account {
			out[i.Name] = true
		}
	}
	return out, nil
}

// Drill records an exercise of an identity.
func (s Service) Drill(ctx context.Context, id, notes string, by activity.Actor) error {
	if strings.TrimSpace(notes) == "" {
		return fmt.Errorf("%w: record what the drill covered", ErrInvalid)
	}
	home, err := s.home(ctx)
	if err != nil {
		return err
	}
	return s.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE breakglass_identities SET last_drill_at = $2 WHERE id = $1 AND retired_at IS NULL`, id, s.now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now(), resolution = 'drill completed'
			WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, "breakglass_drill:"+id); err != nil {
			return err
		}
		return record(ctx, tx, home, "keel.breakglass.drilled", "DrillBreakGlass", "breakglass/"+id, by, activity.Success, notes)
	})
}

// PostMortem closes a use's Finding with the post-mortem link.
func (s Service) PostMortem(ctx context.Context, useID, url string, by activity.Actor) error {
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("%w: the post-mortem must be a https:// link", ErrInvalid)
	}
	home, err := s.home(ctx)
	if err != nil {
		return err
	}
	return s.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		var finding *string
		err := tx.QueryRow(ctx, `UPDATE breakglass_uses SET postmortem_url = $2 WHERE id = $1 RETURNING finding_id::text`, useID, url).Scan(&finding)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if finding != nil {
			if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now(), resolution = $2 WHERE id = $1 AND status = 'open'`, *finding, "post-mortem: "+url); err != nil {
				return err
			}
		}
		return record(ctx, tx, home, "keel.breakglass.postmortem", "RecordPostMortem", "breakglass_use/"+useID, by, activity.Success, url)
	})
}

// WatchResult counts what a run found.
type WatchResult struct {
	Uses          int `json:"uses"`
	DrillsOverdue int `json:"drills_overdue"`
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:breakglass"}

// Watch looks for uses since lookback and for overdue drills.
func (s Service) Watch(ctx context.Context, lookback time.Duration) (WatchResult, error) {
	var res WatchResult
	ids, err := s.List(ctx)
	if err != nil {
		return res, err
	}
	home, err := s.home(ctx)
	if err != nil {
		return res, err
	}
	now := s.now()
	for _, id := range ids {
		if s.Audit != nil {
			a, err := s.Audit(id.Account)
			if err != nil {
				return res, err
			}
			events, err := a.Events(ctx, id.PrincipalID, now.Add(-lookback))
			if err != nil {
				return res, fmt.Errorf("audit %s: %w", id.Account, err)
			}
			for _, e := range events {
				n, err := s.use(ctx, home, id, e)
				if err != nil {
					return res, err
				}
				res.Uses += n
			}
		}
		last := id.CreatedAt
		if id.LastDrillAt != nil {
			last = *id.LastDrillAt
		}
		if now.Sub(last) > DrillEvery {
			res.DrillsOverdue++
			if err := s.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail)
					VALUES ($1, 'breakglass', $2, 'medium', $3, jsonb_build_object('identity', $4::text, 'account', $5::text))
					ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now()`,
					home, "breakglass_drill:"+id.ID, fmt.Sprintf("Break-glass drill overdue for %s in %s (last %s)", id.Name, id.Account, last.Format("2 Jan 2006")), id.Name, id.Account)
				return err
			}); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// use records one audited call once, with a critical Finding.
func (s Service) use(ctx context.Context, home string, id Identity, e Event) (int, error) {
	n := 0
	err := s.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		var useID string
		err := tx.QueryRow(ctx, `INSERT INTO breakglass_uses (tenant_id, identity_id, event_id, event_name, source_ip, used_at) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (event_id) DO NOTHING RETURNING id::text`, home, id.ID, e.ID, e.Name, e.SourceIP, e.At).Scan(&useID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // seen before
		}
		if err != nil {
			return err
		}
		n = 1
		var finding string
		if err := tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail)
			VALUES ($1, 'breakglass', $2, 'critical', $3, jsonb_build_object('identity', $4::text, 'account', $5::text, 'event', $6::text, 'source_ip', $7::text, 'use', $8::text))
			RETURNING id::text`, home, "breakglass_use:"+useID,
			fmt.Sprintf("Break-glass %s used in %s: %s at %s — post-mortem required", id.Name, id.Account, e.Name, e.At.UTC().Format(time.RFC3339)),
			id.Name, id.Account, e.Name, e.SourceIP, useID).Scan(&finding); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE breakglass_uses SET finding_id = $2 WHERE id = $1`, useID, finding); err != nil {
			return err
		}
		return record(ctx, tx, home, "keel.breakglass.used", "DetectBreakGlass", "breakglass/"+id.ID, keelActor, activity.Failure,
			fmt.Sprintf("%s: %s from %s", id.Name, e.Name, e.SourceIP))
	})
	return n, err
}
