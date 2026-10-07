// Package catalog owns Tenants, Teams, Projects, Environments and Cloud
// Accounts (CONTEXT.md). Every operation is authorised by the policy decision
// point; every write, allowed or denied, becomes an Activity.
package catalog

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/store"
)

// Errors mapped to HTTP status by the API layer.
var (
	ErrForbidden = errors.New("forbidden")
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("already exists")
	ErrInvalid   = errors.New("invalid")
)

// Authorizer is the policy decision point.
type Authorizer interface {
	Decide(ctx context.Context, req authz.Request) (authz.Decision, error)
}

// Service is the Catalog.
type Service struct {
	store *store.Store
	az    Authorizer
}

// New returns a Catalog service.
func New(s *store.Store, az Authorizer) *Service { return &Service{store: s, az: az} }

// Store exposes the underlying store for read-side packages.
func (s *Service) Store() *store.Store { return s.store }

// Tenant, Team, Project, Environment and CloudAccount are the read models.
type (
	Tenant struct {
		ID        string    `json:"id"`
		Slug      string    `json:"slug"`
		Name      string    `json:"name"`
		IsHome    bool      `json:"is_home"`
		CreatedAt time.Time `json:"created_at"`
	}
	Team struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
		Slug     string `json:"slug"`
		Name     string `json:"name"`
	}
	Project struct {
		ID         string     `json:"id"`
		TenantID   string     `json:"tenant_id"`
		TeamID     string     `json:"team_id"`
		Slug       string     `json:"slug"`
		Name       string     `json:"name"`
		ArchivedAt *time.Time `json:"archived_at,omitempty"`
	}
	ServiceEntry struct {
		ID              string `json:"id"`
		ProjectID       string `json:"project_id"`
		TeamID          string `json:"team_id"`
		Slug            string `json:"slug"`
		Name            string `json:"name"`
		Repository      string `json:"repository"`
		Template        string `json:"template"`
		TemplateVersion string `json:"template_version"`
	}
	Environment struct {
		ID         string     `json:"id"`
		TenantID   string     `json:"tenant_id"`
		ProjectID  string     `json:"project_id"`
		Name       string     `json:"name"`
		ArchivedAt *time.Time `json:"archived_at,omitempty"`
	}
	CloudAccount struct {
		ID            string     `json:"id"`
		TenantID      string     `json:"tenant_id"`
		EnvironmentID *string    `json:"environment_id"`
		Provider      string     `json:"provider"`
		ExternalID    string     `json:"external_id"`
		Name          string     `json:"name"`
		ArchivedAt    *time.Time `json:"archived_at,omitempty"`
	}
)

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// ValidID reports whether id is a UUID.
func ValidID(id string) bool {
	var u pgtype.UUID
	return u.Scan(id) == nil
}

// write authorises, runs fn in the resource's Tenant scope, and records the
// outcome. On deny it records a "<type>.denied" failure Activity and returns
// ErrForbidden.
type write struct {
	action    string
	res       authz.Resource
	actType   string // e.g. "keel.project.created"
	operation string
	kind      activity.Kind
	why       string
}

func (s *Service) authorize(ctx context.Context, p auth.Principal, action string, res authz.Resource) (authz.Decision, error) {
	d, err := s.az.Decide(ctx, authz.Request{Principal: p, Action: action, Resource: res})
	if err != nil {
		return authz.Decision{Allow: false, Reason: "policy error", Policy: "error"}, err
	}
	return d, nil
}

func actorOf(p auth.Principal) activity.Actor {
	kind := activity.ActorHuman
	switch p.Kind {
	case auth.KindPipeline:
		kind = activity.ActorPipeline
	case auth.KindWorkload:
		kind = activity.ActorWorkload
	}
	return activity.Actor{Type: kind, UID: p.Subject, Session: &activity.Session{Issuer: p.Issuer, MFA: p.MFA}}
}

func (s *Service) do(ctx context.Context, p auth.Principal, w write, fn func(tx pgx.Tx) (resourceID string, err error)) error {
	d, err := s.authorize(ctx, p, w.action, w.res)
	if err != nil || !d.Allow {
		s.recordDenied(ctx, p, w, d)
		if err != nil {
			return fmt.Errorf("authorize: %w", err)
		}
		return ErrForbidden
	}
	return s.store.InTenant(ctx, w.res.TenantID, func(tx pgx.Tx) error {
		id, err := fn(tx)
		if err != nil {
			return err
		}
		_, err = activity.Record(ctx, tx, activity.Activity{
			TenantID: w.res.TenantID, Source: "keel/catalog", Type: w.actType,
			Subject: w.res.Type + "/" + id, Operation: w.operation, Kind: w.kind,
			Actor: actorOf(p), Resources: []activity.Resource{{Type: w.res.Type, UID: id, OwnerTeam: w.res.TeamID}},
			Why: activity.Why{Reason: w.why}, Outcome: activity.Success, StatusDetail: d.String(),
		})
		return err
	})
}

// recordDenied writes the denial into the target Tenant's log, so a Tenant sees
// attempts on its data; it falls back to the caller's own Tenant.
func (s *Service) recordDenied(ctx context.Context, p auth.Principal, w write, d authz.Decision) {
	a := activity.Activity{
		Source: "keel/catalog", Type: deniedType(w.action), Subject: w.res.Type + "/" + w.res.ID,
		Operation: w.operation, Kind: w.kind, Actor: actorOf(p),
		Resources: []activity.Resource{{Type: w.res.Type, UID: w.res.ID}},
		Why:       activity.Why{Reason: w.why}, Outcome: activity.Failure, StatusDetail: d.String(),
	}
	for _, tenant := range []string{w.res.TenantID, p.TenantID} {
		if !ValidID(tenant) {
			continue
		}
		a.TenantID = tenant
		err := s.store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := activity.Record(ctx, tx, a)
			return err
		})
		if err == nil {
			return
		}
	}
}

func deniedType(action string) string { return "keel." + action + ".denied" }

func (s *Service) read(ctx context.Context, p auth.Principal, action string, res authz.Resource, fn func(tx pgx.Tx) error) error {
	d, err := s.authorize(ctx, p, action, res)
	if err != nil {
		return fmt.Errorf("authorize: %w", err)
	}
	if !d.Allow {
		return ErrForbidden
	}
	return s.store.InTenant(ctx, res.TenantID, fn)
}

func mapErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
		case "23503":
			return fmt.Errorf("%w: referenced %s does not exist in this tenant", ErrInvalid, pgErr.ConstraintName)
		case "23514", "22P02":
			return fmt.Errorf("%w: %s", ErrInvalid, pgErr.Message)
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}
