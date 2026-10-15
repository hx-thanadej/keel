package catalog

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
)

// Registration asks to bring one discovered account into a Tenant under
// Project/Environment. Both empty registers it with no Environment.
type Registration struct {
	Provider     string        `json:"provider"`
	ExternalID   string        `json:"external_id"`
	Name         string        `json:"name"`
	Project      string        `json:"project"`
	Environment  string        `json:"environment"`
	Ownership    Ownership     `json:"ownership"`
	ReadOnlyRole *ReadOnlyRole `json:"read_only_role"`
}

// RegistrationStatus is how one Registration ended.
type RegistrationStatus string

const (
	Registered         RegistrationStatus = "registered"
	AlreadyRegistered  RegistrationStatus = "already_registered"
	RegistrationFailed RegistrationStatus = "failed"
)

// RegistrationOutcome reports one Registration. Error is set exactly when
// Status is failed.
type RegistrationOutcome struct {
	Provider           string             `json:"provider"`
	ExternalID         string             `json:"external_id"`
	Status             RegistrationStatus `json:"status"`
	CloudAccount       *CloudAccount      `json:"cloud_account,omitempty"`
	ProjectCreated     bool               `json:"project_created"`
	EnvironmentCreated bool               `json:"environment_created"`
	Error              string             `json:"error,omitempty"`
}

// maxRegistrations bounds one RegisterAccounts call.
const maxRegistrations = 100

var envNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// RegisterAccounts registers each account in its own transaction, creating
// the Project (owned by teamID) and Environment it names when missing. Every
// creation is an Activity. An account already registered at the same place
// is reported unchanged, so a retry converges.
func (s *Service) RegisterAccounts(ctx context.Context, p auth.Principal, tenantID, teamID string, regs []Registration, why string) ([]RegistrationOutcome, error) {
	if len(regs) == 0 || len(regs) > maxRegistrations {
		return nil, invalid("register between 1 and %d accounts at a time", maxRegistrations)
	}
	w := write{action: "cloud_account.register", res: authz.Resource{Type: "cloud_account", TenantID: tenantID, TeamID: teamID},
		operation: "RegisterAccounts", kind: activity.Create, why: why}
	d, err := s.authorize(ctx, p, w.action, w.res)
	if err != nil || !d.Allow {
		s.recordDenied(ctx, p, w, d)
		if err != nil {
			return nil, fmt.Errorf("authorize: %w", err)
		}
		return nil, ErrForbidden
	}
	out := make([]RegistrationOutcome, len(regs))
	for i, r := range regs {
		o := RegistrationOutcome{Provider: r.Provider, ExternalID: r.ExternalID}
		err := s.store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.register(ctx, tx, p, d, tenantID, teamID, r, why, &o)
		})
		if err != nil && !errors.Is(err, errUnchanged) {
			if err = mapErr(err); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			o = RegistrationOutcome{Provider: r.Provider, ExternalID: r.ExternalID, Status: RegistrationFailed, Error: err.Error()}
		}
		out[i] = o
	}
	return out, nil
}

func (s *Service) register(ctx context.Context, tx pgx.Tx, p auth.Principal, d authz.Decision, tenantID, teamID string, r Registration, why string, o *RegistrationOutcome) error {
	if r.Ownership == "" {
		r.Ownership = OwnershipPlatform
	}
	switch {
	case r.ExternalID == "" || r.Name == "":
		return invalid("the account ID and name are required")
	case (r.Project == "") != (r.Environment == ""):
		return invalid("give both a project and an environment, or leave both blank to register the account without one")
	case r.Project != "" && !slugRE.MatchString(r.Project):
		return invalid("project %q must be 2-63 lowercase letters, numbers and dashes, like tat-crm", r.Project)
	case r.Environment != "" && !envNameRE.MatchString(r.Environment):
		return invalid("environment %q must be up to 31 lowercase letters, numbers and dashes, like prod", r.Environment)
	}
	if err := checkOwnership(r.Provider, r.Ownership, r.ReadOnlyRole); err != nil {
		return err
	}
	log := func(typ, op, resType, id, team string) error {
		_, err := activity.Record(ctx, tx, activity.Activity{
			TenantID: tenantID, Source: "keel/catalog", Type: typ, Subject: resType + "/" + id, Operation: op, Kind: activity.Create,
			Actor: actorOf(p), Resources: []activity.Resource{{Type: resType, UID: id, OwnerTeam: team}},
			Why: activity.Why{Reason: why}, Outcome: activity.Success, StatusDetail: d.String(),
		})
		return err
	}

	var envID *string
	if r.Project != "" {
		var projectID, team string
		var archived bool
		err := tx.QueryRow(ctx, `SELECT id::text, team_id::text, archived_at IS NOT NULL FROM projects WHERE slug = $1`, r.Project).Scan(&projectID, &team, &archived)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if !ValidID(teamID) {
				return invalid("choose the team that owns the new project %s", r.Project)
			}
			// projects.team_id references teams(id) across Tenants, so the Team
			// is checked here, under RLS.
			if err := tx.QueryRow(ctx, `SELECT id::text FROM teams WHERE id = $1`, teamID).Scan(&team); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return invalid("that team is not in this organisation")
				}
				return err
			}
			if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, $3, $3) RETURNING id::text`,
				tenantID, teamID, r.Project).Scan(&projectID); err != nil {
				return err
			}
			o.ProjectCreated = true
			if err := log("keel.project.created", "CreateProject", "project", projectID, teamID); err != nil {
				return err
			}
		case err != nil:
			return err
		case archived:
			return invalid("project %s is archived; restore it or choose another project", r.Project)
		}
		var id string
		err = tx.QueryRow(ctx, `SELECT id::text, archived_at IS NOT NULL FROM environments WHERE project_id = $1 AND name = $2`, projectID, r.Environment).Scan(&id, &archived)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, $3) RETURNING id::text`,
				tenantID, projectID, r.Environment).Scan(&id); err != nil {
				return err
			}
			o.EnvironmentCreated = true
			if err := log("keel.environment.created", "CreateEnvironment", "environment", id, team); err != nil {
				return err
			}
		case err != nil:
			return err
		case archived:
			return invalid("environment %s of project %s is archived; choose another environment", r.Environment, r.Project)
		}
		envID = &id
	}

	var a CloudAccount
	err := tx.QueryRow(ctx, `SELECT `+accountCols+` FROM cloud_accounts WHERE provider = $1 AND external_id = $2`, r.Provider, r.ExternalID).
		Scan(&a.ID, &a.TenantID, &a.EnvironmentID, &a.Provider, &a.ExternalID, &a.Name, &a.Ownership, &a.ReadOnlyRole, &a.ArchivedAt)
	switch {
	case err == nil && a.ArchivedAt != nil:
		return fmt.Errorf("%w: account %s is archived here; restore it instead of registering it again", ErrConflict, r.ExternalID)
	case err == nil && equalPtr(a.EnvironmentID, envID):
		*o = RegistrationOutcome{Provider: r.Provider, ExternalID: r.ExternalID, Status: AlreadyRegistered, CloudAccount: &a}
		return errUnchanged
	case err == nil:
		return fmt.Errorf("%w: account %s is already registered under another environment", ErrConflict, r.ExternalID)
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	if err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+accountCols,
		tenantID, envID, r.Provider, r.ExternalID, r.Name, r.Ownership, r.ReadOnlyRole).
		Scan(&a.ID, &a.TenantID, &a.EnvironmentID, &a.Provider, &a.ExternalID, &a.Name, &a.Ownership, &a.ReadOnlyRole, &a.ArchivedAt); err != nil {
		return err
	}
	o.Status, o.CloudAccount = Registered, &a
	return log("keel.cloud_account.created", "CreateCloudAccount", "cloud_account", a.ID, "")
}

func equalPtr(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
