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

// RegisterAccounts registers accounts that discovery found in the caller's
// own Tenant into tenantID, creating the Project (owned by teamID) and
// Environment each names when missing. Every step is authorised exactly as
// its own endpoint authorises it, for every account before any write, so a
// denial anywhere writes nothing. Each account then registers in its own
// transaction; an account already registered at the same place is reported
// unchanged, so a retry converges.
func (s *Service) RegisterAccounts(ctx context.Context, p auth.Principal, tenantID, teamID string, regs []Registration, why string) ([]RegistrationOutcome, error) {
	if len(regs) == 0 || len(regs) > maxRegistrations {
		return nil, invalid("register between 1 and %d accounts at a time", maxRegistrations)
	}
	err := s.store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, r := range regs {
			pl, err := planRegistration(ctx, tx, teamID, r)
			if errors.Is(err, ErrInvalid) {
				continue // reported per account below
			}
			if err != nil {
				return err
			}
			if _, err := s.authorizeSteps(ctx, p, tenantID, teamID, pl, why); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	found := map[[2]string]bool{}
	err = s.read(ctx, p, "cloud_account.discover", authz.Resource{Type: "discovered_account", TenantID: p.TenantID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT provider, external_id FROM discovered_accounts`)
		if err != nil {
			return err
		}
		var k [2]string
		_, err = pgx.ForEachRow(rows, []any{&k[0], &k[1]}, func() error {
			found[k] = true
			return nil
		})
		return err
	})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]RegistrationOutcome, len(regs))
	for i, r := range regs {
		o := RegistrationOutcome{Provider: r.Provider, ExternalID: r.ExternalID}
		err := invalid("account %s was not found by discovery; add it from Cloud accounts instead", r.ExternalID)
		if found[[2]string{r.Provider, r.ExternalID}] {
			err = s.store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
				return s.register(ctx, tx, p, tenantID, teamID, r, why, &o)
			})
		}
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

// registrationPlan is where one Registration lands as the Tenant stands now.
type registrationPlan struct {
	r               Registration
	projectID, team string // the existing Project and its Team; empty when it is new
	projectArchived bool
	envID           string // the existing Environment; empty when it is new
	envArchived     bool
}

func planRegistration(ctx context.Context, tx pgx.Tx, teamID string, r Registration) (registrationPlan, error) {
	pl := registrationPlan{r: r}
	if pl.r.Ownership == "" {
		pl.r.Ownership = OwnershipPlatform
	}
	switch {
	case r.ExternalID == "" || r.Name == "":
		return pl, invalid("the account ID and name are required")
	case (r.Project == "") != (r.Environment == ""):
		return pl, invalid("give both a project and an environment, or leave both blank to register the account without one")
	case r.Project != "" && !slugRE.MatchString(r.Project):
		return pl, invalid("project %q must be 2-63 lowercase letters, numbers and dashes, like tat-crm", r.Project)
	case r.Environment != "" && !envNameRE.MatchString(r.Environment):
		return pl, invalid("environment %q must be up to 31 lowercase letters, numbers and dashes, like prod", r.Environment)
	}
	if err := checkOwnership(r.Provider, pl.r.Ownership, r.ReadOnlyRole); err != nil {
		return pl, err
	}
	if r.Project == "" {
		return pl, nil
	}
	err := tx.QueryRow(ctx, `SELECT id::text, team_id::text, archived_at IS NOT NULL FROM projects WHERE slug = $1`, r.Project).Scan(&pl.projectID, &pl.team, &pl.projectArchived)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if !ValidID(teamID) {
			return pl, invalid("choose the team that owns the new project %s", r.Project)
		}
		return pl, nil
	case err != nil:
		return pl, err
	}
	err = tx.QueryRow(ctx, `SELECT id::text, archived_at IS NOT NULL FROM environments WHERE project_id = $1 AND name = $2`, pl.projectID, r.Environment).Scan(&pl.envID, &pl.envArchived)
	if errors.Is(err, pgx.ErrNoRows) {
		return pl, nil
	}
	return pl, err
}

// authorizeSteps asks the policy about each write the plan needs, with the
// action and resource its own endpoint uses: CreateProject for a new Project,
// CreateEnvironment against the Project's actual Team, CreateCloudAccount
// Tenant-wide. A denial is logged and returned as ErrForbidden.
func (s *Service) authorizeSteps(ctx context.Context, p auth.Principal, tenantID, teamID string, pl registrationPlan, why string) (map[string]authz.Decision, error) {
	var steps []write
	if pl.r.Project != "" {
		team := pl.team
		if pl.projectID == "" {
			team = teamID
			steps = append(steps, write{action: "project.create", res: authz.Resource{Type: "project", TenantID: tenantID, TeamID: teamID}, operation: "CreateProject"})
		}
		if pl.envID == "" {
			steps = append(steps, write{action: "environment.create", res: authz.Resource{Type: "environment", TenantID: tenantID, ProjectID: pl.projectID, TeamID: team}, operation: "CreateEnvironment"})
		}
	}
	steps = append(steps, write{action: "cloud_account.create", res: authz.Resource{Type: "cloud_account", TenantID: tenantID}, operation: "CreateCloudAccount"})
	ds := map[string]authz.Decision{}
	for _, w := range steps {
		w.kind, w.why = activity.Create, why
		d, err := s.authorize(ctx, p, w.action, w.res)
		if err != nil || !d.Allow {
			s.recordDenied(ctx, p, w, d)
			if err != nil {
				return nil, fmt.Errorf("authorize: %w", err)
			}
			return nil, ErrForbidden
		}
		ds[w.action] = d
	}
	return ds, nil
}

// register writes one planned Registration, re-planning and re-authorising
// inside its transaction so a Project changing hands since the batch check
// cannot widen what the caller may do.
func (s *Service) register(ctx context.Context, tx pgx.Tx, p auth.Principal, tenantID, teamID string, r Registration, why string, o *RegistrationOutcome) error {
	pl, err := planRegistration(ctx, tx, teamID, r)
	if err != nil {
		return err
	}
	ds, err := s.authorizeSteps(ctx, p, tenantID, teamID, pl, why)
	if err != nil {
		return err
	}
	r = pl.r
	log := func(action, typ, op, resType, id, team string) error {
		_, err := activity.Record(ctx, tx, activity.Activity{
			TenantID: tenantID, Source: "keel/catalog", Type: typ, Subject: resType + "/" + id, Operation: op, Kind: activity.Create,
			Actor: actorOf(p), Resources: []activity.Resource{{Type: resType, UID: id, OwnerTeam: team}},
			Why: activity.Why{Reason: why}, Outcome: activity.Success, StatusDetail: ds[action].String(),
		})
		return err
	}

	var envID *string
	if r.Project != "" {
		switch {
		case pl.projectArchived:
			return invalid("project %s is archived; restore it or choose another project", r.Project)
		case pl.envArchived:
			return invalid("environment %s of project %s is archived; choose another environment", r.Environment, r.Project)
		}
		if pl.projectID == "" {
			// projects.team_id references teams(id) across Tenants, so the Team
			// is checked here, under RLS.
			if err := tx.QueryRow(ctx, `SELECT id::text FROM teams WHERE id = $1`, teamID).Scan(&pl.team); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return invalid("that team is not in this organisation")
				}
				return err
			}
			if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, $3, $3) RETURNING id::text`,
				tenantID, teamID, r.Project).Scan(&pl.projectID); err != nil {
				return err
			}
			o.ProjectCreated = true
			if err := log("project.create", "keel.project.created", "CreateProject", "project", pl.projectID, teamID); err != nil {
				return err
			}
		}
		if pl.envID == "" {
			if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, $3) RETURNING id::text`,
				tenantID, pl.projectID, r.Environment).Scan(&pl.envID); err != nil {
				return err
			}
			o.EnvironmentCreated = true
			if err := log("environment.create", "keel.environment.created", "CreateEnvironment", "environment", pl.envID, pl.team); err != nil {
				return err
			}
		}
		envID = &pl.envID
	}

	var a CloudAccount
	err = tx.QueryRow(ctx, `SELECT `+accountCols+` FROM cloud_accounts WHERE provider = $1 AND external_id = $2`, r.Provider, r.ExternalID).
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
	return log("cloud_account.create", "keel.cloud_account.created", "CreateCloudAccount", "cloud_account", a.ID, "")
}

func equalPtr(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
