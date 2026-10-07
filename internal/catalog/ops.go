package catalog

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
)

// ---------- Tenants ----------

// CreateTenant registers a client organisation.
func (s *Service) CreateTenant(ctx context.Context, p auth.Principal, slug, name, why string) (Tenant, error) {
	if !slugRE.MatchString(slug) || name == "" {
		return Tenant{}, invalid("slug must match %s and name is required", slugRE)
	}
	res := authz.Resource{Type: "tenant"}
	d, err := s.authorize(ctx, p, "tenant.create", res)
	if err != nil || !d.Allow {
		s.recordDenied(ctx, p, write{action: "tenant.create", res: res, operation: "CreateTenant", kind: activity.Create, why: why}, d)
		if err != nil {
			return Tenant{}, err
		}
		return Tenant{}, ErrForbidden
	}
	var t Tenant
	_, err = s.store.CreateTenantThen(ctx, slug, name, false, func(tx pgx.Tx, id string) error {
		if err := tx.QueryRow(ctx, `SELECT id::text, slug, name, is_home, created_at FROM tenants WHERE id = $1`, id).
			Scan(&t.ID, &t.Slug, &t.Name, &t.IsHome, &t.CreatedAt); err != nil {
			return err
		}
		_, err := activity.Record(ctx, tx, activity.Activity{
			TenantID: id, Source: "keel/catalog", Type: "keel.tenant.created", Subject: "tenant/" + id,
			Operation: "CreateTenant", Kind: activity.Create, Actor: actorOf(p),
			Resources: []activity.Resource{{Type: "tenant", UID: id}},
			Why:       activity.Why{Reason: why}, Outcome: activity.Success, StatusDetail: d.String(),
		})
		return err
	})
	return t, mapErr(err)
}

// GetTenant reads one Tenant.
func (s *Service) GetTenant(ctx context.Context, p auth.Principal, id string) (Tenant, error) {
	var t Tenant
	err := s.read(ctx, p, "tenant.read", authz.Resource{Type: "tenant", ID: id, TenantID: id}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text, slug, name, is_home, created_at FROM tenants WHERE id = $1`, id).
			Scan(&t.ID, &t.Slug, &t.Name, &t.IsHome, &t.CreatedAt)
	})
	return t, mapErr(err)
}

// ---------- Teams ----------

// CreateTeam adds a Team to a Tenant.
func (s *Service) CreateTeam(ctx context.Context, p auth.Principal, tenantID, slug, name, why string) (Team, error) {
	if !slugRE.MatchString(slug) || name == "" {
		return Team{}, invalid("slug must match %s and name is required", slugRE)
	}
	t := Team{TenantID: tenantID, Slug: slug, Name: name}
	err := s.do(ctx, p, write{action: "team.create", res: authz.Resource{Type: "team", TenantID: tenantID},
		actType: "keel.team.created", operation: "CreateTeam", kind: activity.Create, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, $2, $3) RETURNING id::text`, tenantID, slug, name).Scan(&t.ID)
			return t.ID, err
		})
	return t, mapErr(err)
}

// ListTeams lists a Tenant's Teams.
func (s *Service) ListTeams(ctx context.Context, p auth.Principal, tenantID string) ([]Team, error) {
	var out []Team
	err := s.read(ctx, p, "team.read", authz.Resource{Type: "team", TenantID: tenantID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, slug, name FROM teams ORDER BY slug`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Team])
		return err
	})
	return out, mapErr(err)
}

// ---------- Projects ----------

const projectCols = `id::text, tenant_id::text, team_id::text, slug, name, archived_at`

// CreateProject adds a Project delivered by teamID.
func (s *Service) CreateProject(ctx context.Context, p auth.Principal, tenantID, teamID, slug, name, why string) (Project, error) {
	if !slugRE.MatchString(slug) || name == "" || !ValidID(teamID) {
		return Project{}, invalid("slug must match %s; name and a valid team_id are required", slugRE)
	}
	var pr Project
	err := s.do(ctx, p, write{action: "project.create", res: authz.Resource{Type: "project", TenantID: tenantID, TeamID: teamID},
		actType: "keel.project.created", operation: "CreateProject", kind: activity.Create, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, $3, $4) RETURNING `+projectCols,
				tenantID, teamID, slug, name).Scan(&pr.ID, &pr.TenantID, &pr.TeamID, &pr.Slug, &pr.Name, &pr.ArchivedAt)
			return pr.ID, err
		})
	return pr, mapErr(err)
}

// projectTeam looks up a Project's Team for authorisation. It runs before the
// decision, so a missing Project yields "" rather than an error: the caller
// then gets the policy's answer (403) or, if allowed, not-found from the write.
// Existence is never revealed to someone the policy would deny.
func (s *Service) projectTeam(ctx context.Context, tenantID, projectID string) (string, error) {
	var team string
	err := s.store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT team_id::text FROM projects WHERE id = $1`, projectID).Scan(&team)
	})
	if err != nil && !errors.Is(mapErr(err), ErrNotFound) {
		return "", mapErr(err)
	}
	return team, nil
}

// ProjectTeam returns a Project's delivering Team ("" if none or missing),
// for other modules' authorisation checks.
func (s *Service) ProjectTeam(ctx context.Context, tenantID, projectID string) (string, error) {
	return s.projectTeam(ctx, tenantID, projectID)
}

// SetTenantCurrency changes the currency Budgets and reports use.
func (s *Service) SetTenantCurrency(ctx context.Context, p auth.Principal, tenantID, currency, why string) (Tenant, error) {
	if currency != "USD" && currency != "THB" {
		return Tenant{}, invalid("currency must be USD or THB")
	}
	var t Tenant
	err := s.do(ctx, p, write{action: "tenant.update", res: authz.Resource{Type: "tenant", ID: tenantID, TenantID: tenantID},
		actType: "keel.tenant.currency_changed", operation: "SetTenantCurrency", kind: activity.Update, why: why + " → " + currency},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `UPDATE tenants SET currency = $2 WHERE id = $1 RETURNING id::text, slug, name, is_home, created_at`, tenantID, currency).
				Scan(&t.ID, &t.Slug, &t.Name, &t.IsHome, &t.CreatedAt)
			return tenantID, err
		})
	return t, mapErr(err)
}

// SetTenantTimeZone sets the IANA time zone schedules are expressed in.
func (s *Service) SetTenantTimeZone(ctx context.Context, p auth.Principal, tenantID, zone, why string) (Tenant, error) {
	if _, err := time.LoadLocation(zone); err != nil || zone == "" || zone == "Local" {
		return Tenant{}, invalid("time_zone must be an IANA time zone such as Asia/Bangkok")
	}
	var t Tenant
	err := s.do(ctx, p, write{action: "tenant.update", res: authz.Resource{Type: "tenant", ID: tenantID, TenantID: tenantID},
		actType: "keel.tenant.time_zone_changed", operation: "SetTenantTimeZone", kind: activity.Update, why: why + " → " + zone},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `UPDATE tenants SET time_zone = $2 WHERE id = $1 RETURNING id::text, slug, name, is_home, created_at`, tenantID, zone).
				Scan(&t.ID, &t.Slug, &t.Name, &t.IsHome, &t.CreatedAt)
			return tenantID, err
		})
	return t, mapErr(err)
}

// ListServices lists active Services.
func (s *Service) ListServices(ctx context.Context, p auth.Principal, tenantID string) ([]ServiceEntry, error) {
	var out []ServiceEntry
	err := s.read(ctx, p, "service.read", authz.Resource{Type: "service", TenantID: tenantID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, project_id::text, team_id::text, slug, name, repository, template, template_version
			FROM services WHERE archived_at IS NULL ORDER BY slug`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[ServiceEntry])
		return err
	})
	return out, mapErr(err)
}

// ListProjects lists active Projects.
func (s *Service) ListProjects(ctx context.Context, p auth.Principal, tenantID string) ([]Project, error) {
	var out []Project
	err := s.read(ctx, p, "project.read", authz.Resource{Type: "project", TenantID: tenantID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+projectCols+` FROM projects WHERE archived_at IS NULL ORDER BY slug`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Project])
		return err
	})
	return out, mapErr(err)
}

// GetProject reads one Project.
func (s *Service) GetProject(ctx context.Context, p auth.Principal, tenantID, id string) (Project, error) {
	var pr Project
	err := s.read(ctx, p, "project.read", authz.Resource{Type: "project", ID: id, TenantID: tenantID}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT `+projectCols+` FROM projects WHERE id = $1`, id).
			Scan(&pr.ID, &pr.TenantID, &pr.TeamID, &pr.Slug, &pr.Name, &pr.ArchivedAt)
	})
	return pr, mapErr(err)
}

// RenameProject changes a Project's display name.
func (s *Service) RenameProject(ctx context.Context, p auth.Principal, tenantID, id, name, why string) (Project, error) {
	if name == "" {
		return Project{}, invalid("name is required")
	}
	return s.mutateProject(ctx, p, tenantID, id, "project.update", "keel.project.updated", "UpdateProject", activity.Update, why,
		`UPDATE projects SET name = $2 WHERE id = $1 RETURNING `+projectCols, name)
}

// SetConfigRepo names the Project's GitOps config repository ("owner/name"),
// where Promotions open pull requests (#93).
func (s *Service) SetConfigRepo(ctx context.Context, p auth.Principal, tenantID, id, repo, why string) (Project, error) {
	if repo != "" && !configRepoRe.MatchString(repo) {
		return Project{}, invalid("config_repo must be owner/name")
	}
	return s.mutateProject(ctx, p, tenantID, id, "project.update", "keel.project.config_repo_changed", "SetConfigRepo", activity.Update, fmt.Sprintf("%s (config_repo=%s)", why, repo),
		`UPDATE projects SET config_repo = $2 WHERE id = $1 RETURNING `+projectCols, repo)
}

var configRepoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// ArchiveProject hides a Project from lists. Nothing is deleted.
func (s *Service) ArchiveProject(ctx context.Context, p auth.Principal, tenantID, id, why string) (Project, error) {
	return s.mutateProject(ctx, p, tenantID, id, "project.archive", "keel.project.archived", "ArchiveProject", activity.Update, why,
		`UPDATE projects SET archived_at = coalesce(archived_at, now()) WHERE id = $1 RETURNING `+projectCols)
}

func (s *Service) mutateProject(ctx context.Context, p auth.Principal, tenantID, id, action, actType, op string, kind activity.Kind, why, sql string, args ...any) (Project, error) {
	team, err := s.projectTeam(ctx, tenantID, id)
	if err != nil {
		return Project{}, err
	}
	var pr Project
	err = s.do(ctx, p, write{action: action, res: authz.Resource{Type: "project", ID: id, TenantID: tenantID, TeamID: team},
		actType: actType, operation: op, kind: kind, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, sql, append([]any{id}, args...)...).
				Scan(&pr.ID, &pr.TenantID, &pr.TeamID, &pr.Slug, &pr.Name, &pr.ArchivedAt)
			return id, err
		})
	return pr, mapErr(err)
}

// ---------- Environments ----------

const envCols = `id::text, tenant_id::text, project_id::text, name, archived_at`

// CreateEnvironment adds an Environment to a Project.
func (s *Service) CreateEnvironment(ctx context.Context, p auth.Principal, tenantID, projectID, name, why string) (Environment, error) {
	team, err := s.projectTeam(ctx, tenantID, projectID)
	if err != nil {
		return Environment{}, err
	}
	var e Environment
	err = s.do(ctx, p, write{action: "environment.create", res: authz.Resource{Type: "environment", TenantID: tenantID, ProjectID: projectID, TeamID: team},
		actType: "keel.environment.created", operation: "CreateEnvironment", kind: activity.Create, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, $3) RETURNING `+envCols,
				tenantID, projectID, name).Scan(&e.ID, &e.TenantID, &e.ProjectID, &e.Name, &e.ArchivedAt)
			return e.ID, err
		})
	return e, mapErr(err)
}

// ListEnvironments lists a Project's active Environments.
func (s *Service) ListEnvironments(ctx context.Context, p auth.Principal, tenantID, projectID string) ([]Environment, error) {
	var out []Environment
	err := s.read(ctx, p, "environment.read", authz.Resource{Type: "environment", TenantID: tenantID, ProjectID: projectID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+envCols+` FROM environments WHERE project_id = $1 AND archived_at IS NULL ORDER BY name`, projectID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Environment])
		return err
	})
	return out, mapErr(err)
}

// ArchiveEnvironment archives an Environment.
func (s *Service) ArchiveEnvironment(ctx context.Context, p auth.Principal, tenantID, projectID, id, why string) (Environment, error) {
	team, err := s.projectTeam(ctx, tenantID, projectID)
	if err != nil {
		return Environment{}, err
	}
	var e Environment
	err = s.do(ctx, p, write{action: "environment.archive", res: authz.Resource{Type: "environment", ID: id, TenantID: tenantID, ProjectID: projectID, TeamID: team},
		actType: "keel.environment.archived", operation: "ArchiveEnvironment", kind: activity.Update, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `UPDATE environments SET archived_at = coalesce(archived_at, now()) WHERE id = $1 AND project_id = $2 RETURNING `+envCols, id, projectID).
				Scan(&e.ID, &e.TenantID, &e.ProjectID, &e.Name, &e.ArchivedAt)
			return id, err
		})
	return e, mapErr(err)
}

// SetWasteCleanup opts an Environment in or out of automatic waste cleanup
// (#72). Production Environments cannot opt in.
func (s *Service) SetWasteCleanup(ctx context.Context, p auth.Principal, tenantID, projectID, id string, on bool, why string) (Environment, error) {
	team, err := s.projectTeam(ctx, tenantID, projectID)
	if err != nil {
		return Environment{}, err
	}
	var e Environment
	err = s.do(ctx, p, write{action: "environment.update", res: authz.Resource{Type: "environment", ID: id, TenantID: tenantID, ProjectID: projectID, TeamID: team},
		actType: "keel.environment.waste_cleanup_changed", operation: "SetWasteCleanup", kind: activity.Update, why: fmt.Sprintf("%s (waste_cleanup=%v)", why, on)},
		func(tx pgx.Tx) (string, error) {
			var name string
			if err := tx.QueryRow(ctx, `SELECT name FROM environments WHERE id = $1 AND project_id = $2`, id, projectID).Scan(&name); err != nil {
				return "", err
			}
			if on && (name == "prod" || name == "production" || name == "prd") {
				return "", invalid("production Environments cannot enable automatic waste cleanup")
			}
			err := tx.QueryRow(ctx, `UPDATE environments SET waste_cleanup = $3 WHERE id = $1 AND project_id = $2 RETURNING `+envCols, id, projectID, on).
				Scan(&e.ID, &e.TenantID, &e.ProjectID, &e.Name, &e.ArchivedAt)
			return id, err
		})
	return e, mapErr(err)
}

// SetPromotionPath places an Environment in its Project's promotion order
// (nil removes it) and says whether promotions into it need a Tenant
// Approver. Only a Platform Admin may change the approval requirement.
func (s *Service) SetPromotionPath(ctx context.Context, p auth.Principal, tenantID, projectID, id string, order *int, requiresApproval *bool, why string) (Environment, error) {
	team, err := s.projectTeam(ctx, tenantID, projectID)
	if err != nil {
		return Environment{}, err
	}
	action := "environment.update"
	if requiresApproval != nil {
		action = "environment.set_approval"
	}
	var e Environment
	err = s.do(ctx, p, write{action: action, res: authz.Resource{Type: "environment", ID: id, TenantID: tenantID, ProjectID: projectID, TeamID: team},
		actType: "keel.environment.promotion_path_changed", operation: "SetPromotionPath", kind: activity.Update, why: fmt.Sprintf("%s (order=%v approval=%v)", why, derefInt(order), derefBool(requiresApproval))},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `UPDATE environments SET promotion_order = CASE WHEN $3 THEN $4 ELSE promotion_order END,
					requires_approval = coalesce($5, requires_approval)
				WHERE id = $1 AND project_id = $2 RETURNING `+envCols, id, projectID, order != nil, order, requiresApproval).
				Scan(&e.ID, &e.TenantID, &e.ProjectID, &e.Name, &e.ArchivedAt)
			return id, err
		})
	return e, mapErr(err)
}

func derefInt(p *int) any {
	if p == nil {
		return "unchanged"
	}
	return *p
}

func derefBool(p *bool) any {
	if p == nil {
		return "unchanged"
	}
	return *p
}

// ---------- Cloud Accounts ----------

const accountCols = `id::text, tenant_id::text, environment_id::text, provider, external_id, name, archived_at`

// CreateCloudAccount registers a provider account; environmentID nil means platform-owned.
func (s *Service) CreateCloudAccount(ctx context.Context, p auth.Principal, tenantID string, environmentID *string, provider, externalID, name, why string) (CloudAccount, error) {
	if externalID == "" || name == "" {
		return CloudAccount{}, invalid("external_id and name are required")
	}
	if environmentID != nil && !ValidID(*environmentID) {
		return CloudAccount{}, invalid("environment_id must be a uuid")
	}
	var a CloudAccount
	err := s.do(ctx, p, write{action: "cloud_account.create", res: authz.Resource{Type: "cloud_account", TenantID: tenantID},
		actType: "keel.cloud_account.created", operation: "CreateCloudAccount", kind: activity.Create, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, $3, $4, $5) RETURNING `+accountCols,
				tenantID, environmentID, provider, externalID, name).Scan(&a.ID, &a.TenantID, &a.EnvironmentID, &a.Provider, &a.ExternalID, &a.Name, &a.ArchivedAt)
			return a.ID, err
		})
	return a, mapErr(err)
}

// ListCloudAccounts lists a Tenant's active Cloud Accounts.
func (s *Service) ListCloudAccounts(ctx context.Context, p auth.Principal, tenantID string) ([]CloudAccount, error) {
	var out []CloudAccount
	err := s.read(ctx, p, "cloud_account.read", authz.Resource{Type: "cloud_account", TenantID: tenantID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+accountCols+` FROM cloud_accounts WHERE archived_at IS NULL ORDER BY provider, name`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[CloudAccount])
		return err
	})
	return out, mapErr(err)
}

// ArchiveCloudAccount archives a Cloud Account.
func (s *Service) ArchiveCloudAccount(ctx context.Context, p auth.Principal, tenantID, id, why string) (CloudAccount, error) {
	var a CloudAccount
	err := s.do(ctx, p, write{action: "cloud_account.archive", res: authz.Resource{Type: "cloud_account", ID: id, TenantID: tenantID},
		actType: "keel.cloud_account.archived", operation: "ArchiveCloudAccount", kind: activity.Update, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `UPDATE cloud_accounts SET archived_at = coalesce(archived_at, now()) WHERE id = $1 RETURNING `+accountCols, id).
				Scan(&a.ID, &a.TenantID, &a.EnvironmentID, &a.Provider, &a.ExternalID, &a.Name, &a.ArchivedAt)
			return id, err
		})
	return a, mapErr(err)
}

// ---------- Activities ----------

// ListActivities reads a Tenant's Activity Log.
func (s *Service) ListActivities(ctx context.Context, p auth.Principal, tenantID string, f activity.Filter) ([]activity.Stored, error) {
	var out []activity.Stored
	err := s.read(ctx, p, "activity.read", authz.Resource{Type: "activity", TenantID: tenantID}, func(tx pgx.Tx) error {
		var err error
		out, err = activity.List(ctx, tx, f)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list activities: %w", err)
	}
	return out, nil
}
