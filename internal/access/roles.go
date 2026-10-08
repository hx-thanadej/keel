package access

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

//go:embed policy.rego
var policySrc string

// Service manages roles and grants.
type Service struct {
	Store     *store.Store
	Directory Directory
	Now       func() time.Time

	role, grant rego.PreparedEvalQuery
}

// New compiles the access policy.
func New(st *store.Store, dir Directory) (*Service, error) {
	s := &Service{Store: st, Directory: dir, Now: time.Now}
	var err error
	if s.role, err = rego.New(rego.Query("data.keel.access.role"), rego.Module("access.rego", policySrc)).PrepareForEval(context.Background()); err != nil {
		return nil, fmt.Errorf("compile access policy: %w", err)
	}
	if s.grant, err = rego.New(rego.Query("data.keel.access.grant"), rego.Module("access.rego", policySrc)).PrepareForEval(context.Background()); err != nil {
		return nil, fmt.Errorf("compile access policy: %w", err)
	}
	return s, nil
}

func eval[T any](ctx context.Context, q rego.PreparedEvalQuery, input any) (T, error) {
	var out T
	rs, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return out, err
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return out, errors.New("access policy: no decision")
	}
	raw, _ := json.Marshal(rs[0].Expressions[0].Value)
	return out, json.Unmarshal(raw, &out)
}

// Role is a Team's eligibility for a template in an Environment.
type Role struct {
	ID                string       `json:"id"`
	EnvironmentID     string       `json:"environment_id"`
	TeamID            string       `json:"team_id"`
	Template          string       `json:"template"`
	State             string       `json:"state"`
	Decision          RoleDecision `json:"decision"`
	RoleConfiguration *string      `json:"role_configuration"`
	RequestedBy       string       `json:"requested_by"`
	DecidedBy         *string      `json:"decided_by"`
	CreatedAt         time.Time    `json:"created_at"`
}

// RoleDecision is the policy's answer for eligibility.
type RoleDecision struct {
	Allow         bool     `json:"allow"`
	Reasons       []string `json:"reasons"`
	NeedsApproval bool     `json:"needs_approval"`
	Approvers     []string `json:"approvers"`
	Policy        string   `json:"policy"`
}

const roleCols = `id::text, environment_id::text, team_id::text, template, state, decision, role_configuration, requested_by, decided_by, created_at`

func scanRole(r pgx.Row) (Role, error) {
	var x Role
	var d []byte
	err := r.Scan(&x.ID, &x.EnvironmentID, &x.TeamID, &x.Template, &x.State, &d, &x.RoleConfiguration, &x.RequestedBy, &x.DecidedBy, &x.CreatedAt)
	_ = json.Unmarshal(d, &x.Decision)
	return x, err
}

func isProd(name string) bool { return name == "prod" || name == "production" || name == "prd" }

func record(ctx context.Context, tx pgx.Tx, tenant, typ, op, subject string, kind activity.Kind, outcome activity.Outcome, by activity.Actor, detail string, res ...activity.Resource) error {
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/access", Type: typ, Subject: subject, Operation: op,
		Kind: kind, Actor: by, Outcome: outcome, Resources: res, StatusDetail: detail, Why: activity.Why{Reason: detail}})
	return err
}

// RequestRole asks for a Team to be eligible for a template in an
// Environment. Low-risk eligibility is active at once; write access to
// production waits for a Platform Admin or Security Lead.
func (s *Service) RequestRole(ctx context.Context, tenant, env, team, template string, by activity.Actor) (Role, error) {
	t, ok := Templates[template]
	if !ok {
		return Role{}, fmt.Errorf("%w: unknown template %q", ErrInvalid, template)
	}
	var r Role
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var envName string
		err := tx.QueryRow(ctx, `SELECT e.name FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.id = $1 AND e.archived_at IS NULL
			AND EXISTS (SELECT 1 FROM teams WHERE id = $2)`, env, team).Scan(&envName)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		existing, err := scanRole(tx.QueryRow(ctx, `SELECT `+roleCols+` FROM access_roles WHERE environment_id = $1 AND team_id = $2 AND template = $3 AND state IN ('requested', 'active')`, env, team, template))
		if err == nil {
			r = existing
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		d, err := eval[RoleDecision](ctx, s.role, map[string]any{"template": t, "environment": map[string]any{"prod": isProd(envName)}})
		if err != nil {
			return err
		}
		state := "active"
		if d.NeedsApproval {
			state = "requested"
		}
		raw, _ := json.Marshal(d)
		if r, err = scanRole(tx.QueryRow(ctx, `INSERT INTO access_roles (tenant_id, environment_id, team_id, template, state, decision, requested_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+roleCols, tenant, env, team, template, state, raw, by.UID)); err != nil {
			return err
		}
		return record(ctx, tx, tenant, "keel.access.role_requested", "RequestRole", "access_role/"+r.ID, activity.Create, activity.Success, by,
			fmt.Sprintf("%s in %s: %s", template, envName, state), activity.Resource{Type: "access_role", UID: r.ID}, activity.Resource{Type: "team", UID: team})
	})
	if err != nil || r.State != "active" || r.RoleConfiguration != nil {
		return r, err
	}
	return s.provision(ctx, tenant, r)
}

// DecideRole approves or denies a requested eligibility.
func (s *Service) DecideRole(ctx context.Context, tenant, id string, approve bool, by activity.Actor) (Role, error) {
	var r Role
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		cur, err := scanRole(tx.QueryRow(ctx, `SELECT `+roleCols+` FROM access_roles WHERE id = $1 FOR UPDATE`, id))
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
			return fmt.Errorf("%w: the requester cannot decide", ErrState)
		}
		state := "denied"
		if approve {
			state = "active"
		}
		if r, err = scanRole(tx.QueryRow(ctx, `UPDATE access_roles SET state = $2, decided_by = $3, decided_at = now() WHERE id = $1 RETURNING `+roleCols, id, state, by.UID)); err != nil {
			return err
		}
		return record(ctx, tx, tenant, "keel.access.role_decided", "DecideRole", "access_role/"+id, activity.Update, activity.Success, by, cur.Template+": "+state,
			activity.Resource{Type: "access_role", UID: id})
	})
	if err != nil || r.State != "active" {
		return r, err
	}
	return s.provision(ctx, tenant, r)
}

// provision ensures the template's Identity Center role configuration. No
// one is assigned to it here: that is what an Access Grant does.
func (s *Service) provision(ctx context.Context, tenant string, r Role) (Role, error) {
	if s.Directory == nil {
		return r, nil // recorded; provisioned when Identity Center is configured
	}
	t := Templates[r.Template]
	id, err := s.Directory.EnsureRoleConfiguration(ctx, t.RoleConfigurationName(), "Keel: "+t.Description, t.PolicyDocument(), t.MaxHours)
	if err != nil {
		return r, fmt.Errorf("role configuration: %w", err)
	}
	err = s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		r, err = scanRole(tx.QueryRow(ctx, `UPDATE access_roles SET role_configuration = $2 WHERE id = $1 RETURNING `+roleCols, r.ID, id))
		return err
	})
	return r, err
}

// Roles lists eligibilities.
func (s *Service) Roles(ctx context.Context, tenant string) ([]Role, error) {
	var out []Role
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+roleCols+` FROM access_roles ORDER BY created_at DESC LIMIT 500`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Role, error) { return scanRole(r) })
		return err
	})
	return out, err
}
