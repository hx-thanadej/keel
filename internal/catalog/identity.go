package catalog

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
)

// IdentityProvider is a Tenant's OIDC sign-in configuration.
type IdentityProvider struct {
	ID              string  `json:"id"`
	TenantID        string  `json:"tenant_id"`
	Issuer          string  `json:"issuer"`
	ClientID        string  `json:"client_id"`
	ClientSecretRef string  `json:"client_secret_ref"`
	GroupsClaim     string  `json:"groups_claim"`
	EmailDomain     *string `json:"email_domain"`
}

// GroupRole maps an IdP group to a role Binding.
type GroupRole struct {
	ID             string   `json:"id"`
	IdPID          string   `json:"idp_id"`
	Group          string   `json:"group"`
	Role           string   `json:"role"`
	TargetTenantID string   `json:"target_tenant_id"`
	TeamIDs        []string `json:"team_ids"`
}

var roles = map[string]bool{auth.RolePlatformAdmin: true, auth.RoleSecurityLead: true, auth.RoleFinOpsLead: true,
	auth.RoleTeamLead: true, auth.RoleEngineer: true, auth.RoleTenantViewer: true, auth.RoleTenantApprover: true}

// CreateIdentityProvider registers an OIDC issuer for a Tenant.
func (s *Service) CreateIdentityProvider(ctx context.Context, p auth.Principal, tenantID string, in IdentityProvider, why string) (IdentityProvider, error) {
	if !strings.HasPrefix(in.Issuer, "https://") && !strings.HasPrefix(in.Issuer, "http://") || in.ClientID == "" || in.ClientSecretRef == "" {
		return IdentityProvider{}, invalid("issuer (http/https URL), client_id and client_secret_ref are required")
	}
	if in.GroupsClaim == "" {
		in.GroupsClaim = "groups"
	}
	out := in
	out.TenantID = tenantID
	err := s.do(ctx, p, write{action: "identity_provider.create", res: authz.Resource{Type: "identity_provider", TenantID: tenantID},
		actType: "keel.identity_provider.created", operation: "CreateIdentityProvider", kind: activity.Create, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `INSERT INTO identity_providers (tenant_id, issuer, client_id, client_secret_ref, groups_claim, email_domain)
				VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`, tenantID, in.Issuer, in.ClientID, in.ClientSecretRef, in.GroupsClaim, in.EmailDomain).Scan(&out.ID)
			return out.ID, err
		})
	return out, mapErr(err)
}

// ListIdentityProviders lists a Tenant's active identity providers.
func (s *Service) ListIdentityProviders(ctx context.Context, p auth.Principal, tenantID string) ([]IdentityProvider, error) {
	var out []IdentityProvider
	err := s.read(ctx, p, "identity_provider.read", authz.Resource{Type: "identity_provider", TenantID: tenantID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, issuer, client_id, client_secret_ref, groups_claim, email_domain
			FROM identity_providers WHERE archived_at IS NULL ORDER BY created_at`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[IdentityProvider])
		return err
	})
	return out, mapErr(err)
}

// AddGroupRole maps an IdP group to a role in a target Tenant.
func (s *Service) AddGroupRole(ctx context.Context, p auth.Principal, tenantID, idpID string, in GroupRole, why string) (GroupRole, error) {
	if in.Group == "" || !roles[in.Role] || !ValidID(in.TargetTenantID) {
		return GroupRole{}, invalid("group, a known role and target_tenant_id are required")
	}
	for _, t := range in.TeamIDs {
		if !ValidID(t) {
			return GroupRole{}, invalid("team_ids must be uuids")
		}
	}
	if in.TeamIDs == nil {
		in.TeamIDs = []string{}
	}
	out := in
	out.IdPID = idpID
	err := s.do(ctx, p, write{action: "identity_provider.update", res: authz.Resource{Type: "identity_provider", ID: idpID, TenantID: tenantID},
		actType: "keel.idp_group_role.created", operation: "AddGroupRole", kind: activity.Create, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `INSERT INTO idp_group_roles (tenant_id, idp_id, group_name, role, target_tenant_id, team_ids)
				VALUES ($1, $2, $3, $4, $5, $6::uuid[]) RETURNING id::text`, tenantID, idpID, in.Group, in.Role, in.TargetTenantID, in.TeamIDs).Scan(&out.ID)
			return out.ID, err
		})
	return out, mapErr(err)
}
