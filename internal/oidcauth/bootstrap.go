package oidcauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// BootstrapInput creates the home Tenant, its identity provider, and maps one
// IdP group to platform_admin. Run once per installation.
type BootstrapInput struct {
	HomeSlug, HomeName                string
	Issuer, ClientID, ClientSecretRef string
	AdminGroup, EmailDomain           string
}

// Bootstrap sets up the home Tenant so the first admin can sign in. It returns
// the home Tenant id and records Activities as actor keel:bootstrap.
func Bootstrap(ctx context.Context, s *store.Store, in BootstrapInput) (string, error) {
	if in.HomeSlug == "" || in.Issuer == "" || in.ClientID == "" || in.ClientSecretRef == "" || in.AdminGroup == "" {
		return "", errors.New("bootstrap: home slug, issuer, client id, client secret ref and admin group are required")
	}
	actor := activity.Actor{Type: activity.ActorKeel, UID: "keel:bootstrap"}
	return s.CreateTenantThen(ctx, in.HomeSlug, in.HomeName, true, func(tx pgx.Tx, home string) error {
		var domain *string
		if in.EmailDomain != "" {
			domain = &in.EmailDomain
		}
		var idp string
		if err := tx.QueryRow(ctx, `INSERT INTO identity_providers (tenant_id, issuer, client_id, client_secret_ref, email_domain) VALUES ($1, $2, $3, $4, $5) RETURNING id::text`,
			home, in.Issuer, in.ClientID, in.ClientSecretRef, domain).Scan(&idp); err != nil {
			return fmt.Errorf("identity provider: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO idp_group_roles (tenant_id, idp_id, group_name, role, target_tenant_id) VALUES ($1, $2, $3, 'platform_admin', $1)`,
			home, idp, in.AdminGroup); err != nil {
			return fmt.Errorf("admin group: %w", err)
		}
		for _, a := range []activity.Activity{
			{Type: "keel.tenant.created", Subject: "tenant/" + home, Operation: "Bootstrap"},
			{Type: "keel.identity_provider.created", Subject: "identity_provider/" + idp, Operation: "Bootstrap"},
			{Type: "keel.idp_group_role.created", Subject: "identity_provider/" + idp, Operation: "Bootstrap", StatusDetail: in.AdminGroup + " → platform_admin"},
		} {
			a.TenantID, a.Source, a.Kind, a.Actor, a.Outcome = home, "keel/bootstrap", activity.Create, actor, activity.Success
			if _, err := activity.Record(ctx, tx, a); err != nil {
				return err
			}
		}
		return nil
	})
}
