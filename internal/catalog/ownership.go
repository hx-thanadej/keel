package catalog

import (
	"context"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
)

// Ownership says whose organisation a Cloud Account lives in (ADR-0018).
type Ownership string

const (
	// OwnershipPlatform accounts are vended and governed by Keel.
	OwnershipPlatform Ownership = "platform"
	// OwnershipClient accounts sit in the Tenant's own organisation. Keel
	// holds only a read-only role there and never mutates them.
	OwnershipClient Ownership = "client"
)

// ReadOnlyRole references the read-only role a client granted Keel. It is
// an identifier Keel assumes keylessly, never a credential. Exactly the
// fields for the account's provider are set:
// tencent, aws and alibaba use RoleARN; azure uses TenantID and ClientID;
// gcp uses WorkloadIdentityProvider and ServiceAccount.
type ReadOnlyRole struct {
	RoleARN                  string `json:"role_arn,omitempty"`
	TenantID                 string `json:"tenant_id,omitempty"`
	ClientID                 string `json:"client_id,omitempty"`
	WorkloadIdentityProvider string `json:"workload_identity_provider,omitempty"`
	ServiceAccount           string `json:"service_account,omitempty"`
}

var (
	roleARNRE = map[string]*regexp.Regexp{
		"tencent": regexp.MustCompile(`^qcs::cam::uin/\d{1,20}:roleName/[\w+=,.@-]{1,128}$`),
		"aws":     regexp.MustCompile(`^arn:aws(-cn|-us-gov)?:iam::\d{12}:role/([\w+=,.@-]{1,128}/)*[\w+=,.@-]{1,64}$`),
		"alibaba": regexp.MustCompile(`^acs:ram::\d{1,20}:role/[\w.-]{1,64}$`),
	}
	uuidRE           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	gcpWIFProviderRE = regexp.MustCompile(`^projects/\d{1,20}/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$`)
	gcpSARE          = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
)

// checkOwnership rejects a combination the database would also refuse, with
// a message that says what the provider expects.
func checkOwnership(provider string, o Ownership, r *ReadOnlyRole) error {
	switch o {
	case OwnershipPlatform:
		if r != nil {
			return invalid("a platform-owned Cloud Account has no read_only_role")
		}
		return nil
	case OwnershipClient:
		if r == nil {
			return invalid("a client-owned Cloud Account requires a read_only_role")
		}
	default:
		return invalid("ownership must be platform or client")
	}
	only := func(set ...string) bool {
		got := map[string]string{"role_arn": r.RoleARN, "tenant_id": r.TenantID, "client_id": r.ClientID,
			"workload_identity_provider": r.WorkloadIdentityProvider, "service_account": r.ServiceAccount}
		for _, k := range set {
			delete(got, k)
		}
		for _, v := range got {
			if v != "" {
				return false
			}
		}
		return true
	}
	switch provider {
	case "tencent", "aws", "alibaba":
		if !only("role_arn") || !roleARNRE[provider].MatchString(r.RoleARN) {
			return invalid("a client-owned %s Cloud Account needs read_only_role.role_arn matching %s", provider, roleARNRE[provider])
		}
	case "azure":
		if !only("tenant_id", "client_id") || !uuidRE.MatchString(r.TenantID) || !uuidRE.MatchString(r.ClientID) {
			return invalid("a client-owned azure Cloud Account needs read_only_role.tenant_id and client_id as uuids")
		}
	case "gcp":
		if !only("workload_identity_provider", "service_account") || !gcpWIFProviderRE.MatchString(r.WorkloadIdentityProvider) || !gcpSARE.MatchString(r.ServiceAccount) {
			return invalid("a client-owned gcp Cloud Account needs read_only_role.workload_identity_provider (projects/N/locations/global/workloadIdentityPools/P/providers/X) and service_account (name@project.iam.gserviceaccount.com)")
		}
	default:
		return invalid("provider must be one of tencent, aws, azure, gcp, alibaba")
	}
	return nil
}

// SetCloudAccountOwnership records whose organisation a Cloud Account is in
// and, for a client-owned one, the read-only role the client granted.
func (s *Service) SetCloudAccountOwnership(ctx context.Context, p auth.Principal, tenantID, id string, o Ownership, role *ReadOnlyRole, why string) (CloudAccount, error) {
	w := write{action: "cloud_account.update", res: authz.Resource{Type: "cloud_account", ID: id, TenantID: tenantID},
		operation: "SetCloudAccountOwnership", kind: activity.Update, why: why}
	d, err := s.authorize(ctx, p, w.action, w.res)
	if err != nil || !d.Allow {
		s.recordDenied(ctx, p, w, d)
		if err != nil {
			return CloudAccount{}, fmt.Errorf("authorize: %w", err)
		}
		return CloudAccount{}, ErrForbidden
	}
	var a CloudAccount
	err = s.store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var provider string
		var was Ownership
		if err := tx.QueryRow(ctx, `SELECT provider, ownership FROM cloud_accounts WHERE id = $1 AND archived_at IS NULL FOR UPDATE`, id).Scan(&provider, &was); err != nil {
			return err
		}
		if err := checkOwnership(provider, o, role); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE cloud_accounts SET ownership = $2, read_only_role = $3 WHERE id = $1 RETURNING `+accountCols, id, o, role).
			Scan(&a.ID, &a.TenantID, &a.EnvironmentID, &a.Provider, &a.ExternalID, &a.Name, &a.Ownership, &a.ReadOnlyRole, &a.ArchivedAt); err != nil {
			return err
		}
		_, err := activity.Record(ctx, tx, activity.Activity{
			TenantID: tenantID, Source: "keel/catalog", Type: "keel.cloud_account.ownership_changed",
			Subject: "cloud_account/" + id, Operation: w.operation, Kind: w.kind, Actor: actorOf(p),
			Resources: []activity.Resource{{Type: "cloud_account", UID: id}},
			Why:       activity.Why{Reason: why}, Outcome: activity.Success,
			StatusDetail: fmt.Sprintf("ownership %s → %s; %s", was, o, d),
		})
		return err
	})
	return a, mapErr(err)
}

// Querier is what IsClientOwned needs: a pgx.Tx inside a Tenant's scope.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// IsClientOwned reports whether a Cloud Account sits in a client-owned
// organisation, where every mutating flow must refuse to act (ADR-0018). q
// must be scoped to the account's Tenant. A missing account is ErrNotFound,
// so a guard fails closed.
func IsClientOwned(ctx context.Context, q Querier, accountID string) (bool, error) {
	var o Ownership
	if err := q.QueryRow(ctx, `SELECT ownership FROM cloud_accounts WHERE id = $1`, accountID).Scan(&o); err != nil {
		return false, mapErr(err)
	}
	return o == OwnershipClient, nil
}
