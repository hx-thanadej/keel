package catalog

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
)

// ClientPayer marks a client-owned Tencent Cloud Account as its client's
// payer and says where its Bill Storage delivers (ADR-0018, #182). Keel
// reads those bills through the account's read_only_role. An empty Bucket
// records the payer before delivery is set up; bill sync then raises a
// Finding saying what the client must configure.
type ClientPayer struct {
	CloudAccountID string    `json:"cloud_account_id"`
	TenantID       string    `json:"tenant_id"`
	Bucket         string    `json:"bucket"`
	Prefix         string    `json:"prefix"`
	Region         string    `json:"region"`
	Mode           string    `json:"mode"` // per-day | cumulative
	UpdatedAt      time.Time `json:"updated_at"`
	// RoleExternalID is the ExternalId Keel sends when assuming the payer's
	// role. Keel generates it; it is returned only when the payer is first
	// recorded, for the client's trust-policy condition.
	RoleExternalID string `json:"role_external_id,omitempty"`
}

// SetClientPayer records or updates a client payer. Migration 00050 checks
// the bucket, region and mode formats and generates the role's ExternalId,
// which no update changes.
func (s *Service) SetClientPayer(ctx context.Context, p auth.Principal, tenantID, accountID string, in ClientPayer, why string) (ClientPayer, error) {
	if in.Mode == "" {
		in.Mode = "cumulative"
	}
	if in.Region == "" {
		in.Region = "ap-bangkok"
	}
	var out ClientPayer
	var inserted bool
	err := s.do(ctx, p, write{action: "cloud_account.update", res: authz.Resource{Type: "cloud_account", ID: accountID, TenantID: tenantID},
		actType: "keel.cloud_account.client_payer_set", operation: "SetClientPayer", kind: activity.Update, why: why},
		func(tx pgx.Tx) (string, error) {
			var provider string
			var o Ownership
			if err := tx.QueryRow(ctx, `SELECT provider, ownership FROM cloud_accounts WHERE id = $1 AND archived_at IS NULL FOR SHARE`, accountID).Scan(&provider, &o); err != nil {
				return "", err
			}
			if provider != "tencent" || o != OwnershipClient {
				return "", invalid("only a client-owned tencent Cloud Account can be a client payer")
			}
			err := tx.QueryRow(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, bucket, prefix, region, mode) VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (cloud_account_id) DO UPDATE SET bucket = excluded.bucket, prefix = excluded.prefix, region = excluded.region, mode = excluded.mode, updated_at = now()
				RETURNING cloud_account_id::text, tenant_id::text, bucket, prefix, region, mode, updated_at, role_external_id, xmax = 0`,
				accountID, tenantID, in.Bucket, in.Prefix, in.Region, in.Mode).
				Scan(&out.CloudAccountID, &out.TenantID, &out.Bucket, &out.Prefix, &out.Region, &out.Mode, &out.UpdatedAt, &out.RoleExternalID, &inserted)
			if !inserted {
				out.RoleExternalID = ""
			}
			return accountID, err
		})
	return out, mapErr(err)
}
