package catalog

import (
	"context"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
)

// ClientPayer marks a client-owned Cloud Account as its client's payer and
// says where its bills deliver (ADR-0018): a Tencent payer's Bill Storage
// (#182) or an AWS management account's Data Exports (#183). Keel reads
// those bills through the account's read_only_role. An empty Bucket records
// the payer before delivery is set up; bill sync then raises a Finding
// saying what the client must configure.
type ClientPayer struct {
	CloudAccountID string    `json:"cloud_account_id"`
	TenantID       string    `json:"tenant_id"`
	Bucket         string    `json:"bucket"`
	Prefix         string    `json:"prefix"`
	Region         string    `json:"region"`
	Mode           string    `json:"mode"` // tencent: per-day | cumulative; aws: export-folder
	UpdatedAt      time.Time `json:"updated_at"`
	// RoleExternalID is the ExternalId Keel sends when assuming the payer's
	// role. Keel generates it; it is returned only when the payer is first
	// recorded, for the client's trust-policy condition.
	RoleExternalID string `json:"role_external_id,omitempty"`
}

// clientPayerKind is what a client payer's delivery looks like on one
// provider. Migration 00051 checks only what every provider shares.
type clientPayerKind struct {
	bucket        *regexp.Regexp
	region        string // default
	modes         []string
	bucketMeaning string
}

var clientPayerKinds = map[string]clientPayerKind{
	"tencent": {bucket: regexp.MustCompile(`^[a-z0-9][a-z0-9-]*-[0-9]{5,20}$`), region: "ap-bangkok", modes: []string{"cumulative", "per-day"},
		bucketMeaning: "a COS bucket name ending in -<appid>"},
	"aws": {bucket: regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`), region: "us-east-1", modes: []string{"export-folder"},
		bucketMeaning: "an S3 bucket name"},
}

// SetClientPayer records or updates a client payer. An empty mode or region
// takes the provider's default. Migration 00050 generates the role's
// ExternalId, which no update changes.
func (s *Service) SetClientPayer(ctx context.Context, p auth.Principal, tenantID, accountID string, in ClientPayer, why string) (ClientPayer, error) {
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
			kind, ok := clientPayerKinds[provider]
			if !ok || o != OwnershipClient {
				return "", invalid("only a client-owned tencent or aws Cloud Account can be a client payer")
			}
			if in.Mode == "" {
				in.Mode = kind.modes[0]
			}
			if in.Region == "" {
				in.Region = kind.region
			}
			if !slices.Contains(kind.modes, in.Mode) {
				return "", invalid("a %s client payer's mode is one of %v", provider, kind.modes)
			}
			if in.Bucket != "" && !kind.bucket.MatchString(in.Bucket) {
				return "", invalid("a %s client payer's bucket is %s", provider, kind.bucketMeaning)
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
