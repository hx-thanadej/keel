package catalog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	CloudAccountID string `json:"cloud_account_id"`
	TenantID       string `json:"tenant_id"`
	Bucket         string `json:"bucket"`
	Prefix         string `json:"prefix"`
	Region         string `json:"region"`
	Mode           string `json:"mode"` // tencent: per-day | cumulative; aws: export-folder
	// KMSKeyARN is the SSE-KMS key of an AWS export bucket, in the bucket's
	// region. Keel's session may then use it, through S3 only, to read the
	// export. Empty for SSE-S3 buckets and for Tencent.
	KMSKeyARN string    `json:"kms_key_arn"`
	UpdatedAt time.Time `json:"updated_at"`
	// RoleExternalID is the ExternalId Keel sends when assuming the payer's
	// role. Keel generates it; it is returned only when the payer is first
	// recorded or its id is rotated, for the client's trust-policy condition.
	RoleExternalID string `json:"role_external_id,omitempty"`
}

// clientPayerKind is what a client payer's delivery looks like on one
// provider, for defaults and readable errors. Migration 00051 holds each
// provider's full rules.
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
// ExternalId, which only RotateClientPayerExternalID changes.
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
			if in.KMSKeyARN != "" && provider != "aws" {
				return "", invalid("only an aws client payer has a KMS key")
			}
			err := tx.QueryRow(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, provider, bucket, prefix, region, mode, kms_key_arn) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				ON CONFLICT (cloud_account_id) DO UPDATE SET bucket = excluded.bucket, prefix = excluded.prefix, region = excluded.region, mode = excluded.mode, kms_key_arn = excluded.kms_key_arn, updated_at = now()
				RETURNING cloud_account_id::text, tenant_id::text, bucket, prefix, region, mode, kms_key_arn, updated_at, role_external_id, xmax = 0`,
				accountID, tenantID, provider, in.Bucket, in.Prefix, in.Region, in.Mode, in.KMSKeyARN).
				Scan(&out.CloudAccountID, &out.TenantID, &out.Bucket, &out.Prefix, &out.Region, &out.Mode, &out.KMSKeyARN, &out.UpdatedAt, &out.RoleExternalID, &inserted)
			if !inserted {
				out.RoleExternalID = ""
			}
			return accountID, err
		})
	return out, mapErr(err)
}

// RotateClientPayerExternalID gives an active client payer a new random
// ExternalId and returns it this once (#213). The next bill sync assumes the
// payer's role with it, so the client must put it in the role's trust policy;
// until then the sync raises client_role_unusable naming the new id. The
// Activity records the rotation, never either id.
func (s *Service) RotateClientPayerExternalID(ctx context.Context, p auth.Principal, tenantID, accountID, why string) (ClientPayer, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ClientPayer{}, err
	}
	out := ClientPayer{RoleExternalID: hex.EncodeToString(b[:])}
	err := s.do(ctx, p, write{action: "cloud_account.rotate_external_id", res: authz.Resource{Type: "cloud_account", ID: accountID, TenantID: tenantID},
		actType: "keel.cloud_account.client_payer_external_id_rotated", operation: "RotateClientPayerExternalID", kind: activity.Update, why: why},
		func(tx pgx.Tx) (string, error) {
			err := tx.QueryRow(ctx, `UPDATE client_payers p SET role_external_id = $2, updated_at = now() FROM cloud_accounts a
				WHERE p.cloud_account_id = $1 AND a.id = p.cloud_account_id AND a.archived_at IS NULL
				RETURNING p.cloud_account_id::text, p.tenant_id::text, p.bucket, p.prefix, p.region, p.mode, p.kms_key_arn, p.updated_at`, accountID, out.RoleExternalID).
				Scan(&out.CloudAccountID, &out.TenantID, &out.Bucket, &out.Prefix, &out.Region, &out.Mode, &out.KMSKeyARN, &out.UpdatedAt)
			return accountID, err
		})
	if err != nil {
		return ClientPayer{}, mapErr(err)
	}
	return out, nil
}
