package cost

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/findings"
)

// ClientPayer is a client-owned payer Cloud Account whose bills Keel reads
// through the read-only role its client granted (ADR-0018). An empty Bucket
// means the client has not set up bill delivery yet.
type ClientPayer struct {
	TenantID       string
	CloudAccountID string
	PayerID        string // the payer's external id and FOCUS BillingAccountId: a Tencent UIN or an AWS management account id
	RoleARN        string // read_only_role.role_arn
	RoleExternalID string // Keel's ExternalId for this payer; the role's trust policy requires it
	Bucket         string
	Prefix         string
	Region         string
	Mode           FileMode
	KMSKeyARN      string // aws: the export bucket's SSE-KMS key, or empty
}

// RoleError marks a Connect failure in assuming the payer's role (missing
// role, refused trust policy, wrong ExternalId). Any other Connect error
// happened after the role was assumed and is a bucket or delivery problem.
type RoleError struct{ Err error }

func (e *RoleError) Error() string { return e.Err.Error() }
func (e *RoleError) Unwrap() error { return e.Err }

// ErrIdentityRejected marks a Ready failure where Keel's identity loaded but
// STS refused it, as opposed to one that never loaded. The two need
// different fixes, so the home Finding's hint differs.
var ErrIdentityRejected = errors.New("STS rejected")

// ClientBillSync runs one BillSync per client payer, each confined to its
// payer's Tenant. It only lists and reads: Connect hands back read-only
// bill access, and a payer without delivery gets a Finding telling the
// client what to configure.
type ClientBillSync struct {
	Ingester *Ingester
	Provider string // tencent or aws
	// OwnPayers are Keel's payer ids. A client account registered under one
	// is refused, so a client payer never re-owns Keel's loads.
	OwnPayers []string
	// Connect returns bill access through the payer's read-only role. It
	// wraps a failure to assume the role in *RoleError.
	Connect func(ClientPayer) (Objects, InvoiceSource, error)
	// Ready checks Keel's own side, such as STS accepting its base identity,
	// once per run that has payers. Its failure is Keel's, not any client's,
	// so the run stops with that error and raises a Finding in Keel's home
	// Tenant, not the client's. A run with no payers resolves that Finding.
	Ready func(context.Context) error
	Now   func() time.Time
}

// ClientSync reports one client payer's run.
type ClientSync struct {
	Payer      ClientPayer `json:"-"`
	Report     SyncReport  `json:"report"`
	NoDelivery bool        `json:"no_delivery"`
}

// Run syncs every client payer. One payer's failure does not stop the
// others; the errors are joined.
func (c *ClientBillSync) Run(ctx context.Context) ([]ClientSync, error) {
	if _, ok := clientPayerHelp[c.Provider]; !ok {
		return nil, fmt.Errorf("no client payers on provider %q", c.Provider)
	}
	payers, err := c.payers(ctx)
	if err != nil {
		return nil, err
	}
	if len(payers) == 0 {
		return nil, c.noPayers(ctx)
	}
	if c.Ready != nil {
		if err := c.keelReady(ctx, len(payers)); err != nil {
			for _, p := range payers {
				err = errors.Join(err, c.blocked(ctx, p, ReasonKeelIdentity))
			}
			return nil, err
		}
	}
	var out []ClientSync
	var failed []error
	for _, p := range payers {
		cs, err := c.one(ctx, p)
		if err != nil {
			failed = append(failed, fmt.Errorf("client payer %s (tenant %s): %w", p.PayerID, p.TenantID, err))
		}
		out = append(out, cs)
	}
	return out, errors.Join(failed...)
}

// FolderPrefix scopes an AWS export prefix to a folder: a non-empty prefix
// ends in "/", so reports/export cannot also match reports/export2/. The
// empty prefix stays empty and means the whole bucket.
func FolderPrefix(prefix string) string {
	if prefix == "" || strings.HasSuffix(prefix, "/") {
		return prefix
	}
	return prefix + "/"
}

func (c *ClientBillSync) one(ctx context.Context, p ClientPayer) (ClientSync, error) {
	cs := ClientSync{Payer: p}
	if slices.Contains(c.OwnPayers, p.PayerID) {
		return cs, fmt.Errorf("payer %s is Keel's own payer, not a client's", p.PayerID)
	}
	if p.Bucket == "" {
		cs.NoDelivery = true
		return cs, errors.Join(c.noDelivery(ctx, p, "no Bill Storage bucket is recorded for this payer"), c.blocked(ctx, p, ReasonNoBucket))
	}
	objs, inv, err := c.Connect(p)
	var roleErr *RoleError
	if errors.As(err, &roleErr) {
		return cs, errors.Join(err, c.roleUnusable(ctx, p, err), c.blocked(ctx, p, ReasonRoleUnusable))
	}
	if err := c.assumed(ctx, p); err != nil {
		return cs, err
	}
	if err != nil {
		cs.NoDelivery = true
		return cs, errors.Join(err, c.noDelivery(ctx, p, "Keel assumed the role but cannot open the bucket: "+err.Error()), c.blocked(ctx, p, ReasonBucketUnreadable))
	}
	bs := &BillSync{Ingester: c.Ingester, Objects: objs, Provider: c.Provider, BillingAccountID: p.PayerID,
		Prefix: p.Prefix, Mode: p.Mode, Invoices: inv, Now: c.Now, Tenant: p.TenantID}
	cs.Report, err = bs.Run(ctx)
	if err != nil {
		return cs, err
	}
	if cs.Report.BillFiles == 0 {
		cs.NoDelivery = true
		return cs, c.noDelivery(ctx, p, fmt.Sprintf("bucket %s holds no bill files under prefix %q", p.Bucket, p.Prefix))
	}
	return cs, c.resolve(ctx, p, findings.BillDeliveryMissing, "bills delivered")
}

// blocked saves a payer's status when the run stops before its bills.
func (c *ClientBillSync) blocked(ctx context.Context, p ClientPayer, reason string) error {
	return recordSync(ctx, c.Ingester.Store, syncRun{tenant: p.TenantID, provider: c.Provider, account: p.PayerID, source: "files",
		at: c.now(), state: RunBlocked, reason: reason})
}

func (c *ClientBillSync) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *ClientBillSync) fingerprint(kind findings.Kind, p ClientPayer) string {
	return kind.String() + ":" + c.Provider + "/" + p.PayerID
}

// clientPayerHelp says, per provider, what the client configures when
// Keel cannot assume its role or finds no bills, and what Keel's operator
// fixes when Keel's own identity is unusable.
var clientPayerHelp = map[string]struct {
	role, delivery func(ClientPayer) string
	keel, rejected string
}{
	"tencent": {
		role: func(p ClientPayer) string {
			return fmt.Sprintf("In payer %s, check that role %s exists and that its trust policy allows sts:AssumeRole from Keel's base role "+
				"with the condition string_equal sts:external_id %s. Keel retries every hour.", p.PayerID, p.RoleARN, p.RoleExternalID)
		},
		delivery: func(p ClientPayer) string {
			return fmt.Sprintf("In payer %s, open Billing Center, Bill Overview, Bill Storage and deliver only the Standard bill (FOCUS) to a private COS bucket in that account, "+
				"under its own prefix. Allow role %s cos:GetBucket, cos:HeadBucket, cos:GetObject and cos:HeadObject on it. "+
				"Then record the bucket, prefix and region on the payer's Cloud Account in Keel. Keel only reads; it never changes Bill Storage or the bucket.", p.PayerID, p.RoleARN)
		},
		keel: "Give keel-api a keyless Tencent identity: TKE pod identity (TKE_WEB_IDENTITY_TOKEN_FILE) or a CVM instance role. " +
			"No client role was tried; the clients' roles are not at fault. Keel retries every hour.",
		rejected: "STS rejected Keel's Tencent identity, so the identity loaded but is not accepted. Check that its credentials have not expired or been revoked and, for TKE pod identity or a CVM role, " +
			"that the cluster's OIDC provider or the instance role is still trusted; the reason has STS's message. " +
			"No client role was tried; the clients' roles are not at fault. Keel retries every hour.",
	},
	"aws": {
		role: func(p ClientPayer) string {
			return fmt.Sprintf("In management account %s, check that role %s exists and that its trust policy allows sts:AssumeRole from Keel's base role "+
				"with the condition StringEquals sts:ExternalId %s. Keel retries every hour.", p.PayerID, p.RoleARN, p.RoleExternalID)
		},
		delivery: func(p ClientPayer) string {
			return fmt.Sprintf("In management account %s, open Billing and Cost Management, Data Exports, and create a standard export of FOCUS 1.2 with AWS columns, "+
				"gzip text/csv, overwrite, to an S3 bucket in that account under its own prefix. Allow role %s s3:ListBucket on the bucket and s3:GetObject on its objects, and kms:Decrypt on the bucket's key if it uses SSE-KMS. "+
				"Then record the bucket, prefix, region and any SSE-KMS key ARN on the payer's Cloud Account in Keel. Keel only reads; it never changes the export or the bucket.", p.PayerID, p.RoleARN)
		},
		keel: "Give keel-api a keyless AWS identity: web identity (AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE) or the instance role; access keys are refused. " +
			"No client role was tried; the clients' roles are not at fault. Keel retries every hour.",
		rejected: "STS rejected Keel's AWS identity, so the identity loaded but is not accepted. Check that its credentials have not expired or been revoked and, for web identity, " +
			"that the role's trust policy still trusts the cluster's OIDC provider and token audience, or that the instance role is still attached; the reason has STS's message. " +
			"No client role was tried; the clients' roles are not at fault. Keel retries every hour.",
	},
}

// keelReady runs Ready and keeps one open Finding in Keel's home Tenant
// while it fails, resolved by the next run it passes.
func (c *ClientBillSync) keelReady(ctx context.Context, payers int) error {
	home, err := homeTenant(ctx, c.Ingester.Store)
	if err != nil {
		return err
	}
	ready := c.Ready(ctx)
	if ready == nil {
		return c.resolveKeel(ctx, home, "Keel identity usable")
	}
	ready = fmt.Errorf("%d %s client payers not synced: %w", payers, c.Provider, ready)
	hint := clientPayerHelp[c.Provider].keel
	if errors.Is(ready, ErrIdentityRejected) {
		hint = clientPayerHelp[c.Provider].rejected
	}
	return errors.Join(ready, c.Ingester.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at)
			VALUES ($1, $2, $3, 'high', $4, jsonb_build_object('provider', $5::text, 'reason', $6::text, 'configure', $7::text), $8)
			ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = excluded.first_seen_at, detail = excluded.detail`,
			home, findings.KeelIdentityUnusable, c.keelFingerprint(), fmt.Sprintf("Keel's own %s identity is unusable; its client payers are not synced", c.Provider),
			c.Provider, ready.Error(), hint, c.now())
		return err
	}))
}

// noPayers resolves keel_identity_unusable: it is about client payers Keel
// could not sync, and none are left. Without a home Tenant there is no such
// Finding.
func (c *ClientBillSync) noPayers(ctx context.Context) error {
	var home *string
	if err := c.Ingester.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil || home == nil {
		return err
	}
	return c.resolveKeel(ctx, *home, "no client payers left to sync")
}

func (c *ClientBillSync) resolveKeel(ctx context.Context, home, resolution string) error {
	return c.Ingester.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = $3
			WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, c.keelFingerprint(), c.now(), resolution)
		return err
	})
}

func (c *ClientBillSync) keelFingerprint() string {
	return findings.KeelIdentityUnusable.String() + ":" + c.Provider
}

// roleUnusable keeps one open Finding in the payer's Tenant until Keel can
// assume the payer's read-only role again.
func (c *ClientBillSync) roleUnusable(ctx context.Context, p ClientPayer, cause error) error {
	return c.raise(ctx, p, findings.ClientRoleUnusable, "high", fmt.Sprintf("Keel cannot assume %s read-only role %s for payer %s", c.Provider, p.RoleARN, p.PayerID),
		cause.Error(), clientPayerHelp[c.Provider].role(p))
}

// noDelivery keeps one open Finding in the payer's Tenant until bills arrive.
func (c *ClientBillSync) noDelivery(ctx context.Context, p ClientPayer, why string) error {
	return c.raise(ctx, p, findings.BillDeliveryMissing, "medium", fmt.Sprintf("%s bills for payer %s are not delivered to Keel: %s", c.Provider, p.PayerID, why),
		why, clientPayerHelp[c.Provider].delivery(p))
}

func (c *ClientBillSync) raise(ctx context.Context, p ClientPayer, kind findings.Kind, severity, title, why, todo string) error {
	return c.Ingester.Store.InTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at)
			VALUES ($1, $2, $3, $4, $5, jsonb_build_object('provider', $6::text, 'payer', $7::text, 'cloud_account_id', $8::text, 'reason', $9::text, 'configure', $10::text), $11)
			ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = excluded.first_seen_at, detail = excluded.detail`,
			p.TenantID, kind, c.fingerprint(kind, p), severity, title, c.Provider, p.PayerID, p.CloudAccountID, why, todo, c.now())
		return err
	})
}

// assumed records that Keel just assumed the payer's role and resolves the
// role Finding. Connect assumes the role up front, so any Connect result
// other than a RoleError proves it.
func (c *ClientBillSync) assumed(ctx context.Context, p ClientPayer) error {
	if err := c.Ingester.Store.InTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE client_payers SET last_assumed_at = $2 WHERE cloud_account_id = $1`, p.CloudAccountID, c.now())
		return err
	}); err != nil {
		return err
	}
	return c.resolve(ctx, p, findings.ClientRoleUnusable, "role assumed")
}

func (c *ClientBillSync) resolve(ctx context.Context, p ClientPayer, kind findings.Kind, resolution string) error {
	return c.Ingester.Store.InTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = $3
			WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, c.fingerprint(kind, p), c.now(), resolution)
		return err
	})
}

// payerModes maps client_payers.mode to how the provider's files make up a
// period.
var payerModes = map[string]FileMode{"per-day": PerDayFiles, "cumulative": CumulativeFiles, "export-folder": LatestExportFolder}

func (c *ClientBillSync) payers(ctx context.Context) ([]ClientPayer, error) {
	rows, err := c.Ingester.Store.AppPool().Query(ctx, `SELECT tenant_id::text, cloud_account_id::text, external_id, role_arn, role_external_id, bucket, prefix, region, mode, kms_key_arn FROM client_payers_for($1)`, c.Provider)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ClientPayer, error) {
		var p ClientPayer
		var mode string
		err := r.Scan(&p.TenantID, &p.CloudAccountID, &p.PayerID, &p.RoleARN, &p.RoleExternalID, &p.Bucket, &p.Prefix, &p.Region, &mode, &p.KMSKeyARN)
		p.Mode = payerModes[mode]
		if c.Provider == "aws" {
			p.Prefix = FolderPrefix(p.Prefix)
		}
		return p, err
	})
}
