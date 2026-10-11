package cost

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// ClientPayer is a client-owned payer Cloud Account whose bills Keel reads
// through the read-only role its client granted (ADR-0018). An empty Bucket
// means the client has not set up bill delivery yet.
type ClientPayer struct {
	TenantID       string
	CloudAccountID string
	UIN            string // the payer's external id, its billing account
	RoleARN        string // read_only_role.role_arn
	Bucket         string
	Prefix         string
	Region         string
	Mode           FileMode
}

// ClientBillSync runs one BillSync per client payer, each confined to its
// payer's Tenant. It only lists and reads: Connect hands back read-only
// bill access, and a payer without delivery gets a Finding telling the
// client what to configure.
type ClientBillSync struct {
	Ingester *Ingester
	Provider string
	// OwnPayers are Keel's payer ids. A client account registered under one
	// is refused, so a client payer never re-owns Keel's loads.
	OwnPayers []string
	// Connect returns bill access through the payer's read-only role.
	Connect func(ClientPayer) (Objects, InvoiceSource, error)
	Now     func() time.Time
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
	payers, err := c.payers(ctx)
	if err != nil {
		return nil, err
	}
	var out []ClientSync
	var failed []error
	for _, p := range payers {
		cs, err := c.one(ctx, p)
		if err != nil {
			failed = append(failed, fmt.Errorf("client payer %s (tenant %s): %w", p.UIN, p.TenantID, err))
		}
		out = append(out, cs)
	}
	return out, errors.Join(failed...)
}

func (c *ClientBillSync) one(ctx context.Context, p ClientPayer) (ClientSync, error) {
	cs := ClientSync{Payer: p}
	if slices.Contains(c.OwnPayers, p.UIN) {
		return cs, fmt.Errorf("payer %s is Keel's own payer, not a client's", p.UIN)
	}
	if p.Bucket == "" {
		cs.NoDelivery = true
		return cs, c.noDelivery(ctx, p, "no Bill Storage bucket is recorded for this payer")
	}
	objs, inv, err := c.Connect(p)
	if err != nil {
		return cs, err
	}
	bs := &BillSync{Ingester: c.Ingester, Objects: objs, Provider: c.Provider, BillingAccountID: p.UIN,
		Prefix: p.Prefix, Mode: p.Mode, Invoices: inv, Now: c.Now, Tenant: p.TenantID}
	cs.Report, err = bs.Run(ctx)
	if err != nil {
		return cs, err
	}
	if cs.Report.BillFiles == 0 {
		cs.NoDelivery = true
		return cs, c.noDelivery(ctx, p, fmt.Sprintf("bucket %s holds no bill files under prefix %q", p.Bucket, p.Prefix))
	}
	return cs, c.Ingester.Store.InTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = 'bills delivered'
			WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, c.fingerprint(p), c.now())
		return err
	})
}

func (c *ClientBillSync) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *ClientBillSync) fingerprint(p ClientPayer) string {
	return "bill_delivery_missing:" + c.Provider + "/" + p.UIN
}

// noDelivery keeps one open Finding in the payer's Tenant until bills arrive.
func (c *ClientBillSync) noDelivery(ctx context.Context, p ClientPayer, why string) error {
	todo := fmt.Sprintf("In payer %s, open Billing Center, Bill Overview, Bill Storage and deliver only the Standard bill (FOCUS) to a private COS bucket in that account, "+
		"under its own prefix. Allow role %s cos:GetBucket, cos:HeadBucket, cos:GetObject and cos:HeadObject on it. "+
		"Then record the bucket, prefix and region on the payer's Cloud Account in Keel. Keel only reads; it never changes Bill Storage or the bucket.", p.UIN, p.RoleARN)
	return c.Ingester.Store.InTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at)
			VALUES ($1, 'bill_delivery_missing', $2, 'medium', $3, jsonb_build_object('provider', $4::text, 'payer', $5::text, 'cloud_account_id', $6::text, 'reason', $7::text, 'configure', $8::text), $9)
			ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = excluded.first_seen_at, detail = excluded.detail`,
			p.TenantID, c.fingerprint(p), fmt.Sprintf("%s bills for payer %s are not delivered to Keel: %s", c.Provider, p.UIN, why),
			c.Provider, p.UIN, p.CloudAccountID, why, todo, c.now())
		return err
	})
}

func (c *ClientBillSync) payers(ctx context.Context) ([]ClientPayer, error) {
	rows, err := c.Ingester.Store.AppPool().Query(ctx, `SELECT tenant_id::text, cloud_account_id::text, external_id, role_arn, bucket, prefix, region, mode FROM client_payers_for($1)`, c.Provider)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ClientPayer, error) {
		var p ClientPayer
		var mode string
		err := r.Scan(&p.TenantID, &p.CloudAccountID, &p.UIN, &p.RoleARN, &p.Bucket, &p.Prefix, &p.Region, &mode)
		p.Mode = CumulativeFiles
		if mode == "per-day" {
			p.Mode = PerDayFiles
		}
		return p, err
	})
}
