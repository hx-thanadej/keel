package catalog

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
)

// RoleHealth is how well Keel can read a client-owned Cloud Account through
// the read-only role its client granted (ADR-0018). Nothing here is
// recorded for the purpose: it is derived from what bill sync leaves behind.
type RoleHealth struct {
	CloudAccountID string `json:"cloud_account_id"`
	// ClientPayer is true when Keel reads this account's bills through its
	// role. Keel assumes no other client-owned account's role yet.
	ClientPayer bool `json:"client_payer"`
	// LastAssumeAt is the latest time Keel provably assumed the role: a
	// payer load (it needs the role) or the role Finding being resolved by
	// a successful AssumeRole. A sync that assumes the role but finds no new
	// bill file leaves no trace, so this can lag by a delivery interval.
	LastAssumeAt *time.Time `json:"last_assume_at"`
	// LastIngestAt is when a cost load last carried this account's lines.
	LastIngestAt *time.Time    `json:"last_ingest_at"`
	Findings     []RoleFinding `json:"findings"`
}

// RoleFinding is an open Finding that says the role or bill delivery is broken.
type RoleFinding struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

// ListRoleHealth reports role health for a Tenant's client-owned Cloud
// Accounts, to anyone who may read its Cloud Accounts.
func (s *Service) ListRoleHealth(ctx context.Context, p auth.Principal, tenantID string) ([]RoleHealth, error) {
	var out []RoleHealth
	err := s.read(ctx, p, "cloud_account.read", authz.Resource{Type: "cloud_account", TenantID: tenantID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT a.id::text, p.cloud_account_id IS NOT NULL,
				CASE WHEN p.cloud_account_id IS NOT NULL THEN greatest(payer.at, role_ok.at) END,
				ingest.at
			FROM cloud_accounts a
			LEFT JOIN client_payers p ON p.cloud_account_id = a.id
			LEFT JOIN LATERAL (
				SELECT max(act.occurred_at) AS at FROM activities act
				WHERE act.type = 'keel.cost.loaded' AND act.subject IN (
					SELECT 'cost_load/' || f.load_id FROM cost_facts f
					WHERE f.cloud_account_id = a.id OR (f.provider = a.provider AND f.billing_account_id = a.external_id))
			) ingest ON true
			LEFT JOIN LATERAL (
				SELECT max(act.occurred_at) AS at FROM activities act
				WHERE act.type = 'keel.cost.loaded' AND act.subject IN (
					SELECT 'cost_load/' || f.load_id FROM cost_facts f WHERE f.provider = a.provider AND f.billing_account_id = a.external_id)
			) payer ON true
			LEFT JOIN LATERAL (
				SELECT max(fi.resolved_at) AS at FROM findings fi
				WHERE fi.kind = 'client_role_unusable' AND fi.status = 'resolved' AND fi.detail->>'cloud_account_id' = a.id::text
			) role_ok ON true
			WHERE a.ownership = 'client' AND a.archived_at IS NULL
			ORDER BY a.provider, a.name`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (RoleHealth, error) {
			h := RoleHealth{Findings: []RoleFinding{}}
			return h, r.Scan(&h.CloudAccountID, &h.ClientPayer, &h.LastAssumeAt, &h.LastIngestAt)
		})
		if err != nil {
			return err
		}
		byID := map[string]*RoleHealth{}
		for i := range out {
			byID[out[i].CloudAccountID] = &out[i]
		}
		rows, err = tx.Query(ctx, `
			SELECT a.id::text, f.id::text, f.kind, f.severity, f.title
			FROM findings f JOIN cloud_accounts a ON a.ownership = 'client' AND a.archived_at IS NULL AND (
				(f.kind IN ('client_role_unusable', 'bill_delivery_missing') AND f.detail->>'cloud_account_id' = a.id::text)
				OR (f.kind = 'bill_sync_blocked' AND f.detail->>'provider' = a.provider AND f.detail->>'billing_account' = a.external_id))
			WHERE f.status = 'open'
			ORDER BY f.first_seen_at`)
		if err != nil {
			return err
		}
		var account string
		var f RoleFinding
		_, err = pgx.ForEachRow(rows, []any{&account, &f.ID, &f.Kind, &f.Severity, &f.Title}, func() error {
			if h := byID[account]; h != nil {
				h.Findings = append(h.Findings, f)
			}
			return nil
		})
		return err
	})
	return out, mapErr(err)
}
