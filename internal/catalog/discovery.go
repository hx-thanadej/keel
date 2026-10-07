package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/discovery"
)

// DiscoveredAccount is an account found in a provider organisation.
type DiscoveredAccount struct {
	discovery.Account
	FirstSeenAt time.Time             `json:"first_seen_at"`
	LastSeenAt  time.Time             `json:"last_seen_at"`
	Registered  bool                  `json:"registered"` // already a Cloud Account in some Tenant
	Suggestion  *discovery.Suggestion `json:"suggestion,omitempty"`
}

// Discover lists accounts from src and records them in the home Tenant.
// Only the home Tenant can run discovery.
func (s *Service) Discover(ctx context.Context, p auth.Principal, tenantID string, src discovery.Source) ([]DiscoveredAccount, error) {
	err := s.do(ctx, p, write{action: "cloud_account.discover", res: authz.Resource{Type: "discovered_account", TenantID: tenantID},
		actType: "keel.cloud_accounts.discovered", operation: "DiscoverAccounts", kind: activity.Update, why: "discover " + src.Provider()},
		func(tx pgx.Tx) (string, error) {
			var home bool
			if err := tx.QueryRow(ctx, `SELECT is_home FROM tenants WHERE id = $1`, tenantID).Scan(&home); err != nil {
				return "", err
			}
			if !home {
				return "", fmt.Errorf("%w: discovery runs in the home Tenant", ErrInvalid)
			}
			accounts, err := src.ListAccounts(ctx)
			if err != nil {
				return "", fmt.Errorf("list %s accounts: %w", src.Provider(), err)
			}
			for _, a := range accounts {
				tags, _ := json.Marshal(a.Tags)
				if _, err := tx.Exec(ctx, `INSERT INTO discovered_accounts (tenant_id, provider, external_id, name, parent, tags)
					VALUES ($1, $2, $3, $4, $5, $6)
					ON CONFLICT (tenant_id, provider, external_id) DO UPDATE SET name = excluded.name, parent = excluded.parent, tags = excluded.tags, last_seen_at = now()`,
					tenantID, a.Provider, a.ExternalID, a.Name, a.Parent, tags); err != nil {
					return "", err
				}
			}
			return src.Provider(), nil
		})
	if err != nil {
		return nil, mapErr(err)
	}
	return s.ListDiscovered(ctx, p, tenantID)
}

// ListDiscovered returns discovered accounts with registration status and a
// suggested Project/Environment.
func (s *Service) ListDiscovered(ctx context.Context, p auth.Principal, tenantID string) ([]DiscoveredAccount, error) {
	var out []DiscoveredAccount
	err := s.read(ctx, p, "cloud_account.discover", authz.Resource{Type: "discovered_account", TenantID: tenantID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.provider, d.external_id, d.name, d.parent, d.tags, d.first_seen_at, d.last_seen_at,
				EXISTS (SELECT 1 FROM registered_accounts(d.provider, ARRAY[d.external_id]))
			FROM discovered_accounts d ORDER BY d.provider, d.name`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (DiscoveredAccount, error) {
			var d DiscoveredAccount
			var tags []byte
			err := r.Scan(&d.Provider, &d.ExternalID, &d.Name, &d.Parent, &tags, &d.FirstSeenAt, &d.LastSeenAt, &d.Registered)
			_ = json.Unmarshal(tags, &d.Tags)
			if !d.Registered {
				d.Suggestion = discovery.Suggest(d.Name)
			}
			return d, err
		})
		return err
	})
	return out, mapErr(err)
}

// LastCatalogSync returns the most recent catalog-info.yaml sync report.
func (s *Service) LastCatalogSync(ctx context.Context, p auth.Principal, tenantID string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := s.read(ctx, p, "catalog_sync.read", authz.Resource{Type: "catalog_sync", TenantID: tenantID}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT jsonb_build_object('started_at', started_at, 'finished_at', finished_at, 'report', report)
			FROM catalog_sync_runs ORDER BY started_at DESC LIMIT 1`).Scan(&raw)
	})
	return raw, mapErr(err)
}
