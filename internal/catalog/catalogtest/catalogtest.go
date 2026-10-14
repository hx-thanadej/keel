// Package catalogtest registers client payers for tests the way an
// operator does, in the database, so tests get a catalog.ClientReadRole
// only as production code does: from catalog.LoadClientReadRole.
package catalogtest

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store"
)

var modes = map[string]struct{ region, mode string }{
	"tencent": {"ap-bangkok", "per-day"},
	"aws":     {"us-east-1", "export-folder"},
}

// ClientPayer registers payer on provider, with read-only role roleARN, as
// the client payer of a new client Tenant, and returns that Tenant and the
// role as catalog.LoadClientReadRole builds it.
func ClientPayer(t *testing.T, st *store.Store, provider, payer, roleARN string) (string, catalog.ClientReadRole) {
	t.Helper()
	ctx := context.Background()
	tenant, err := st.CreateTenant(ctx, "client-"+provider+"-"+payer, "Client "+payer, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `WITH a AS (INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
			VALUES (current_tenant_id(), $1, $2, 'payer', 'client', jsonb_build_object('role_arn', $3::text)) RETURNING id)
			INSERT INTO client_payers (cloud_account_id, tenant_id, provider, region, mode) SELECT id, current_tenant_id(), $1, $4, $5 FROM a`,
			provider, payer, roleARN, modes[provider].region, modes[provider].mode)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r, err := catalog.LoadClientReadRole(ctx, st, provider, tenant, payer)
	if err != nil {
		t.Fatal(err)
	}
	return tenant, r
}
