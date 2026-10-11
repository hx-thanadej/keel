package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type tencentClient struct {
	st                   *store.Store
	home, tenant, payer  string
	account, roleFP, kfp string
}

// tencentClientWorld is a home Tenant and one client Tenant whose Tencent
// payer delivers bills to a bucket through its read-only role.
func tencentClientWorld(t *testing.T) tencentClient {
	t.Helper()
	ctx := context.Background()
	c := tencentClient{st: storetest.New(t), payer: "300000000001"}
	c.roleFP, c.kfp = "client_role_unusable:tencent/"+c.payer, "keel_identity_unusable:tencent"
	var err error
	if c.home, err = c.st.CreateTenant(ctx, "harmonyx", "HarmonyX", true); err != nil {
		t.Fatal(err)
	}
	if c.tenant, err = c.st.CreateTenant(ctx, "c1", "C1", false); err != nil {
		t.Fatal(err)
	}
	if err := c.st.InTenant(ctx, c.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
			VALUES ($1, 'tencent', $2, 'payer', 'client', jsonb_build_object('role_arn', $3::text)) RETURNING id`,
			c.tenant, c.payer, "qcs::cam::uin/"+c.payer+":roleName/KeelReadOnly").Scan(&c.account); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, provider, bucket, prefix, region, mode)
			VALUES ($1, $2, 'tencent', 'c1-bills-1250000001', 'focus/', 'ap-bangkok', 'per-day')`, c.account, c.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c tencentClient) open(t *testing.T, tenant, fingerprint string) string {
	t.Helper()
	var title string
	if err := c.st.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(context.Background(), `SELECT title FROM findings WHERE fingerprint = $1 AND status = 'open'`, fingerprint).Scan(&title)
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return title
}

func (c tencentClient) lastAssumed(t *testing.T) *time.Time {
	t.Helper()
	var at *time.Time
	if err := c.st.InTenant(context.Background(), c.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT last_assumed_at FROM client_payers WHERE cloud_account_id = $1`, c.account).Scan(&at)
	}); err != nil {
		t.Fatal(err)
	}
	return at
}

// withoutTencentCredentials leaves Keel's Tencent chain with only the CVM
// instance role, which off a CVM finds nothing.
func withoutTencentCredentials(t *testing.T) {
	for _, k := range []string{"KEEL_ENV", "TKE_WEB_IDENTITY_TOKEN_FILE", "TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_SESSION_TOKEN"} {
		t.Setenv(k, "")
	}
	t.Setenv("HOME", t.TempDir())
}

// TestTencentClientSyncBlamesKeelForItsOwnCredentials: with Keel's own
// Tencent credentials absent, the production client sync tells Keel's home
// Tenant, not the client: no client_role_unusable lands in the client's
// Tenant and its role health is untouched. Once Keel's identity works, the
// home Finding resolves and a role the client's trust policy refuses is
// still the client's to fix.
func TestTencentClientSyncBlamesKeelForItsOwnCredentials(t *testing.T) {
	c := tencentClientWorld(t)
	ctx := context.Background()
	withoutTencentCredentials(t)
	sync := clientBillSyncs(ctx, c.st)[0]
	if sync.Provider != "tencent" {
		t.Fatalf("first client sync is %s, want tencent", sync.Provider)
	}
	if _, err := sync.Run(ctx); err == nil || !strings.Contains(err.Error(), "Keel's Tencent identity") {
		t.Fatalf("sync without Keel's Tencent credentials = %v, want Keel's identity error", err)
	}
	if title := c.open(t, c.tenant, c.roleFP); title != "" {
		t.Errorf("client Tenant blamed for Keel's missing credentials: %s", title)
	}
	if at := c.lastAssumed(t); at != nil {
		t.Errorf("last_assumed_at = %v without Keel's credentials, want never", at)
	}
	if c.open(t, c.home, c.kfp) == "" {
		t.Fatalf("home Tenant has no Finding for Keel's unusable Tencent identity")
	}

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Response":{"Error":{"Code":"InvalidParameter.ExternalIdIncorrect","Message":"external id mismatch"},"RequestId":"r"}}`)
	}))
	defer sts.Close()
	refused := tencentClientBillSync(sync.Ingester, staticCreds{id: "base-id"}, sts.URL)
	if _, err := refused.Run(ctx); err == nil || !strings.Contains(err.Error(), "external id mismatch") {
		t.Fatalf("run against a refusing role = %v, want the AssumeRole refusal", err)
	}
	if c.open(t, c.tenant, c.roleFP) == "" {
		t.Error("a role the client's trust policy refuses raised no client_role_unusable in the client's Tenant")
	}
	if at := c.lastAssumed(t); at != nil {
		t.Errorf("last_assumed_at = %v after a refused role, want never", at)
	}
	if title := c.open(t, c.home, c.kfp); title != "" {
		t.Errorf("home identity Finding still open once Keel's credentials worked: %s", title)
	}
}
