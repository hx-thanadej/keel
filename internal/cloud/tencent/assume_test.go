package tencent_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type baseCreds struct{}

func (baseCreds) GetCredential() (common.CredentialIface, error) {
	return common.NewCredential("base-id", "base-key"), nil
}

// fakeSTS grants every AssumeRole and keeps each request body.
type fakeSTS struct{ bodies []map[string]any }

func (f *fakeSTS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	f.bodies = append(f.bodies, body)
	_, _ = io.WriteString(w, `{"Response":{"Credentials":{"TmpSecretId":"id","TmpSecretKey":"k","Token":"t"},"ExpiredTime":4102444800,"RequestId":"r"}}`)
}

// outbound records every HTTP request the process makes and fails it.
type outbound struct{ hosts []string }

func (o *outbound) RoundTrip(r *http.Request) (*http.Response, error) {
	o.hosts = append(o.hosts, r.URL.Host)
	return nil, errors.New("no network in tests")
}

// TestUncheckedRolesAreNeverAssumed: a Keel role or a client role that no
// constructor built (the zero values a caller can still write) fails
// before any STS call (#244). The zero values have no STS endpoint, so they
// would reach real Tencent: every outbound request is caught instead.
func TestUncheckedRolesAreNeverAssumed(t *testing.T) {
	o := &outbound{}
	defer func(t http.RoundTripper) { http.DefaultTransport = t }(http.DefaultTransport)
	http.DefaultTransport = o
	for name, p := range map[string]common.Provider{
		"zero keel role":   &tencent.KeelRole{},
		"zero client role": &tencent.ClientRole{},
	} {
		if _, err := p.GetCredential(); err == nil {
			t.Errorf("%s: assumed", name)
		}
	}
	if len(o.hosts) != 0 {
		t.Fatalf("requests to %v, want none", o.hosts)
	}
}

// TestCachedKeelSessionHonoursOwnershipSwitch: once a Tenant registers the
// account as client-owned, Keel's cached session there is refused on its
// next use, in this replica and in another, without waiting for the
// session to expire or calling STS again (#249).
func TestCachedKeelSessionHonoursOwnershipSwitch(t *testing.T) {
	f := &fakeSTS{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := context.Background()
	st := storetest.New(t)
	const account = "200000000001"
	var roles []*tencent.KeelRole
	for _, s := range []*store.Store{st, storetest.Replica(t, st)} {
		r, err := tencent.NewKeelRole(ctx, s, baseCreds{}, account, "KeelMember", "ap-bangkok", srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.GetCredential(); err != nil {
			t.Fatal(err)
		}
		roles = append(roles, r)
	}
	if len(f.bodies) != 2 {
		t.Fatalf("STS calls %d, want one per replica", len(f.bodies))
	}

	tenant, err := st.CreateTenant(ctx, "client", "Client", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
			VALUES (current_tenant_id(), 'tencent', $1, 'payer', 'client', jsonb_build_object('role_arn', 'qcs::cam::uin/'||$1||':roleName/R'))`, account)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for i, r := range roles {
		if _, err := r.GetCredential(); !errors.Is(err, catalog.ErrClientOwned) {
			t.Errorf("replica %d: cached session after the switch: %v, want ErrClientOwned", i, err)
		}
	}
	if len(f.bodies) != 2 {
		t.Errorf("STS calls %d after the switch, want none", len(f.bodies)-2)
	}
}

// TestKeelRoleSendsNoExternalId: Keel's own role is assumed in the account
// it was checked for, with no ExternalId and no session policy.
func TestKeelRoleSendsNoExternalId(t *testing.T) {
	f := &fakeSTS{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	r, err := tencent.NewKeelRole(context.Background(), storetest.New(t), baseCreds{}, "200000000001", "KeelMember", "ap-bangkok", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetCredential(); err != nil {
		t.Fatal(err)
	}
	if len(f.bodies) != 1 || f.bodies[0]["RoleArn"] != "qcs::cam::uin/200000000001:roleName/KeelMember" {
		t.Fatalf("STS bodies %v, want one AssumeRole of KeelMember in 200000000001", f.bodies)
	}
	for _, k := range []string{"ExternalId", "Policy"} {
		if v, ok := f.bodies[0][k]; ok {
			t.Errorf("Keel's own role sent %s %v", k, v)
		}
	}
}
