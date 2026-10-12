package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type clientWorld struct {
	st                   *store.Store
	provider             string
	home, tenant, payer  string
	account, roleFP, kfp string
}

// payerShapes are one valid client payer per provider: its read-only role
// and its Bill Storage or Data Exports bucket.
var payerShapes = map[string]struct{ role, bucket, prefix, region, mode string }{
	"tencent": {"qcs::cam::uin/300000000001:roleName/KeelReadOnly", "c1-bills-1250000001", "focus/", "ap-bangkok", "per-day"},
	"aws":     {"arn:aws:iam::300000000001:role/KeelReadOnly", "c1-bills", "exports/", "us-east-1", "export-folder"},
}

// newClientWorld is a home Tenant and one client Tenant whose payer on
// provider delivers bills to a bucket through its read-only role.
func newClientWorld(t *testing.T, provider string) clientWorld {
	t.Helper()
	ctx := context.Background()
	c := clientWorld{st: storetest.New(t), provider: provider, payer: "300000000001"}
	c.roleFP, c.kfp = "client_role_unusable:"+provider+"/"+c.payer, "keel_identity_unusable:"+provider
	var err error
	if c.home, err = c.st.CreateTenant(ctx, "harmonyx", "HarmonyX", true); err != nil {
		t.Fatal(err)
	}
	if c.tenant, err = c.st.CreateTenant(ctx, "c1", "C1", false); err != nil {
		t.Fatal(err)
	}
	c.account = addClientPayer(t, c.st, c.tenant, provider, c.payer)
	return c
}

// addClientPayer registers one client payer on provider in tenant and
// returns its Cloud Account id.
func addClientPayer(t *testing.T, st *store.Store, tenant, provider, payer string) string {
	t.Helper()
	ctx := context.Background()
	shape := payerShapes[provider]
	role := strings.ReplaceAll(shape.role, "300000000001", payer)
	var account string
	if err := st.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
			VALUES ($1, $2, $3, 'payer', 'client', jsonb_build_object('role_arn', $4::text)) RETURNING id`,
			tenant, provider, payer, role).Scan(&account); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, provider, bucket, prefix, region, mode)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, account, tenant, provider, shape.bucket, shape.prefix, shape.region, shape.mode)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return account
}

func (c clientWorld) open(t *testing.T, tenant, fingerprint string) (title, detail string) {
	t.Helper()
	if err := c.st.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(context.Background(), `SELECT title, detail::text FROM findings WHERE fingerprint = $1 AND status = 'open'`, fingerprint).Scan(&title, &detail)
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return title, detail
}

func (c clientWorld) lastAssumed(t *testing.T) *time.Time {
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
// Tenant and its role health is untouched.
func TestTencentClientSyncBlamesKeelForItsOwnCredentials(t *testing.T) {
	c := newClientWorld(t, "tencent")
	ctx := context.Background()
	withoutTencentCredentials(t)
	sync := clientBillSyncs(ctx, c.st, "")[0]
	if sync.Provider != "tencent" {
		t.Fatalf("first client sync is %s, want tencent", sync.Provider)
	}
	if _, err := sync.Run(ctx); err == nil || !strings.Contains(err.Error(), "Keel's Tencent identity") {
		t.Fatalf("sync without Keel's Tencent credentials = %v, want Keel's identity error", err)
	}
	if title, _ := c.open(t, c.tenant, c.roleFP); title != "" {
		t.Errorf("client Tenant blamed for Keel's missing credentials: %s", title)
	}
	if at := c.lastAssumed(t); at != nil {
		t.Errorf("last_assumed_at = %v without Keel's credentials, want never", at)
	}
	title, detail := c.open(t, c.home, c.kfp)
	if title == "" {
		t.Fatalf("home Tenant has no Finding for Keel's unusable Tencent identity")
	}
	if !strings.Contains(detail, "Give keel-api a keyless Tencent identity") {
		t.Errorf("an identity that never loaded is not told to give Keel a keyless one: %s", detail)
	}
}

// fakeSTS answers GetCallerIdentity for Keel's own identity and AssumeRole
// for a client's role, each accepting or refusing as told, and records the
// actions it was asked for.
type fakeSTS struct {
	mu                   sync.Mutex
	actions              []string
	identityOK, assumeOK bool
	provider             string
	// trusted, when set, is the only ExternalId the client's trust policy
	// accepts; assumedWith is the ExternalId of the last AssumeRole.
	trusted, assumedWith string
}

func (f *fakeSTS) trust(externalID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trusted = externalID
}

func (f *fakeSTS) lastExternalID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.assumedWith
}

func (f *fakeSTS) set(identityOK, assumeOK bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identityOK, f.assumeOK, f.actions = identityOK, assumeOK, nil
}

func (f *fakeSTS) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.actions)
}

func (f *fakeSTS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	action := r.Header.Get("X-TC-Action")
	var req struct{ ExternalId string }
	if f.provider == "aws" {
		form, _ := url.ParseQuery(string(body))
		action, req.ExternalId = form.Get("Action"), form.Get("ExternalId")
	} else {
		_ = json.Unmarshal(body, &req)
	}
	f.mu.Lock()
	f.actions = append(f.actions, action)
	ok := map[string]bool{"GetCallerIdentity": f.identityOK, "AssumeRole": f.assumeOK}[action]
	if action == "AssumeRole" {
		f.assumedWith = req.ExternalId
		ok = ok && (f.trusted == "" || f.trusted == req.ExternalId)
	}
	f.mu.Unlock()
	if f.provider == "tencent" {
		switch {
		case !ok && action == "GetCallerIdentity":
			_, _ = io.WriteString(w, `{"Response":{"Error":{"Code":"AuthFailure.SecretIdNotFound","Message":"secret id not found"},"RequestId":"r"}}`)
		case !ok:
			_, _ = io.WriteString(w, `{"Response":{"Error":{"Code":"InvalidParameter.ExternalIdIncorrect","Message":"external id mismatch"},"RequestId":"r"}}`)
		case action == "AssumeRole":
			_, _ = io.WriteString(w, `{"Response":{"Credentials":{"TmpSecretId":"id","TmpSecretKey":"k","Token":"t"},"ExpiredTime":4102444800,"RequestId":"r"}}`)
		case action == "GetCallerIdentity":
			_, _ = io.WriteString(w, `{"Response":{"Arn":"qcs::sts:200000000001:assumed-role/4611686018427397919/keel","AccountId":"200000000001","UserId":"4611686018427397919:keel","PrincipalId":"200000000001","Type":"AssumedRole","RequestId":"r"}}`)
		default:
			_, _ = io.WriteString(w, `{"Response":{"Error":{"Code":"InternalError","Message":"unexpected action"},"RequestId":"r"}}`)
		}
		return
	}
	switch {
	case !ok && action == "GetCallerIdentity":
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
	case !ok:
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized to perform sts:AssumeRole</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
	case action == "GetCallerIdentity":
		_, _ = io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::200000000001:assumed-role/keel/keel</Arn><UserId>AROA:keel</UserId><Account>200000000001</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
	case action == "AssumeRole":
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><AssumedRoleUser><Arn>arn:aws:sts::300000000001:assumed-role/KeelReadOnly/keel</Arn><AssumedRoleId>AROA:keel</AssumedRoleId></AssumedRoleUser>`+
			`<Credentials><AccessKeyId>ASIAX</AccessKeyId><SecretAccessKey>secret-x</SecretAccessKey><SessionToken>token-x</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>`+
			`</AssumeRoleResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></AssumeRoleResponse>`)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// clientSyncAgainst is the production client sync for provider, with Keel's
// base identity and STS faked.
func clientSyncAgainst(c clientWorld, sts string) *cost.ClientBillSync {
	in := &cost.Ingester{Store: c.st}
	if c.provider == "aws" {
		return awsClientBillSync(in, webIdentity{}, sts, "")
	}
	return tencentClientBillSync(in, staticCreds{id: "base-id"}, sts)
}

// TestSTSRejectingKeelsIdentityStaysHome: when STS rejects Keel's own base
// identity, the sync asks only GetCallerIdentity, raises
// keel_identity_unusable in Keel's home Tenant and leaves the client's
// Tenant and role health untouched. Once STS accepts Keel's identity, the
// home Finding resolves and a client role that refuses Keel raises
// client_role_unusable in the client's Tenant. Neither Finding carries
// credential material.
func TestSTSRejectingKeelsIdentityStaysHome(t *testing.T) {
	for _, provider := range []string{"tencent", "aws"} {
		t.Run(provider, func(t *testing.T) {
			c := newClientWorld(t, provider)
			ctx := context.Background()
			fake := &fakeSTS{provider: provider}
			srv := httptest.NewServer(fake)
			defer srv.Close()
			sync := clientSyncAgainst(c, srv.URL)

			fake.set(false, true)
			if _, err := sync.Run(ctx); err == nil || !strings.Contains(err.Error(), "STS rejected Keel's") {
				t.Fatalf("sync with Keel's identity rejected = %v, want Keel's identity error", err)
			}
			if got := fake.calls(); !slices.Equal(got, []string{"GetCallerIdentity"}) {
				t.Errorf("STS calls %v, want only GetCallerIdentity: no client role is tried once Keel's identity fails", got)
			}
			if title, _ := c.open(t, c.tenant, c.roleFP); title != "" {
				t.Errorf("client Tenant blamed for Keel's rejected identity: %s", title)
			}
			if at := c.lastAssumed(t); at != nil {
				t.Errorf("last_assumed_at = %v with Keel's identity rejected, want never", at)
			}
			title, detail := c.open(t, c.home, c.kfp)
			if title == "" {
				t.Fatal("home Tenant has no keel_identity_unusable for Keel's rejected identity")
			}
			if strings.Contains(detail, "Give keel-api a keyless") || !strings.Contains(detail, "rejected") {
				t.Errorf("an already keyless identity STS rejected is not told what to check: %s", detail)
			}
			for _, secret := range []string{"base-key", "base-secret", "base-token"} {
				if strings.Contains(detail, secret) {
					t.Errorf("home Finding detail carries credential material %q: %s", secret, detail)
				}
			}

			fake.set(true, false)
			_, err := sync.Run(ctx)
			if err == nil {
				t.Fatal("run against a refusing role succeeded")
			}
			if got := fake.calls(); len(got) < 2 || got[0] != "GetCallerIdentity" || got[1] != "AssumeRole" {
				t.Errorf("STS calls %v, want GetCallerIdentity then AssumeRole", got)
			}
			if title, _ := c.open(t, c.tenant, c.roleFP); title == "" {
				t.Errorf("a role refusing Keel raised no client_role_unusable in the client's Tenant: %v", err)
			}
			if at := c.lastAssumed(t); at != nil {
				t.Errorf("last_assumed_at = %v after a refused role, want never", at)
			}
			if title, _ := c.open(t, c.home, c.kfp); title != "" {
				t.Errorf("home identity Finding still open once STS accepted Keel's identity: %s", title)
			}
		})
	}
}

type missingCreds struct{}

func (missingCreds) GetCredential() (common.CredentialIface, error) {
	return nil, errors.New("no credential found")
}

// TestKeelIdentityFindingResolvesWithNoPayers: an open keel_identity_unusable
// is about client payers Keel could not sync. Once every payer on that
// provider is archived, the next sync resolves it, even while Keel's
// identity is still unusable, and asks STS nothing.
func TestKeelIdentityFindingResolvesWithNoPayers(t *testing.T) {
	c := newClientWorld(t, "tencent")
	ctx := context.Background()
	fake := &fakeSTS{provider: "tencent"}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	sync := tencentClientBillSync(&cost.Ingester{Store: c.st}, missingCreds{}, srv.URL)
	fake.set(false, false)
	if _, err := sync.Run(ctx); err == nil {
		t.Fatal("sync with Keel's identity rejected succeeded")
	}
	if title, _ := c.open(t, c.home, c.kfp); title == "" {
		t.Fatal("home Tenant has no keel_identity_unusable")
	}

	if _, err := storetest.Superuser(t, c.st).Exec(ctx, `UPDATE cloud_accounts SET archived_at = now() WHERE id = $1`, c.account); err != nil {
		t.Fatal(err)
	}
	fake.set(false, false)
	if runs, err := sync.Run(ctx); err != nil || len(runs) != 0 {
		t.Fatalf("sync with no payers = %v, %v, want nothing to do", runs, err)
	}
	if title, _ := c.open(t, c.home, c.kfp); title != "" {
		t.Errorf("keel_identity_unusable still open with no client payers left: %s", title)
	}
	if got := fake.calls(); len(got) != 0 {
		t.Errorf("STS calls %v with no client payers, want none", got)
	}
}

// TestTencentReadyHonoursItsContext: the Tencent SDK call cannot be
// cancelled, so Ready must return when its ctx ends instead of waiting out
// the SDK's own timeout on a STS that never answers.
func TestTencentReadyHonoursItsContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	sync := tencentClientBillSync(&cost.Ingester{}, staticCreds{id: "base-id"}, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sync.Ready(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Ready after its ctx ended = %v, want the ctx error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ready ignored its ctx and kept waiting on STS")
	}
}

// TestOneProvidersKeelIdentityFailureLeavesTheOtherSyncing: with Keel's
// Tencent identity rejected, the AWS client payer in the same database is
// still synced through its role and stamped, and each provider's Findings
// stay its own.
func TestOneProvidersKeelIdentityFailureLeavesTheOtherSyncing(t *testing.T) {
	c := newClientWorld(t, "tencent")
	ctx := context.Background()
	awsAccount := addClientPayer(t, c.st, c.tenant, "aws", "300000000002")

	tfake, afake := &fakeSTS{provider: "tencent"}, &fakeSTS{provider: "aws"}
	tfake.set(false, true)
	afake.set(true, true)
	tsrv, asrv := httptest.NewServer(tfake), httptest.NewServer(afake)
	defer tsrv.Close()
	defer asrv.Close()
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`)
	}))
	defer s3.Close()

	in := &cost.Ingester{Store: c.st}
	if _, err := tencentClientBillSync(in, staticCreds{id: "base-id"}, tsrv.URL).Run(ctx); err == nil || !strings.Contains(err.Error(), "STS rejected Keel's Tencent identity") {
		t.Fatalf("Tencent sync with Keel's identity rejected = %v, want Keel's identity error", err)
	}
	if _, err := awsClientBillSync(in, webIdentity{}, asrv.URL, s3.URL).Run(ctx); err != nil && !strings.Contains(err.Error(), "holds no bill files") {
		t.Fatalf("AWS sync beside a rejected Tencent identity = %v", err)
	}

	if title, _ := c.open(t, c.home, c.kfp); title == "" {
		t.Error("home Tenant has no keel_identity_unusable:tencent")
	}
	if title, _ := c.open(t, c.home, "keel_identity_unusable:aws"); title != "" {
		t.Errorf("AWS blamed for Tencent's rejected identity: %s", title)
	}
	if title, _ := c.open(t, c.tenant, "client_role_unusable:aws/300000000002"); title != "" {
		t.Errorf("AWS client role blamed: %s", title)
	}
	if got := tfake.calls(); !slices.Equal(got, []string{"GetCallerIdentity"}) {
		t.Errorf("Tencent STS calls %v, want only GetCallerIdentity", got)
	}
	if got := afake.calls(); !slices.Equal(got, []string{"GetCallerIdentity", "AssumeRole"}) {
		t.Errorf("AWS STS calls %v, want GetCallerIdentity then AssumeRole", got)
	}
	if at := c.lastAssumed(t); at != nil {
		t.Errorf("Tencent payer last_assumed_at = %v, want never", at)
	}
	var at *time.Time
	if err := c.st.InTenant(ctx, c.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT last_assumed_at FROM client_payers WHERE cloud_account_id = $1`, awsAccount).Scan(&at)
	}); err != nil {
		t.Fatal(err)
	}
	if at == nil {
		t.Error("AWS payer last_assumed_at is unset though its role was assumed")
	}
}

// TestSyncAfterRotationUsesTheNewExternalID: once a payer's ExternalId is
// rotated, the very next sync assumes the client's role with the new id and
// never the old one. Until the client's trust policy names the new id the
// role refuses Keel; once it does, the sync assumes the role again.
func TestSyncAfterRotationUsesTheNewExternalID(t *testing.T) {
	c := newClientWorld(t, "aws")
	ctx := context.Background()
	az, err := authz.New()
	if err != nil {
		t.Fatal(err)
	}
	var old string
	if err := c.st.InTenant(ctx, c.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT role_external_id FROM client_payers WHERE cloud_account_id = $1`, c.account).Scan(&old)
	}); err != nil {
		t.Fatal(err)
	}
	fake := &fakeSTS{provider: "aws"}
	fake.set(true, true)
	fake.trust(old)
	sts := httptest.NewServer(fake)
	defer sts.Close()
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`)
	}))
	defer s3.Close()
	sync := awsClientBillSync(&cost.Ingester{Store: c.st}, webIdentity{}, sts.URL, s3.URL)
	run := func() {
		t.Helper()
		if _, err := sync.Run(ctx); err != nil && !strings.Contains(err.Error(), "holds no bill files") && !strings.Contains(err.Error(), "AccessDenied") {
			t.Fatalf("sync = %v", err)
		}
	}
	run()
	if got := fake.lastExternalID(); got != old {
		t.Fatalf("sync before rotation assumed with %q, want %q", got, old)
	}

	admin := auth.Principal{Subject: "user:admin@harmonyx.co", Kind: auth.KindHuman, TenantID: c.home, Home: true,
		Bindings: []auth.Binding{{Role: auth.RolePlatformAdmin, TenantID: c.tenant}}}
	rotated, err := catalog.New(c.st, az).RotateClientPayerExternalID(ctx, admin, c.tenant, c.account, "operator lost the id")
	if err != nil {
		t.Fatal(err)
	}
	run()
	if got := fake.lastExternalID(); got != rotated.RoleExternalID {
		t.Errorf("sync after rotation assumed with %q, want the new %q", got, rotated.RoleExternalID)
	}
	title, detail := c.open(t, c.tenant, c.roleFP)
	if title == "" || !strings.Contains(detail, rotated.RoleExternalID) || strings.Contains(detail, old) {
		t.Errorf("trust policy still on the old id: Finding %q %s, want client_role_unusable naming only the new id", title, detail)
	}

	fake.trust(rotated.RoleExternalID)
	run()
	if got := fake.lastExternalID(); got != rotated.RoleExternalID {
		t.Errorf("sync once the client trusts the new id assumed with %q", got)
	}
	if title, _ := c.open(t, c.tenant, c.roleFP); title != "" {
		t.Errorf("client_role_unusable still open once the trust policy names the new id: %s", title)
	}
}
