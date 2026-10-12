package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/cost"
)

type staticCreds struct{ id string }

func (s staticCreds) GetCredential() (common.CredentialIface, error) {
	return common.NewCredential(s.id, "base-key"), nil
}

func TestBillCredentialsAssumesPayerRole(t *testing.T) {
	var calls int
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		var req struct{ RoleArn string }
		_ = json.Unmarshal(body, &req)
		if r.Header.Get("X-TC-Action") != "AssumeRole" || req.RoleArn != "qcs::cam::uin/200045645249:roleName/KeelBillReader" ||
			!strings.Contains(r.Header.Get("Authorization"), "Credential=base-id/") {
			t.Errorf("STS got action %q role %q auth %q", r.Header.Get("X-TC-Action"), req.RoleArn, r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"Response":{"Credentials":{"TmpSecretId":"payer-id","TmpSecretKey":"payer-key","Token":"payer-token"},"ExpiredTime":4102444800,"RequestId":"r"}}`)
	}))
	defer sts.Close()

	base := staticCreds{id: "base-id"}
	p := billCredentials(base, "200045645249", "KeelBillReader", "ap-bangkok")
	role, ok := p.(*tencent.MemberRole)
	if !ok {
		t.Fatalf("bill credentials = %T, want the assumed payer role", p)
	}
	role.Endpoint = sts.URL
	for range 2 {
		c, err := p.GetCredential()
		if err != nil {
			t.Fatal(err)
		}
		if id, _, token := c.GetCredential(); id != "payer-id" || token != "payer-token" {
			t.Fatalf("bill credentials = %s/%s, want the assumed role's", id, token)
		}
	}
	if calls != 1 {
		t.Errorf("STS calls = %d, want 1 (cached until near expiry)", calls)
	}
}

func TestBillCredentialsWithoutRoleKeepBaseIdentity(t *testing.T) {
	base := staticCreds{id: "base-id"}
	if p := billCredentials(base, "200045645249", "", "ap-bangkok"); p != common.Provider(base) {
		t.Fatalf("bill credentials = %#v, want the base identity", p)
	}
}

// TestClientPayerConnectAssumesEachClientsRole: each client payer's bills
// and invoices are read with credentials from that client's own read-only
// role, assumed from Keel's base identity; a role outside the payer is refused.
func TestClientPayerConnectAssumesEachClientsRole(t *testing.T) {
	var assumed []string
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct{ RoleArn, ExternalId string }
		_ = json.Unmarshal(body, &req)
		externalIDs := map[string]string{"qcs::cam::uin/300000000001:roleName/KeelReadOnly": "ext-c1", "qcs::cam::uin/300000000002:roleName/AcmeKeelRead": "ext-c2",
			"qcs::cam::uin/300000000001:roleName/Untrusted": "ext-c1"}
		if want := externalIDs[req.RoleArn]; req.ExternalId != want {
			t.Errorf("AssumeRole %s with ExternalId %q, want the payer's own %q", req.RoleArn, req.ExternalId, want)
		}
		if r.Header.Get("X-TC-Action") != "AssumeRole" || !strings.Contains(r.Header.Get("Authorization"), "Credential=base-id/") {
			t.Errorf("STS got action %q auth %q", r.Header.Get("X-TC-Action"), r.Header.Get("Authorization"))
		}
		assumed = append(assumed, req.RoleArn)
		if strings.HasSuffix(req.RoleArn, "/Untrusted") {
			_, _ = io.WriteString(w, `{"Response":{"Error":{"Code":"InvalidParameter.ExternalIdIncorrect","Message":"external id mismatch"},"RequestId":"r"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"Response":{"Credentials":{"TmpSecretId":"id-`+req.RoleArn+`","TmpSecretKey":"k","Token":"token-`+req.RoleArn+`"},"ExpiredTime":4102444800,"RequestId":"r"}}`)
	}))
	defer sts.Close()
	connect := clientPayerConnect(staticCreds{id: "base-id"}, sts.URL)

	payers := []cost.ClientPayer{
		{TenantID: "t1", PayerID: "300000000001", RoleARN: "qcs::cam::uin/300000000001:roleName/KeelReadOnly", RoleExternalID: "ext-c1", Bucket: "c1-bills-1250000001", Region: "ap-bangkok"},
		{TenantID: "t2", PayerID: "300000000002", RoleARN: "qcs::cam::uin/300000000002:roleName/AcmeKeelRead", RoleExternalID: "ext-c2", Bucket: "c2-bills-1250000002", Region: "ap-singapore"},
	}
	for _, p := range payers {
		_, inv, err := connect(p)
		if err != nil {
			t.Fatal(err)
		}
		c, err := inv.(tencent.Invoices).Creds.GetCredential()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, token := c.GetCredential(); token != "token-"+p.RoleARN {
			t.Errorf("payer %s reads with token %q, want its own role's", p.PayerID, token)
		}
	}
	if want := []string{payers[0].RoleARN, payers[1].RoleARN}; !slices.Equal(assumed, want) {
		t.Errorf("STS assumed %v, want %v", assumed, want)
	}

	elsewhere := payers[0]
	elsewhere.RoleARN = "qcs::cam::uin/300000000002:roleName/KeelReadOnly"
	if _, _, err := connect(elsewhere); err == nil {
		t.Error("a read-only role outside the payer account was accepted")
	}

	untrusted := payers[0]
	untrusted.RoleARN = "qcs::cam::uin/300000000001:roleName/Untrusted"
	if _, _, err := connect(untrusted); err == nil || !strings.Contains(err.Error(), "external id mismatch") {
		t.Errorf("connect with a role that refuses Keel = %v, want the AssumeRole error before any bill read", err)
	}
}

// webIdentity stands in for Keel's keyless AWS identity.
type webIdentity struct{}

func (webIdentity) Retrieve(context.Context) (sdk.Credentials, error) {
	return sdk.Credentials{AccessKeyID: "KEELBASE", SecretAccessKey: "base-secret", SessionToken: "base-token", Source: "WebIdentityCredentials"}, nil
}

// TestAWSClientPayerConnectReadsEachExportAsItsClient: each client
// management account's export is listed and read with credentials from that
// client's own role, assumed from Keel's identity with the payer's
// ExternalId and a session policy that allows only reading its bucket. The
// bucket sees nothing but reads; a role outside the management account or
// one that refuses Keel never reaches the bucket.
func TestAWSClientPayerConnectReadsEachExportAsItsClient(t *testing.T) {
	type assumeCall struct{ role, externalID, policy, signer string }
	var mu sync.Mutex
	var assumed []assumeCall
	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		mu.Lock()
		assumed = append(assumed, assumeCall{form.Get("RoleArn"), form.Get("ExternalId"), form.Get("Policy"), r.Header.Get("Authorization")})
		mu.Unlock()
		if form.Get("Action") != "AssumeRole" {
			t.Errorf("STS action %q", form.Get("Action"))
		}
		role := form.Get("RoleArn")
		if strings.HasSuffix(role, "/Untrusted") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized to perform sts:AssumeRole</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
			return
		}
		account := strings.Split(role, ":")[4]
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><AssumedRoleUser><Arn>`+role+`/keel</Arn><AssumedRoleId>AROA:keel</AssumedRoleId></AssumedRoleUser>`+
			`<Credentials><AccessKeyId>ASIA`+account+`</AccessKeyId><SecretAccessKey>secret-`+account+`</SecretAccessKey><SessionToken>token-`+account+`</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>`+
			`</AssumeRoleResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></AssumeRoleResponse>`)
	}))
	defer stsSrv.Close()

	type s3Call struct{ method, path, signer, token string }
	var reads []s3Call
	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reads = append(reads, s3Call{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("X-Amz-Security-Token")})
		mu.Unlock()
		bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if key == "" {
			var contents string
			for _, k := range []string{"exports/focus/data/BILLING_PERIOD=2026-09/part-0.csv.gz", "exports2/x.csv.gz"} {
				if strings.HasPrefix(k, r.URL.Query().Get("prefix")) {
					contents += `<Contents><Key>` + k + `</Key><ETag>"e-` + bucket + `"</ETag><Size>3</Size><LastModified>2026-09-02T00:00:00.000Z</LastModified></Contents>`
				}
			}
			_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>`+bucket+`</Name><Prefix>exports/</Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>`+contents+`</ListBucketResult>`)
			return
		}
		w.Header().Set("Last-Modified", "Wed, 02 Sep 2026 00:00:00 GMT")
		w.Header().Set("ETag", `"e-`+bucket+`"`)
		_, _ = io.WriteString(w, "csv")
	}))
	defer s3Srv.Close()
	connect := awsClientPayerConnect(webIdentity{}, stsSrv.URL, s3Srv.URL)

	payers := []cost.ClientPayer{
		{TenantID: "t1", PayerID: "300000000001", RoleARN: "arn:aws:iam::300000000001:role/KeelReadOnly", RoleExternalID: "0123456789abcdef0123456789abcdef", Bucket: "c1-bills", Prefix: "exports/", Region: "us-east-1"},
		{TenantID: "t2", PayerID: "300000000002", RoleARN: "arn:aws:iam::300000000002:role/billing/AcmeKeelRead", RoleExternalID: "fedcba9876543210fedcba9876543210", Bucket: "c2-bills", Prefix: "exports/", Region: "ap-southeast-1",
			KMSKeyARN: "arn:aws:kms:ap-southeast-1:300000000002:key/1234abcd-12ab-34cd-56ef-1234567890ab"},
	}
	wantPolicies := []string{
		`{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::c1-bills","Condition":{"StringLike":{"s3:prefix":"exports/*"}}},` +
			`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::c1-bills/exports/*"}]}`,
		`{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::c2-bills","Condition":{"StringLike":{"s3:prefix":"exports/*"}}},` +
			`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::c2-bills/exports/*"},` +
			`{"Effect":"Allow","Action":"kms:Decrypt","Resource":"arn:aws:kms:ap-southeast-1:300000000002:key/1234abcd-12ab-34cd-56ef-1234567890ab","Condition":{"StringEquals":{"kms:ViaService":"s3.ap-southeast-1.amazonaws.com"}}}]}`,
	}
	for _, p := range payers {
		objs, inv, err := connect(p)
		if err != nil {
			t.Fatal(err)
		}
		if inv != nil {
			t.Errorf("payer %s has an invoice source; AWS client payers have none", p.PayerID)
		}
		listed, err := objs.(cost.ETagLister).ListWithETag(context.Background(), cost.FolderPrefix("exports"))
		if err != nil || len(listed) != 1 || strings.HasPrefix(listed[0].Key, "exports2/") {
			t.Fatalf("payer %s listed %v, %v", p.PayerID, listed, err)
		}
		if _, err := objs.Get(context.Background(), listed[0].Key); err != nil {
			t.Fatal(err)
		}
	}

	if len(assumed) != 2 {
		t.Fatalf("STS calls %+v, want one per payer", assumed)
	}
	for i, p := range payers {
		a := assumed[i]
		if a.role != p.RoleARN || a.externalID != p.RoleExternalID {
			t.Errorf("AssumeRole %s with ExternalId %q, want %s with the payer's own %q", a.role, a.externalID, p.RoleARN, p.RoleExternalID)
		}
		if !strings.Contains(a.signer, "Credential=KEELBASE/") {
			t.Errorf("AssumeRole signed by %q, want Keel's base identity", a.signer)
		}
		if a.policy != wantPolicies[i] {
			t.Errorf("session policy %s\nwant %s", a.policy, wantPolicies[i])
		}
	}
	if len(reads) != 4 {
		t.Fatalf("S3 calls %+v, want a list and a get per payer", reads)
	}
	for _, r := range reads {
		if r.method != http.MethodGet {
			t.Errorf("S3 %s %s: Keel only reads a client's bucket", r.method, r.path)
		}
		bucket, _, _ := strings.Cut(strings.TrimPrefix(r.path, "/"), "/")
		account := map[string]string{"c1-bills": "300000000001", "c2-bills": "300000000002"}[bucket]
		if !strings.Contains(r.signer, "Credential=ASIA"+account+"/") || r.token != "token-"+account {
			t.Errorf("S3 %s read with %q / %q, want the session of %s's own role", r.path, r.signer, r.token, account)
		}
	}

	assumed, reads = nil, nil
	elsewhere := payers[0]
	elsewhere.RoleARN = "arn:aws:iam::300000000002:role/KeelReadOnly"
	untrusted := payers[0]
	untrusted.RoleARN = "arn:aws:iam::300000000001:role/Untrusted"
	for name, p := range map[string]cost.ClientPayer{"role outside the management account": elsewhere, "role refusing Keel": untrusted} {
		_, _, err := connect(p)
		var roleErr *cost.RoleError
		if !errors.As(err, &roleErr) {
			t.Errorf("%s: connect = %v, want a RoleError", name, err)
		}
	}
	if len(assumed) != 1 || assumed[0].role != untrusted.RoleARN {
		t.Errorf("STS calls %+v, want only the in-account role tried", assumed)
	}
	if len(reads) != 0 {
		t.Errorf("S3 calls %+v after the role failed", reads)
	}
}

// TestBrokenAWSIdentityLeavesTencentSyncing: an AWS config Keel cannot load
// does not stop the Tencent client sync, and the AWS sync reports it as
// Keel's own identity problem. Access keys in the environment fail the same
// keyless check before any client role is tried.
func TestBrokenAWSIdentityLeavesTencentSyncing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/config", []byte("[profile other\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string]map[string]string{
		"malformed config": {"AWS_CONFIG_FILE": dir + "/config", "AWS_PROFILE": "missing"},
		"access keys":      {"AWS_CONFIG_FILE": "/dev/null", "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
			t.Setenv("KEEL_ENV", "dev")
			t.Setenv("TENCENTCLOUD_SECRET_ID", "keel-dev-id")
			t.Setenv("TENCENTCLOUD_SECRET_KEY", "keel-dev-key")
			for k, v := range env {
				t.Setenv(k, v)
			}
			fake := &fakeSTS{provider: "tencent"}
			fake.set(true, true)
			srv := httptest.NewServer(fake)
			defer srv.Close()
			syncs := clientBillSyncs(context.Background(), nil, srv.URL)
			providers := []string{}
			for _, cs := range syncs {
				providers = append(providers, cs.Provider)
			}
			if !slices.Equal(providers, []string{"tencent", "aws"}) {
				t.Fatalf("client syncs %v, want tencent and aws", providers)
			}
			if err := syncs[0].Ready(context.Background()); err != nil || syncs[0].Connect == nil {
				t.Errorf("the Tencent sync is not ready with Keel's Tencent credentials and a broken AWS identity: %v", err)
			}
			if err := syncs[1].Ready(context.Background()); err == nil {
				t.Error("the AWS sync is ready with a broken Keel identity")
			}
		})
	}
}
