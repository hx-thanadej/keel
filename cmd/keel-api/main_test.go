package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

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
		{TenantID: "t1", UIN: "300000000001", RoleARN: "qcs::cam::uin/300000000001:roleName/KeelReadOnly", ExternalID: "ext-c1", Bucket: "c1-bills-1250000001", Region: "ap-bangkok"},
		{TenantID: "t2", UIN: "300000000002", RoleARN: "qcs::cam::uin/300000000002:roleName/AcmeKeelRead", ExternalID: "ext-c2", Bucket: "c2-bills-1250000002", Region: "ap-singapore"},
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
			t.Errorf("payer %s reads with token %q, want its own role's", p.UIN, token)
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
