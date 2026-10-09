package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
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
