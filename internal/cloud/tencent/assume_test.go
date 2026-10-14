package tencent_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
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

// TestUncheckedRolesAreNeverAssumed: a Keel role or a client role that no
// constructor built (the zero values a caller can still write) fails
// before any STS call (#244).
func TestUncheckedRolesAreNeverAssumed(t *testing.T) {
	f := &fakeSTS{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	for name, p := range map[string]common.Provider{
		"zero keel role":   &tencent.KeelRole{},
		"zero client role": &tencent.ClientRole{},
	} {
		if _, err := p.GetCredential(); err == nil {
			t.Errorf("%s: assumed", name)
		}
	}
	if len(f.bodies) != 0 {
		t.Fatalf("STS calls %v, want none", f.bodies)
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
