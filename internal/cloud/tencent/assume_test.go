package tencent_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

type baseCreds struct{}

func (baseCreds) GetCredential() (common.CredentialIface, error) {
	return common.NewCredential("base-id", "base-key"), nil
}

// TestUnguardedKeelRoleIsNeverAssumed: Keel's own role (no ExternalID)
// without a Guard fails before any STS call, so a job that forgets the
// ownership check cannot reach a client's organisation (#240).
func TestUnguardedKeelRoleIsNeverAssumed(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer srv.Close()
	r := &tencent.MemberRole{Base: baseCreds{}, Account: "300000000001", Role: "KeelMember", Region: "ap-bangkok", Endpoint: srv.URL}
	if _, err := r.GetCredential(); err == nil || calls != 0 {
		t.Fatalf("unguarded Keel role: err %v, STS calls %d; want an error and no call", err, calls)
	}
}
