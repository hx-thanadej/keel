package aws_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/catalog/catalogtest"
	"github.com/hx-thanadej/keel/internal/cloud/aws"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// TestKeylessRefusesAccessKeys: access keys in the environment are not
// Keel's identity (ADR-0007), even when the default chain would use them.
func TestKeylessRefusesAccessKeys(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	id, err := aws.Keyless(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Retrieve(context.Background()); err == nil || !strings.Contains(err.Error(), "never access keys") {
		t.Errorf("Retrieve with access keys = %v, want refused", err)
	}
}

// TestReadOnlyRoleMustBeInTheManagementAccount: a registered role ARN in
// another account, or a role no registration holds, is refused before any
// STS call.
func TestReadOnlyRoleMustBeInTheManagementAccount(t *testing.T) {
	_, elsewhere := catalogtest.ClientPayer(t, storetest.New(t), "aws", "300000000001", "arn:aws:iam::300000000002:role/KeelReadOnly")
	for name, grant := range map[string]catalog.ClientReadRole{"other account": elsewhere, "unregistered": {}} {
		if _, err := aws.ReadOnlyRole(nil, grant, aws.Export{Bucket: "c1-bills", Region: "us-east-1"}, "http://127.0.0.1:1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := aws.ReadsRole(nil, grant, "ap-southeast-1", "http://127.0.0.1:1"); err == nil {
			t.Errorf("%s: accepted for reads", name)
		}
	}
	if _, _, _, err := (&aws.ClientRole{}).Get(); err == nil {
		t.Error("the zero client role was assumed")
	}
}
