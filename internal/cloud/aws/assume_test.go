package aws_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/cloud/aws"
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

// TestReadOnlyRoleMustBeInTheManagementAccount: a role ARN from another
// account, or a payer without Keel's ExternalId, is refused before any STS
// call.
func TestReadOnlyRoleMustBeInTheManagementAccount(t *testing.T) {
	for name, tc := range map[string]struct{ arn, externalID string }{
		"other account":  {"arn:aws:iam::300000000002:role/KeelReadOnly", "0123456789abcdef0123456789abcdef"},
		"not a role":     {"arn:aws:iam::300000000001:user/keel", "0123456789abcdef0123456789abcdef"},
		"no external id": {"arn:aws:iam::300000000001:role/KeelReadOnly", ""},
	} {
		if _, err := aws.ReadOnlyRole(nil, tc.arn, "300000000001", tc.externalID, aws.Export{Bucket: "c1-bills", Region: "us-east-1"}, "http://127.0.0.1:1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
