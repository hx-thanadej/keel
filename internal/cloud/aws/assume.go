package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Identity is Keel's own AWS identity, the principal a client's trust policy
// names.
type Identity = sdk.CredentialsProvider

// keylessSources are the credential sources Keel accepts for its own
// identity: web identity (OIDC from Keel's cluster), the instance role, or
// the container credentials endpoint. Never access keys (ADR-0007).
var keylessSources = []string{stscreds.WebIdentityProviderName, ec2rolecreds.ProviderName, endpointcreds.ProviderName}

type keylessOnly struct{ Identity }

func (k keylessOnly) Retrieve(ctx context.Context) (sdk.Credentials, error) {
	c, err := k.Identity.Retrieve(ctx)
	if err != nil {
		return c, err
	}
	if !slices.Contains(keylessSources, c.Source) {
		return sdk.Credentials{}, fmt.Errorf("aws credentials from %q refused: Keel's identity must be web identity, an instance role or container credentials, never access keys", c.Source)
	}
	return c, nil
}

// Keyless loads Keel's identity from the default chain and refuses any
// source that is not keyless.
func Keyless(ctx context.Context) (Identity, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil, err
	}
	return keylessOnly{cfg.Credentials}, nil
}

var roleARN = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):iam::(\d{12}):role/([\w+=,.@-]{1,128}/)*[\w+=,.@-]{1,64}$`)

// ClientRole is a client's read-only role in its management account
// (ADR-0018), assumed from Keel's identity with Keel's ExternalId for that
// payer.
type ClientRole struct {
	creds *sdk.CredentialsCache
}

// ReadOnlyRole assumes arn, which must live in account, the client's
// management account. Every session carries a session policy allowing only
// s3:ListBucket and s3:GetObject on bucket, so the credentials read the
// bill export and nothing else, whatever the role itself allows (AWS grants
// the intersection). stsEndpoint overrides the STS endpoint, for tests.
func ReadOnlyRole(base Identity, arn, account, externalID, bucket, region, stsEndpoint string) (*ClientRole, error) {
	m := roleARN.FindStringSubmatch(arn)
	if m == nil {
		return nil, fmt.Errorf("read-only role %q is not arn:aws:iam::<account>:role/<name>", arn)
	}
	if m[2] != account {
		return nil, fmt.Errorf("read-only role %s is not in management account %s", arn, account)
	}
	if externalID == "" {
		return nil, fmt.Errorf("read-only role %s has no ExternalId", arn)
	}
	policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{
		{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:" + m[1] + ":s3:::" + bucket},
		{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:" + m[1] + ":s3:::" + bucket + "/*"},
	}})
	if err != nil {
		return nil, err
	}
	client := sts.New(sts.Options{Region: region, Credentials: base}, func(o *sts.Options) {
		if stsEndpoint != "" {
			o.BaseEndpoint = &stsEndpoint
		}
	})
	p := stscreds.NewAssumeRoleProvider(client, arn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "keel"
		o.ExternalID = &externalID
		o.Policy = sdk.String(string(policy))
		o.Duration = time.Hour
	})
	return &ClientRole{creds: sdk.NewCredentialsCache(p)}, nil
}

// Get returns the session's (access key id, secret, session token),
// assuming the role again when the session is near expiry.
func (r *ClientRole) Get() (id, key, token string, err error) {
	c, err := r.creds.Retrieve(context.Background())
	if err != nil {
		return "", "", "", err
	}
	return c.AccessKeyID, c.SecretAccessKey, c.SessionToken, nil
}
