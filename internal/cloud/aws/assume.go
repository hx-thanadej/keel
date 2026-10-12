package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/hx-thanadej/keel/internal/cost"
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

// CallerIdentity asks STS who base is. Credentials can load and still be
// rejected (expired, revoked, untrusted web identity), and an AssumeRole
// made with them fails as if the client's role had refused; this tells the
// two apart. It needs no permission. stsEndpoint overrides the STS
// endpoint, for tests.
func CallerIdentity(ctx context.Context, base Identity, stsEndpoint string) error {
	_, err := stsWith(base, "us-east-1", stsEndpoint).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return err
}

func stsWith(base Identity, region, endpoint string) *sts.Client {
	return sts.New(sts.Options{Region: region, Credentials: base}, func(o *sts.Options) {
		if endpoint != "" {
			o.BaseEndpoint = &endpoint
		}
	})
}

var roleARN = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):iam::(\d{12}):role/([\w+=,.@-]{1,128}/)*[\w+=,.@-]{1,64}$`)

// ClientRole is a client's read-only role in its management account
// (ADR-0018), assumed from Keel's identity with Keel's ExternalId for that
// payer.
type ClientRole struct {
	creds *sdk.CredentialsCache
}

// Export is where a client management account's Data Exports land: the S3
// bucket and its region, the export's folder (a key prefix; one without a
// trailing "/" is given one, and empty means the whole bucket), and the
// bucket's SSE-KMS key ARN when it has one.
type Export struct {
	Bucket, Prefix, Region, KMSKeyARN string
}

var kmsKeyARN = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]+):\d{12}:key/(mrk-[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

type statement struct {
	Effect    string
	Action    string
	Resource  string
	Condition map[string]map[string]string `json:",omitempty"`
}

// sessionPolicy allows reading e and nothing else: s3:ListBucket on the
// bucket only for keys under the prefix, s3:GetObject only on objects under
// it, and, for an SSE-KMS bucket, kms:Decrypt on its key only when S3 in the
// bucket's region calls KMS for this session (kms:ViaService). An empty
// prefix allows the whole bucket. partition is the role's ARN partition.
func sessionPolicy(partition string, e Export) (string, error) {
	if e.Bucket == "" {
		return "", fmt.Errorf("export has no bucket")
	}
	if strings.ContainsAny(e.Bucket+e.Prefix, "*?$") {
		return "", fmt.Errorf("export bucket %q or prefix %q holds an IAM wildcard or policy variable", e.Bucket, e.Prefix)
	}
	prefix := cost.FolderPrefix(e.Prefix)
	list := statement{Effect: "Allow", Action: "s3:ListBucket", Resource: "arn:" + partition + ":s3:::" + e.Bucket}
	get := statement{Effect: "Allow", Action: "s3:GetObject", Resource: "arn:" + partition + ":s3:::" + e.Bucket + "/" + prefix + "*"}
	if prefix != "" {
		list.Condition = map[string]map[string]string{"StringLike": {"s3:prefix": prefix + "*"}}
	}
	statements := []statement{list, get}
	if e.KMSKeyARN != "" {
		m := kmsKeyARN.FindStringSubmatch(e.KMSKeyARN)
		if m == nil || m[1] != partition || m[2] != e.Region {
			return "", fmt.Errorf("KMS key %q is not arn:%s:kms:%s:<account>:key/<id>, the bucket's partition and region", e.KMSKeyARN, partition, e.Region)
		}
		// AWS documents the ViaService name as s3.<region>.amazonaws.com in
		// every partition.
		statements = append(statements, statement{Effect: "Allow", Action: "kms:Decrypt", Resource: e.KMSKeyARN,
			Condition: map[string]map[string]string{"StringEquals": {"kms:ViaService": "s3." + e.Region + ".amazonaws.com"}}})
	}
	b, err := json.Marshal(struct {
		Version   string
		Statement []statement
	}{"2012-10-17", statements})
	return string(b), err
}

// ReadOnlyRole assumes arn, which must live in account, the client's
// management account. Every session carries sessionPolicy(export), and AWS
// grants the intersection of the role's policies and the session policy, so
// even a role that allows more reads only the export's prefix (and decrypts
// only through S3 with the export's key) through Keel. stsEndpoint
// overrides the STS endpoint, for tests.
func ReadOnlyRole(base Identity, arn, account, externalID string, export Export, stsEndpoint string) (*ClientRole, error) {
	m, err := clientRoleARN(arn, account, externalID)
	if err != nil {
		return nil, err
	}
	policy, err := sessionPolicy(m[1], export)
	if err != nil {
		return nil, err
	}
	return assume(base, arn, externalID, policy, export.Region, stsEndpoint), nil
}

// clientRoleARN checks that arn is a role in account and that Keel has an
// ExternalId for it, and returns arn's partition and account.
func clientRoleARN(arn, account, externalID string) ([]string, error) {
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
	return m, nil
}

func assume(base Identity, arn, externalID, policy, region, stsEndpoint string) *ClientRole {
	p := stscreds.NewAssumeRoleProvider(stsWith(base, region, stsEndpoint), arn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "keel"
		o.ExternalID = &externalID
		o.Policy = &policy
		o.Duration = time.Hour
	})
	return &ClientRole{creds: sdk.NewCredentialsCache(p)}
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
