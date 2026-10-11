package aws

import "testing"

const key = "arn:aws:kms:us-east-1:300000000001:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// TestSessionPolicyReadsOnlyTheExport: the session policy names the export
// prefix on both S3 statements, says plainly when there is no prefix, and
// lets the export's KMS key decrypt only through S3 in the bucket's region.
func TestSessionPolicyReadsOnlyTheExport(t *testing.T) {
	for name, tc := range map[string]struct {
		partition string
		export    Export
		want      string
	}{
		"prefix": {"aws", Export{Bucket: "c1-bills", Prefix: "exports/focus", Region: "us-east-1"},
			`{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::c1-bills","Condition":{"StringLike":{"s3:prefix":"exports/focus*"}}},` +
				`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::c1-bills/exports/focus*"}]}`},
		"no prefix is the whole bucket": {"aws", Export{Bucket: "c1-bills", Region: "us-east-1"},
			`{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::c1-bills"},` +
				`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::c1-bills/*"}]}`},
		"sse-kms": {"aws", Export{Bucket: "c1-bills", Prefix: "exports/", Region: "us-east-1", KMSKeyARN: key},
			`{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::c1-bills","Condition":{"StringLike":{"s3:prefix":"exports/*"}}},` +
				`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::c1-bills/exports/*"},` +
				`{"Effect":"Allow","Action":"kms:Decrypt","Resource":"` + key + `","Condition":{"StringEquals":{"kms:ViaService":"s3.us-east-1.amazonaws.com"}}}]}`},
		"govcloud": {"aws-us-gov", Export{Bucket: "c1-bills", Prefix: "x/", Region: "us-gov-west-1", KMSKeyARN: "arn:aws-us-gov:kms:us-gov-west-1:300000000001:key/mrk-1234abcd12ab34cd56ef1234567890ab"},
			`{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws-us-gov:s3:::c1-bills","Condition":{"StringLike":{"s3:prefix":"x/*"}}},` +
				`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws-us-gov:s3:::c1-bills/x/*"},` +
				`{"Effect":"Allow","Action":"kms:Decrypt","Resource":"arn:aws-us-gov:kms:us-gov-west-1:300000000001:key/mrk-1234abcd12ab34cd56ef1234567890ab","Condition":{"StringEquals":{"kms:ViaService":"s3.us-gov-west-1.amazonaws.com"}}}]}`},
	} {
		got, err := sessionPolicy(tc.partition, tc.export)
		if err != nil || got != tc.want {
			t.Errorf("%s: policy = %s, %v\nwant %s", name, got, err, tc.want)
		}
	}
	for name, e := range map[string]Export{
		"no bucket":                {Region: "us-east-1"},
		"wildcard prefix":          {Bucket: "c1-bills", Prefix: "exports/*", Region: "us-east-1"},
		"policy variable prefix":   {Bucket: "c1-bills", Prefix: "${aws:username}/", Region: "us-east-1"},
		"kms alias":                {Bucket: "c1-bills", Region: "us-east-1", KMSKeyARN: "arn:aws:kms:us-east-1:300000000001:alias/bills"},
		"kms wildcard":             {Bucket: "c1-bills", Region: "us-east-1", KMSKeyARN: "*"},
		"kms in another region":    {Bucket: "c1-bills", Region: "us-west-2", KMSKeyARN: key},
		"kms in another partition": {Bucket: "c1-bills", Region: "us-east-1", KMSKeyARN: "arn:aws-cn:kms:us-east-1:300000000001:key/1234abcd-12ab-34cd-56ef-1234567890ab"},
	} {
		if got, err := sessionPolicy("aws", e); err == nil {
			t.Errorf("%s: policy %s, want refused", name, got)
		}
	}
}
