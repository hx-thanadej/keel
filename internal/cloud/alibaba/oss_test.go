package alibaba

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRRSAAndSignedOSS(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("ack-sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 3, 0, 0, 0, time.UTC)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "AssumeRoleWithOIDC" || r.Form.Get("OIDCToken") != "ack-sa-jwt" || r.Form.Get("RoleArn") != "acs:ram::1:role/keel-bills" {
			http.Error(w, `{"Code":"InvalidParameter"}`, http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, `{"Credentials":{"AccessKeyId":"STS.id","AccessKeySecret":"secret","SecurityToken":"tok","Expiration":"%s"}}`, now.Add(time.Hour).Format(time.RFC3339))
	}))
	t.Cleanup(sts.Close)
	creds := &RRSA{RoleArn: "acs:ram::1:role/keel-bills", ProviderArn: "acs:ram::1:oidc-provider/ack", TokenFile: tokenFile, Endpoint: sts.URL, Now: func() time.Time { return now }}

	date := now.Format(http.TimeFormat)
	want := map[string]string{
		"/":                         sign(Credentials{AccessKeyID: "STS.id", AccessKeySecret: "secret", SecurityToken: "tok"}, date, "/keel-bills/"),
		"/bills/2026-09/detail.csv": sign(Credentials{AccessKeyID: "STS.id", AccessKeySecret: "secret", SecurityToken: "tok"}, date, "/keel-bills/bills/2026-09/detail.csv"),
	}
	oss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want[r.URL.Path] || r.Header.Get("x-oss-security-token") != "tok" || r.Header.Get("Date") != date {
			http.Error(w, "SignatureDoesNotMatch", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/" {
			if r.URL.Query().Get("marker") == "" {
				_, _ = fmt.Fprint(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextMarker>a</NextMarker><Contents><Key>bills/2026-09/detail.csv</Key><ETag>"E1"</ETag></Contents></ListBucketResult>`)
				return
			}
			_, _ = fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
			return
		}
		_, _ = fmt.Fprint(w, "data")
	}))
	t.Cleanup(oss.Close)
	o := OSS{Bucket: "keel-bills", Endpoint: oss.URL, Creds: creds, Now: func() time.Time { return now }}
	objs, err := o.ListWithETag(context.Background(), "bills/")
	if err != nil || len(objs) != 1 || objs[0].ETag != "E1" {
		t.Fatalf("%+v %v", objs, err)
	}
	raw, err := o.Get(context.Background(), objs[0].Key)
	if err != nil || string(raw) != "data" {
		t.Fatalf("%q %v", raw, err)
	}
}

// The V1 signature for a known request (OSS documentation's algorithm:
// base64(HMAC-SHA1(secret, VERB\nMD5\nType\nDate\nheaders+resource))).
func TestSignV1(t *testing.T) {
	got := sign(Credentials{AccessKeyID: "id", AccessKeySecret: "secret", SecurityToken: "tok"}, "Wed, 07 Oct 2026 03:00:00 GMT", "/b/k")
	if got[:7] != "OSS id:" || len(got) != 7+28 {
		t.Fatalf("%q", got)
	}
}
