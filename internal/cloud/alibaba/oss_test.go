package alibaba

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// Known-answer vector, derived once with
// printf 'GET\n\n\nWed, 07 Oct 2026 03:00:00 GMT\nx-oss-security-token:tok\n/b/k' | openssl dgst -sha1 -hmac secret -binary | base64
func TestSignV1(t *testing.T) {
	got := sign(Credentials{AccessKeyID: "id", AccessKeySecret: "secret", SecurityToken: "tok"}, "Wed, 07 Oct 2026 03:00:00 GMT", "/b/k")
	if want := "OSS id:CMqOBR2DDOO4uBLMwSaSAy4iNBc="; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// OSS's SignatureDoesNotMatch body echoes StringToSign, which carries the
// STS security token; STS errors may echo request inputs.
func TestErrorsOmitResponseBodies(t *testing.T) {
	const token = "CAIS-SECRET-TOKEN"
	oss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match</Message><RequestId>RID-1</RequestId><HostId>b.oss</HostId><StringToSign>GET\n\n\nDate\nx-oss-security-token:`+token+`\n/b/</StringToSign></Error>`)
	}))
	t.Cleanup(oss.Close)
	o := OSS{Bucket: "b", Endpoint: oss.URL, Creds: staticCreds{Credentials{AccessKeyID: "STS.id", AccessKeySecret: "s", SecurityToken: token}}}
	_, err := o.ListWithETag(context.Background(), "")
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "SignatureDoesNotMatch") || !strings.Contains(err.Error(), "RID-1") {
		t.Fatalf("oss error %v: want status, Code and RequestId only", err)
	}

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"Code":"InvalidParameter.OIDCToken","Message":"OIDCToken `+token+` is invalid","RequestId":"RID-2"}`)
	}))
	t.Cleanup(sts.Close)
	_, err = (&RRSA{RoleArn: "r", ProviderArn: "p", TokenFile: tokenFile, Endpoint: sts.URL}).Credentials(context.Background())
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "InvalidParameter.OIDCToken") || !strings.Contains(err.Error(), "RID-2") {
		t.Fatalf("sts error %v: want status, Code and RequestId only", err)
	}
}

type staticCreds struct{ c Credentials }

func (s staticCreds) Credentials(context.Context) (Credentials, error) { return s.c, nil }
