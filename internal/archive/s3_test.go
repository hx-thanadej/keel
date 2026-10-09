package archive_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/archive"
)

// fakeBucket is a path-style S3 endpoint for bucket "archive". It ignores
// auth (signing is the SDK's job) and keeps each PUT's headers so tests can
// assert what reached the wire.
type fakeBucket struct {
	mu        sync.Mutex
	objs      map[string][]byte
	hdr       map[string]http.Header
	lock      bool
	versioned bool
}

func fakeS3(t *testing.T, lock, versioned bool) (*fakeBucket, *httptest.Server) {
	t.Helper()
	f := &fakeBucket{objs: map[string][]byte{}, hdr: map[string]http.Header{}, lock: lock, versioned: versioned}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeBucket) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/archive"), "/")
	q := r.URL.Query()
	xmlErr := func(code string) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `<Error><Code>%s</Code></Error>`, code)
	}
	switch {
	case r.Method == http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			b = decodeAWSChunked(b)
		}
		f.objs[key] = b
		f.hdr[key] = r.Header.Clone()
		w.Header().Set("ETag", `"x"`)
	case q.Has("object-lock"):
		if !f.lock {
			xmlErr("ObjectLockConfigurationNotFoundError")
			return
		}
		_, _ = w.Write([]byte(`<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`))
	case q.Has("versioning"):
		if f.versioned {
			_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
			return
		}
		_, _ = w.Write([]byte(`<VersioningConfiguration></VersioningConfiguration>`))
	case q.Has("retention"):
		h := f.hdr[key]
		if h == nil || h.Get("X-Amz-Object-Lock-Mode") == "" {
			xmlErr("NoSuchObjectLockConfiguration")
			return
		}
		_, _ = fmt.Fprintf(w, `<Retention><Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`,
			h.Get("X-Amz-Object-Lock-Mode"), h.Get("X-Amz-Object-Lock-Retain-Until-Date"))
	case q.Get("list-type") == "2":
		var keys []string
		for k := range f.objs {
			if strings.HasPrefix(k, q.Get("prefix")) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var b strings.Builder
		fmt.Fprintf(&b, `<ListBucketResult><Name>archive</Name><KeyCount>%d</KeyCount><IsTruncated>false</IsTruncated>`, len(keys))
		for _, k := range keys {
			fmt.Fprintf(&b, `<Contents><Key>%s</Key><ETag>"x"</ETag><Size>%d</Size></Contents>`, k, len(f.objs[k]))
		}
		b.WriteString(`</ListBucketResult>`)
		_, _ = w.Write([]byte(b.String()))
	case r.Method == http.MethodGet:
		b, ok := f.objs[key]
		if !ok {
			xmlErr("NoSuchKey")
			return
		}
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("ETag", `"x"`)
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func newS3(t *testing.T, srv *httptest.Server, retentionDays int) *archive.S3 {
	t.Helper()
	s3, err := archive.NewS3(archive.S3Config{Endpoint: strings.TrimPrefix(srv.URL, "http://"), Insecure: true, Bucket: "archive", Region: "ap-southeast-1",
		Creds: archive.StaticCreds("id", "secret", ""), RetentionDays: retentionDays})
	if err != nil {
		t.Fatal(err)
	}
	return s3
}

func TestS3ObjectStorePutGet(t *testing.T) {
	f, srv := fakeS3(t, false, false)
	s3 := newS3(t, srv, 0)
	if err := s3.Put(context.Background(), "a/b.json", []byte(`{"x":1}`), "application/json"); err != nil {
		t.Fatal(err)
	}
	if string(f.objs["a/b.json"]) != `{"x":1}` {
		t.Fatalf("stored %q", f.objs["a/b.json"])
	}
	if h := f.hdr["a/b.json"]; h.Get("X-Amz-Object-Lock-Mode") != "" || h.Get("X-Amz-Object-Lock-Retain-Until-Date") != "" {
		t.Fatalf("no retention configured, but PUT carried lock headers: %v", h)
	}
	got, err := s3.Get(context.Background(), "a/b.json")
	if err != nil || string(got) != `{"x":1}` {
		t.Fatalf("get %q %v", got, err)
	}
	if _, err := s3.Get(context.Background(), "missing"); err != archive.ErrNotFound {
		t.Fatalf("missing: %v", err)
	}
}

func TestPutWritesComplianceRetention(t *testing.T) {
	f, srv := fakeS3(t, true, true)
	s3 := newS3(t, srv, 2555)
	body := []byte(`{"seq":1}` + "\n")
	before := time.Now().UTC().Truncate(time.Second)
	if err := s3.Put(context.Background(), "activity-log/v1/t/1.jsonl", body, "application/x-ndjson"); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	h := f.hdr["activity-log/v1/t/1.jsonl"]
	if got := h.Get("X-Amz-Object-Lock-Mode"); got != "COMPLIANCE" {
		t.Fatalf("x-amz-object-lock-mode = %q, want COMPLIANCE", got)
	}
	until, err := time.Parse(time.RFC3339, h.Get("X-Amz-Object-Lock-Retain-Until-Date"))
	if err != nil {
		t.Fatalf("retain-until %q: %v", h.Get("X-Amz-Object-Lock-Retain-Until-Date"), err)
	}
	if lo, hi := before.AddDate(0, 0, 2555), after.AddDate(0, 0, 2555); until.Before(lo) || until.After(hi) {
		t.Fatalf("retain-until %s not within [%s, %s]", until, lo, hi)
	}
	if !strings.HasSuffix(h.Get("X-Amz-Object-Lock-Retain-Until-Date"), "Z") {
		t.Fatalf("retain-until must be UTC: %q", h.Get("X-Amz-Object-Lock-Retain-Until-Date"))
	}
	sum := md5.Sum(body)
	if got := h.Get("Content-Md5"); got != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("Content-MD5 = %q, want MD5 of body", got)
	}
	if h.Get("X-Amz-Object-Lock-Legal-Hold") != "" {
		t.Fatal("legal hold must stay off")
	}

	rs, err := s3.Retentions(context.Background(), "activity-log/v1/t/")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Mode != "COMPLIANCE" || !rs[0].Until.Equal(until) {
		t.Fatalf("retentions %+v, want one COMPLIANCE until %s", rs, until)
	}
}

func TestRetentionsReportsUnlockedObject(t *testing.T) {
	f, srv := fakeS3(t, true, true)
	f.objs["activity-log/v1/t/old.jsonl"] = []byte("x")
	rs, err := newS3(t, srv, 0).Retentions(context.Background(), "activity-log/v1/t/")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Mode != "" || !rs[0].Until.IsZero() {
		t.Fatalf("retentions %+v, want one object without retention", rs)
	}
}

func TestRequireObjectLock(t *testing.T) {
	cases := []struct {
		name            string
		lock, versioned bool
		wantErr         string
	}{
		{"locked and versioned", true, true, ""},
		{"no object lock", false, true, "Object Lock"},
		{"no versioning", true, false, "versioning"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, srv := fakeS3(t, c.lock, c.versioned)
			err := newS3(t, srv, 2555).RequireObjectLock(context.Background())
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("error %v, want one mentioning %q", err, c.wantErr)
			}
		})
	}
}

func TestRetentionBelowOneYearRejected(t *testing.T) {
	for _, s := range []string{"364", "0", "-1", "seven"} {
		if _, err := archive.ParseRetentionDays(s); err == nil {
			t.Errorf("ParseRetentionDays(%q) accepted", s)
		}
	}
	if d, err := archive.ParseRetentionDays(""); err != nil || d != 2555 {
		t.Errorf("default = %d, %v; want 2555", d, err)
	}
	if d, err := archive.ParseRetentionDays("365"); err != nil || d != 365 {
		t.Errorf("365 = %d, %v", d, err)
	}
	if _, err := archive.NewS3(archive.S3Config{Endpoint: "localhost:1", Bucket: "archive", RetentionDays: 30}); err == nil {
		t.Error("NewS3 accepted 30 days of retention")
	}
}

// decodeAWSChunked strips aws-chunked framing ("<hex>;chunk-signature=…\r\n<data>\r\n").
func decodeAWSChunked(b []byte) []byte {
	var out []byte
	for len(b) > 0 {
		i := bytes.Index(b, []byte("\r\n"))
		if i < 0 {
			break
		}
		var n int
		_, _ = fmt.Sscanf(string(b[:i]), "%x", &n)
		b = b[i+2:]
		if n == 0 {
			break
		}
		out = append(out, b[:n]...)
		b = b[n+2:]
	}
	return out
}
