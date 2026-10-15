package archive

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/minio/minio-go/v7"
)

// TestReaderCannotWrite: a Reader, which bill and COS reads use, gets and
// lists objects, and every write it could make (PUT, DELETE, POST) fails
// with ErrReadOnly before it reaches the bucket.
func TestReaderCannotWrite(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		if r.URL.Query().Has("list-type") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<ListBucketResult><Name>bills</Name><IsTruncated>false</IsTruncated><Contents><Key>a.csv</Key><ETag>"e"</ETag></Contents></ListBucketResult>`))
			return
		}
		w.Header().Set("Last-Modified", "Mon, 2 Jan 2006 15:04:05 GMT")
		w.Header().Set("ETag", `"e"`)
		_, _ = w.Write([]byte("cost"))
	}))
	defer srv.Close()
	r, err := NewReader(S3Config{Endpoint: strings.TrimPrefix(srv.URL, "http://"), Insecure: true, Region: "ap-bangkok", Bucket: "bills",
		Creds: StaticCreds("id", "key", "")})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if b, err := r.Get(ctx, "a.csv"); err != nil || string(b) != "cost" {
		t.Fatalf("Get: %q %v", b, err)
	}
	if vs, err := r.ListWithETag(ctx, ""); err != nil || len(vs) != 1 {
		t.Fatalf("ListWithETag: %v %v", vs, err)
	}
	reads := len(methods)

	writes := map[string]func() error{
		"PUT": func() error { return r.s.Put(ctx, "a.csv", []byte("x"), "text/csv") },
		"DELETE": func() error {
			return r.s.c.RemoveObject(ctx, "bills", "a.csv", minio.RemoveObjectOptions{})
		},
		"POST": func() error {
			objs := make(chan minio.ObjectInfo, 1)
			objs <- minio.ObjectInfo{Key: "a.csv"}
			close(objs)
			for e := range r.s.c.RemoveObjects(ctx, "bills", objs, minio.RemoveObjectsOptions{}) {
				return e.Err
			}
			return nil
		},
	}
	for name, write := range writes {
		if err := write(); !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s: err %v, want ErrReadOnly", name, err)
		}
	}
	if len(methods) != reads {
		t.Fatalf("writes reached the bucket: %v", methods[reads:])
	}
}
