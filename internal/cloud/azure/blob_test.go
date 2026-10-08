package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFederatedBlobListAndGet(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("k8s-sa-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_assertion") != "k8s-sa-jwt" || r.Form.Get("client_id") != "app-1" || r.Form.Get("scope") != StorageScope ||
			r.Form.Get("client_secret") != "" || r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		tokens++
		_, _ = fmt.Fprint(w, `{"access_token":"at-1","expires_in":3600}`)
	})
	mux.HandleFunc("GET /exports/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" || r.Header.Get("x-ms-version") == "" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("comp") == "list" {
			if r.URL.Query().Get("prefix") != "focus/" {
				http.Error(w, "prefix", http.StatusBadRequest)
				return
			}
			if r.URL.Query().Get("marker") == "" {
				_, _ = fmt.Fprint(w, `<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>focus/20260901-20260930/part_0_0001.csv.gz</Name><Properties><Etag>"0x8DC1"</Etag></Properties></Blob></Blobs><NextMarker>m2</NextMarker></EnumerationResults>`)
				return
			}
			_, _ = fmt.Fprint(w, `<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>focus/20260901-20260930/manifest.json</Name><Properties><Etag>0x8DC2</Etag></Properties></Blob></Blobs><NextMarker/></EnumerationResults>`)
			return
		}
		if r.URL.EscapedPath() != "/exports/focus/20260901-20260930/part_0_0001.csv.gz" {
			http.Error(w, r.URL.EscapedPath(), http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, "data")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	auth := &Federated{TenantID: "tenant-1", ClientID: "app-1", TokenFile: tokenFile, Authority: srv.URL, Scope: StorageScope}
	b := Blob{Account: "keelbills", Container: "exports", Endpoint: srv.URL, Auth: auth}
	ctx := context.Background()
	objs, err := b.ListWithETag(ctx, "focus/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 2 || objs[0].ETag != "0x8DC1" || !strings.HasSuffix(objs[1].Key, "manifest.json") {
		t.Fatalf("%+v", objs)
	}
	raw, err := b.Get(ctx, objs[0].Key)
	if err != nil || string(raw) != "data" {
		t.Fatalf("%q %v", raw, err)
	}
	if tokens != 1 {
		t.Fatalf("token fetched %d times, want cached", tokens)
	}
	if _, err := (Blob{Container: "exports", Endpoint: srv.URL, Auth: &Federated{TenantID: "tenant-1", ClientID: "other", TokenFile: tokenFile, Authority: srv.URL, Scope: StorageScope}}).List(ctx, "focus/"); err == nil {
		t.Fatal("expected a token error")
	}
}

func TestFromEnvNeedsWorkloadIdentity(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	if _, err := FromEnv(StorageScope); err == nil {
		t.Fatal("expected an error without workload identity")
	}
}
