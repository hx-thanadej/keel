package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestGCSListAndGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /storage/v1/b/keel-bills/o", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("pageToken") == "" {
			_, _ = fmt.Fprint(w, `{"items":[{"name":"focus/2026-09/000000000000.csv.gz","generation":"17"}],"nextPageToken":"p2"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"items":[{"name":"focus/2026-09/000000000001.csv.gz","generation":"18"}]}`)
	})
	mux.HandleFunc("GET /storage/v1/b/keel-bills/o/{object}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("alt") != "media" || r.PathValue("object") != "focus/2026-09/000000000000.csv.gz" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, "data")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	g := GCS{Bucket: "keel-bills", Endpoint: srv.URL, Tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at-1", TokenType: "Bearer"})}
	objs, err := g.ListWithETag(context.Background(), "focus/")
	if err != nil || len(objs) != 2 || objs[1].ETag != "18" {
		t.Fatalf("%+v %v", objs, err)
	}
	raw, err := g.Get(context.Background(), objs[0].Key)
	if err != nil || string(raw) != "data" {
		t.Fatalf("%q %v", raw, err)
	}
}

func TestOnlyKeylessCredentialsAccepted(t *testing.T) {
	for _, ok := range []string{
		``,
		`{"type":"external_account","audience":"//iam.googleapis.com/x"}`,
		`{"type":"impersonated_service_account","source_credentials":{"type":"external_account"}}`,
		`{"type":"impersonated_service_account","source_credentials":{"type":"impersonated_service_account","source_credentials":{"type":"external_account"}}}`,
	} {
		if err := checkKeyless([]byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{"type":"service_account","private_key":"SECRET-KEY"}`,
		`{"type":"authorized_user","refresh_token":"SECRET-KEY","client_secret":"SECRET-KEY"}`,
		`{"type":"impersonated_service_account","source_credentials":{"type":"service_account","private_key":"SECRET-KEY"}}`,
		`{"type":"impersonated_service_account","source_credentials":{"type":"authorized_user","refresh_token":"SECRET-KEY"}}`,
		`{"type":"impersonated_service_account"}`,
		`{"type":"gdch_service_account","private_key":"SECRET-KEY"}`,
	} {
		err := checkKeyless([]byte(bad))
		if !errors.Is(err, ErrKeyFile) {
			t.Errorf("%s: got %v, want ErrKeyFile", bad, err)
			continue
		}
		if strings.Contains(err.Error(), "SECRET-KEY") {
			t.Errorf("error leaks credential content: %v", err)
		}
	}
}

func TestGCSErrorOmitsRawBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":{"code":403,"message":"caller lacks storage.objects.list","errors":[{"debug":"Bearer at-SECRET"}]}}`)
	}))
	t.Cleanup(srv.Close)
	g := GCS{Bucket: "b", Endpoint: srv.URL, Tokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "at-SECRET"})}
	_, err := g.ListWithETag(context.Background(), "")
	if err == nil || strings.Contains(err.Error(), "at-SECRET") || !strings.Contains(err.Error(), "caller lacks storage.objects.list") {
		t.Fatalf("error %v: want the message field only", err)
	}
}
