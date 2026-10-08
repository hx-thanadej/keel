package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestKeyFilesRefused(t *testing.T) {
	if err := checkKeyless([]byte(`{"type":"service_account","private_key":"x"}`)); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("service account key: %v", err)
	}
	for _, ok := range []string{`{"type":"external_account"}`, `{"type":"impersonated_service_account"}`, ``} {
		if err := checkKeyless([]byte(ok)); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
}
