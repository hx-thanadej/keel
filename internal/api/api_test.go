package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
)

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(api.NewRouter(api.Info{Version: "test"}))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var body struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" || body.Version != "test" {
		t.Fatalf("body = %+v, want status ok, version test", body)
	}
}

func TestUnknownRouteIs404(t *testing.T) {
	srv := httptest.NewServer(api.NewRouter(api.Info{Version: "test"}))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
}
