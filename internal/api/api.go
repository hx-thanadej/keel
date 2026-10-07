// Package api is Keel's HTTP surface.
package api

import (
	"encoding/json"
	"net/http"
)

// Info is build metadata exposed on /healthz.
type Info struct {
	Version string
}

// NewRouter returns the Keel API handler.
func NewRouter(info Info) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": info.Version})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
