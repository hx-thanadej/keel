package api

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/hx-thanadej/keel/internal/leaks"
)

// WebhookDeps serves GitHub webhooks (#136). Authentication is the HMAC
// signature, not a session.
type WebhookDeps struct {
	Leaks *leaks.Service
}

func mountWebhooks(mux Mux, d WebhookDeps) {
	mux.HandleFunc("POST /v1/webhooks/github", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody("unreadable body"))
			return
		}
		if err := d.Leaks.Verify(body, r.Header.Get("X-Hub-Signature-256")); err != nil {
			writeJSON(w, http.StatusUnauthorized, errBody("bad signature"))
			return
		}
		delivery, event := r.Header.Get("X-GitHub-Delivery"), r.Header.Get("X-GitHub-Event")
		if delivery == "" || event == "" {
			writeJSON(w, http.StatusBadRequest, errBody("missing delivery or event header"))
			return
		}
		err = d.Leaks.Receive(r.Context(), delivery, event, body)
		switch {
		case errors.Is(err, leaks.ErrReplay):
			writeJSON(w, http.StatusOK, map[string]string{"status": "duplicate"})
		case err != nil:
			slog.Error("github webhook", "delivery", delivery, "err", err)
			writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		default:
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
		}
	})
}
