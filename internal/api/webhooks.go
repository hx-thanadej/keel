package api

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/hx-thanadej/keel/internal/githubgov"
	"github.com/hx-thanadej/keel/internal/leaks"
)

// WebhookDeps serves the GitHub organisation webhook: secret-scanning alerts
// (#136) and, when Governance is set, governance events (#193).
// Authentication is the HMAC signature, not a session.
type WebhookDeps struct {
	Leaks      *leaks.Service
	Governance *githubgov.Receiver
}

// maxWebhookBody caps a delivery; governance and alert payloads are a few KiB.
const maxWebhookBody = 1 << 20

func mountWebhooks(mux Mux, d WebhookDeps) {
	mux.HandleFunc("POST /v1/webhooks/github", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody("unreadable body"))
			return
		}
		if len(body) > maxWebhookBody {
			writeJSON(w, http.StatusRequestEntityTooLarge, errBody("body too large"))
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
		if d.Governance != nil && githubgov.Governs(event) {
			err = d.Governance.Receive(r.Context(), delivery, event, body)
		} else {
			err = d.Leaks.Receive(r.Context(), delivery, event, body)
		}
		switch {
		case errors.Is(err, leaks.ErrReplay), errors.Is(err, githubgov.ErrReplay):
			writeJSON(w, http.StatusOK, map[string]string{"status": "duplicate"})
		case errors.Is(err, githubgov.ErrForeignOrg):
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored"})
		case err != nil:
			slog.Error("github webhook", "delivery", delivery, "event", event, "err", err)
			writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		default:
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
		}
	})
}
