package leaks

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hx-thanadej/keel/internal/ghapi"
)

// GitHubAlerts reads secret-scanning alerts (token needs "secret scanning
// alerts: read").
type GitHubAlerts struct {
	Client ghapi.Client
}

// Secret implements Alerts.
func (g GitHubAlerts) Secret(ctx context.Context, repo string, number int) (string, string, error) {
	var a struct {
		SecretType string `json:"secret_type"`
		Secret     string `json:"secret"`
	}
	err := g.Client.Do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/secret-scanning/alerts/%d", repo, number), nil, &a)
	return a.SecretType, a.Secret, err
}
