package promotion

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ArgoCD reads applications from an Argo CD API server with a read-only
// account token. Keel never holds cluster credentials; Argo CD pulls.
type ArgoCD struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// App implements Argo.
func (a ArgoCD) App(ctx context.Context, name string) (AppStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(a.BaseURL, "/")+"/api/v1/applications/"+url.PathEscape(name), nil)
	if err != nil {
		return AppStatus{}, err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	c := a.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := c.Do(req)
	if err != nil {
		return AppStatus{}, err
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode != http.StatusOK {
		return AppStatus{}, fmt.Errorf("argo cd %s: HTTP %d: %.200s", name, res.StatusCode, body)
	}
	var app struct {
		Status struct {
			Sync struct {
				Status string `json:"status"`
			} `json:"sync"`
			Health struct {
				Status string `json:"status"`
			} `json:"health"`
			Summary struct {
				Images []string `json:"images"`
			} `json:"summary"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &app); err != nil {
		return AppStatus{}, err
	}
	return AppStatus{Sync: app.Status.Sync.Status, Health: app.Status.Health.Status, Images: app.Status.Summary.Images}, nil
}
