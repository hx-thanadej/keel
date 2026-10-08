package decisions

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/hx-thanadej/keel/internal/ghapi"
)

// GitHub implements Source (contents: read).
type GitHub struct {
	Client ghapi.Client
}

// List implements Source.
func (g GitHub) List(ctx context.Context, repo, dir string) ([]string, error) {
	var entries []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}
	err := g.Client.Do(ctx, http.MethodGet, "/repos/"+repo+"/contents/"+dir, nil, &entries)
	if ghapi.Status(err) == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type == "file" {
			out = append(out, e.Path)
		}
	}
	return out, nil
}

// Read implements Source.
func (g GitHub) Read(ctx context.Context, repo, path string) ([]byte, error) {
	var f struct {
		Content string `json:"content"`
	}
	if err := g.Client.Do(ctx, http.MethodGet, "/repos/"+repo+"/contents/"+path, nil, &f); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
}
