// Package ghapi is a minimal GitHub REST client shared by Keel's GitHub
// integrations.
package ghapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client calls the GitHub REST API with one token.
type Client struct {
	BaseURL string // default https://api.github.com
	Token   string
	HTTP    *http.Client
}

// Error is a non-2xx response.
type Error struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *Error) Error() string {
	return fmt.Sprintf("github %s %s: HTTP %d: %.300s", e.Method, e.Path, e.Status, e.Body)
}

// Status returns the HTTP status of a GitHub error, or 0.
func Status(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// Do sends in as JSON (if not nil) and decodes the response into out (if not nil).
func (c Client) Do(ctx context.Context, method, path string, in, out any) error {
	base := c.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	h := c.HTTP
	if h == nil {
		h = http.DefaultClient
	}
	res, err := h.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if res.StatusCode >= 300 {
		return &Error{Method: method, Path: path, Status: res.StatusCode, Body: string(raw)}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}
