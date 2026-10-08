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
	"slices"
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
	_, err := c.do(ctx, method, path, in, out)
	return err
}

// DoList GETs one page of a list endpoint into out and returns the path of
// the next page from the Link header, or "" on the last page. GitHub pages
// some endpoints only by cursor, so callers follow next instead of
// counting pages. A next link outside BaseURL is an error, so the token is
// never sent to another host.
func (c Client) DoList(ctx context.Context, path string, out any) (next string, err error) {
	h, err := c.do(ctx, http.MethodGet, path, nil, out)
	if err != nil {
		return "", err
	}
	link, err := nextLink(h.Values("Link"))
	if err != nil {
		return "", fmt.Errorf("github %s: %w", path, err)
	}
	if link == "" {
		return "", nil
	}
	base := strings.TrimSuffix(c.base(), "/")
	if !strings.HasPrefix(link, base+"/") {
		return "", fmt.Errorf("github %s: next page %q is outside %s", path, link, base)
	}
	return strings.TrimPrefix(link, base), nil
}

// nextLink finds the target whose rel names "next" in Link headers (RFC
// 8288: `<https://...>; rel="next", <https://...>; rel="last"`). A header
// that does not parse is an error, not the last page: reading it as the end
// of the list would resolve the Findings on the pages never read.
func nextLink(headers []string) (string, error) {
	var next string
	for _, h := range headers {
		s := trimOWS(h)
		for s != "" {
			end := strings.IndexByte(s, '>')
			if s[0] != '<' || end < 0 {
				return "", fmt.Errorf("malformed Link header %q", h)
			}
			target := s[1:end]
			s = trimOWS(s[end+1:])
			for s != "" && s[0] == ';' {
				var name, value string
				var ok bool
				name, value, s, ok = linkParam(trimOWS(s[1:]))
				if !ok {
					return "", fmt.Errorf("malformed Link header %q", h)
				}
				if !strings.EqualFold(name, "rel") || !slices.Contains(strings.Fields(strings.ToLower(value)), "next") {
					continue
				}
				if next != "" && next != target {
					return "", fmt.Errorf("two next pages in Link header %q", h)
				}
				next = target
			}
			if s == "" {
				break
			}
			if s[0] != ',' {
				return "", fmt.Errorf("malformed Link header %q", h)
			}
			s = trimOWS(s[1:])
		}
	}
	return next, nil
}

// linkParam reads `name`, `name=token` or `name="quoted"` and returns the
// rest of s after it.
func linkParam(s string) (name, value, rest string, ok bool) {
	i := strings.IndexAny(s, "=;, \t")
	if i < 0 {
		i = len(s)
	}
	name, s = s[:i], trimOWS(s[i:])
	if name == "" {
		return "", "", "", false
	}
	if s == "" || s[0] != '=' {
		return name, "", s, true
	}
	s = trimOWS(s[1:])
	if s != "" && s[0] == '"' {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
				if i < len(s) {
					b.WriteByte(s[i])
				}
			case '"':
				return name, b.String(), trimOWS(s[i+1:]), true
			default:
				b.WriteByte(s[i])
			}
		}
		return "", "", "", false
	}
	i = strings.IndexAny(s, ";, \t")
	if i < 0 {
		i = len(s)
	}
	if i == 0 {
		return "", "", "", false
	}
	return name, s[:i], trimOWS(s[i:]), true
}

func trimOWS(s string) string { return strings.Trim(s, " \t") }

func (c Client) base() string {
	if c.BaseURL == "" {
		return "https://api.github.com"
	}
	return c.BaseURL
}

func (c Client) do(ctx context.Context, method, path string, in, out any) (http.Header, error) {
	base := c.base()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, body)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if res.StatusCode >= 300 {
		return nil, &Error{Method: method, Path: path, Status: res.StatusCode, Body: string(raw)}
	}
	if out != nil && len(raw) > 0 {
		return res.Header, json.Unmarshal(raw, out)
	}
	return res.Header, nil
}
