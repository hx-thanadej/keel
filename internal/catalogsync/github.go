package catalogsync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// GitHub reads repositories of one user or organisation over the REST API.
// Token needs read-only "contents" and "metadata" (a GitHub App installation
// token or a fine-grained token).
type GitHub struct {
	BaseURL string // default https://api.github.com
	Owner   string
	Org     bool // Owner is an organisation (else a user)
	Token   string
	Client  *http.Client
}

func (g *GitHub) get(ctx context.Context, path string, v any) (int, error) {
	base := g.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	c := g.Client
	if c == nil {
		c = http.DefaultClient
	}
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return res.StatusCode, nil
	}
	return res.StatusCode, json.NewDecoder(res.Body).Decode(v)
}

// ListRepos implements Source.
func (g *GitHub) ListRepos(ctx context.Context) ([]Repo, error) {
	kind := "users"
	if g.Org {
		kind = "orgs"
	}
	var all []Repo
	for page := 1; ; page++ {
		var repos []Repo
		st, err := g.get(ctx, fmt.Sprintf("/%s/%s/repos?per_page=100&page=%d", kind, url.PathEscape(g.Owner), page), &repos)
		if err != nil {
			return nil, err
		}
		if st != http.StatusOK {
			return nil, fmt.Errorf("list repos: HTTP %d", st)
		}
		all = append(all, repos...)
		if len(repos) < 100 {
			return all, nil
		}
	}
}

// ReadFile implements Source.
func (g *GitHub) ReadFile(ctx context.Context, r Repo, path string) ([]byte, bool, error) {
	var f struct {
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	st, err := g.get(ctx, "/repos/"+r.FullName+"/contents/"+url.PathEscape(path), &f)
	if err != nil {
		return nil, false, err
	}
	switch st {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("HTTP %d", st)
	}
	if f.Encoding != "base64" {
		return nil, false, fmt.Errorf("unexpected encoding %q", f.Encoding)
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
	return b, true, err
}
