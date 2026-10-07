package apply

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHub is the write side Keel needs: read a tree and files, create a
// branch, commit a file, open and inspect pull requests. The token needs
// contents:write and pull_requests:write on the Service repositories.
type GitHub struct {
	BaseURL string // default https://api.github.com
	Token   string
	Client  *http.Client
}

func (g GitHub) do(ctx context.Context, method, path string, in, out any) error {
	base := g.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, body)
	if err != nil {
		return err
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
		return err
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if res.StatusCode >= 300 {
		return fmt.Errorf("github %s %s: HTTP %d: %.300s", method, path, res.StatusCode, raw)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Repo is "owner/name" parsed from a repository URL.
func Repo(repoURL string) (string, error) {
	u, err := url.Parse(repoURL)
	if err != nil || u.Host != "github.com" {
		return "", fmt.Errorf("not a github.com repository: %q", repoURL)
	}
	parts := strings.Split(strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/"), "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("not a repository URL: %q", repoURL)
	}
	return parts[0] + "/" + parts[1], nil
}

// DefaultBranch returns the repository's default branch.
func (g GitHub) DefaultBranch(ctx context.Context, repo string) (string, error) {
	return g.defaultBranch(ctx, repo)
}

func (g GitHub) defaultBranch(ctx context.Context, repo string) (string, error) {
	var r struct {
		DefaultBranch string `json:"default_branch"`
	}
	err := g.do(ctx, http.MethodGet, "/repos/"+repo, nil, &r)
	return r.DefaultBranch, err
}

// YAMLFiles lists .yaml/.yml paths on a branch.
func (g GitHub) YAMLFiles(ctx context.Context, repo, branch string) ([]string, error) {
	var t struct {
		Tree []struct{ Path, Type string } `json:"tree"`
	}
	if err := g.do(ctx, http.MethodGet, "/repos/"+repo+"/git/trees/"+url.PathEscape(branch)+"?recursive=1", nil, &t); err != nil {
		return nil, err
	}
	var out []string
	for _, e := range t.Tree {
		if e.Type == "blob" && (strings.HasSuffix(e.Path, ".yaml") || strings.HasSuffix(e.Path, ".yml")) {
			out = append(out, e.Path)
		}
	}
	return out, nil
}

// File returns a file's content and blob sha.
func (g GitHub) File(ctx context.Context, repo, path, ref string) ([]byte, string, error) {
	var f struct{ Content, Encoding, SHA string }
	if err := g.do(ctx, http.MethodGet, "/repos/"+repo+"/contents/"+path+"?ref="+url.QueryEscape(ref), nil, &f); err != nil {
		return nil, "", err
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
	return b, f.SHA, err
}

// Branch creates branch from base.
func (g GitHub) Branch(ctx context.Context, repo, base, branch string) error {
	var ref struct {
		Object struct{ SHA string } `json:"object"`
	}
	if err := g.do(ctx, http.MethodGet, "/repos/"+repo+"/git/ref/heads/"+url.PathEscape(base), nil, &ref); err != nil {
		return err
	}
	return g.do(ctx, http.MethodPost, "/repos/"+repo+"/git/refs", map[string]string{"ref": "refs/heads/" + branch, "sha": ref.Object.SHA}, nil)
}

// Commit writes one file on a branch.
// An empty sha creates the file.
func (g GitHub) Commit(ctx context.Context, repo, branch, path, sha, message string, content []byte) error {
	body := map[string]string{"message": message, "content": base64.StdEncoding.EncodeToString(content), "branch": branch}
	if sha != "" {
		body["sha"] = sha
	}
	return g.do(ctx, http.MethodPut, "/repos/"+repo+"/contents/"+path, body, nil)
}

// PullRequest is the part of a PR Keel tracks.
type PullRequest struct {
	Number   int        `json:"number"`
	HTMLURL  string     `json:"html_url"`
	State    string     `json:"state"`
	Merged   bool       `json:"merged"`
	MergedAt *time.Time `json:"merged_at"`
}

// OpenPR opens a pull request.
func (g GitHub) OpenPR(ctx context.Context, repo, head, base, title, body string) (PullRequest, error) {
	var pr PullRequest
	err := g.do(ctx, http.MethodPost, "/repos/"+repo+"/pulls", map[string]string{"title": title, "head": head, "base": base, "body": body}, &pr)
	return pr, err
}

// PR reads a pull request by its HTML URL.
func (g GitHub) PR(ctx context.Context, htmlURL string) (PullRequest, error) {
	u, err := url.Parse(htmlURL)
	if err != nil {
		return PullRequest{}, err
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/") // owner/repo/pull/N
	if len(parts) != 4 || parts[2] != "pull" {
		return PullRequest{}, fmt.Errorf("not a pull request URL: %q", htmlURL)
	}
	var pr PullRequest
	err = g.do(ctx, http.MethodGet, "/repos/"+parts[0]+"/"+parts[1]+"/pulls/"+parts[3], nil, &pr)
	return pr, err
}
