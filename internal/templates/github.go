package templates

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/hx-thanadej/keel/internal/ghapi"
)

// GitHub implements Git. The token needs administration and contents write
// on the organisation's repositories, and organisation custom-property values.
type GitHub struct {
	Client ghapi.Client
}

var _ Git = GitHub{}

// Repo implements Git.
func (g GitHub) Repo(ctx context.Context, full string) (RepoInfo, bool, error) {
	var r struct {
		ID            int64  `json:"id"`
		DefaultBranch string `json:"default_branch"`
		Size          int    `json:"size"`
		Owner         struct {
			ID int64 `json:"id"`
		} `json:"owner"`
	}
	err := g.Client.Do(ctx, http.MethodGet, "/repos/"+full, nil, &r)
	if ghapi.Status(err) == http.StatusNotFound {
		return RepoInfo{}, false, nil
	}
	if err != nil {
		return RepoInfo{}, false, err
	}
	info := RepoInfo{ID: r.ID, OwnerID: r.Owner.ID, DefaultBranch: r.DefaultBranch}
	// A freshly generated repository has no commits for a few seconds.
	if _, err := g.Head(ctx, full, r.DefaultBranch); err != nil {
		if s := ghapi.Status(err); s == http.StatusNotFound || s == http.StatusConflict {
			info.Empty = true
			return info, true, nil
		}
		return RepoInfo{}, false, err
	}
	return info, true, nil
}

// Head implements Git.
func (g GitHub) Head(ctx context.Context, full, branch string) (string, error) {
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	err := g.Client.Do(ctx, http.MethodGet, "/repos/"+full+"/git/ref/heads/"+url.PathEscape(branch), nil, &ref)
	return ref.Object.SHA, err
}

// Generate implements Git: a private repository from a template repository.
func (g GitHub) Generate(ctx context.Context, template, owner, name, description string) error {
	return g.Client.Do(ctx, http.MethodPost, "/repos/"+template+"/generate", map[string]any{
		"owner": owner, "name": name, "description": description, "private": true, "include_all_branches": false}, nil)
}

// PutFile implements Git; it writes only when the content differs.
func (g GitHub) PutFile(ctx context.Context, full, branch, path, message string, content []byte) (bool, error) {
	var cur struct {
		SHA     string `json:"sha"`
		Content string `json:"content"`
	}
	err := g.Client.Do(ctx, http.MethodGet, "/repos/"+full+"/contents/"+path+"?ref="+url.QueryEscape(branch), nil, &cur)
	switch {
	case ghapi.Status(err) == http.StatusNotFound:
		cur.SHA = ""
	case err != nil:
		return false, err
	default:
		if have, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(cur.Content, "\n", "")); err == nil && bytes.Equal(have, content) {
			return false, nil
		}
	}
	body := map[string]any{"message": message, "content": base64.StdEncoding.EncodeToString(content), "branch": branch}
	if cur.SHA != "" {
		body["sha"] = cur.SHA
	}
	return true, g.Client.Do(ctx, http.MethodPut, "/repos/"+full+"/contents/"+path, body, nil)
}

// SetProperties implements Git.
func (g GitHub) SetProperties(ctx context.Context, org, repo string, props map[string]string) error {
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	var values []map[string]any
	for _, k := range names {
		values = append(values, map[string]any{"property_name": k, "value": props[k]})
	}
	return g.Client.Do(ctx, http.MethodPatch, "/orgs/"+url.PathEscape(org)+"/properties/values",
		map[string]any{"repository_names": []string{repo}, "properties": values}, nil)
}

// EnableSecretScanning implements Git.
func (g GitHub) EnableSecretScanning(ctx context.Context, full string) error {
	on := map[string]string{"status": "enabled"}
	return g.Client.Do(ctx, http.MethodPatch, "/repos/"+full,
		map[string]any{"security_and_analysis": map[string]any{"secret_scanning": on, "secret_scanning_push_protection": on}}, nil)
}

// GrantTeam implements Git.
func (g GitHub) GrantTeam(ctx context.Context, org, team, full, permission string) error {
	return g.Client.Do(ctx, http.MethodPut, "/orgs/"+url.PathEscape(org)+"/teams/"+url.PathEscape(team)+"/repos/"+full, map[string]string{"permission": permission}, nil)
}
