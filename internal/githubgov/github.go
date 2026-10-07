package githubgov

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/hx-thanadej/keel/internal/ghapi"
)

// Repo is what governance needs to know about a repository.
type Repo struct {
	Name           string
	Private        bool
	Archived       bool
	Properties     map[string]string
	SecretScanning bool
	PushProtection bool
}

// API is the GitHub surface the reconciler uses.
type API interface {
	Owner() (name string, org bool)
	Plan(ctx context.Context) (string, error)
	PropertySchema(ctx context.Context) ([]Property, error)
	PutPropertySchema(ctx context.Context, ps []Property) error
	SubClaimKeys(ctx context.Context) ([]string, error)
	PutSubClaimKeys(ctx context.Context, keys []string) error
	OrgRulesets(ctx context.Context) ([]Ruleset, error)
	PutOrgRuleset(ctx context.Context, r Ruleset) error // create when r.ID == 0
	Repos(ctx context.Context) ([]Repo, error)
	RepoRulesets(ctx context.Context, repo string) ([]Ruleset, error)
	PutRepoRuleset(ctx context.Context, repo string, r Ruleset) error
	EnableSecretScanning(ctx context.Context, repo string) error
	Actions(ctx context.Context) (ActionsSettings, error)
	PutActions(ctx context.Context, a ActionsSettings) error
}

// ActionsSettings is what GitHub reports for the organisation.
type ActionsSettings struct {
	AllowedActions         string // all | local_only | selected
	SHAPinningRequired     bool
	GitHubOwnedAllowed     bool
	VerifiedAllowed        bool
	Patterns               []string
	DefaultPermissions     string // read | write
	CanApprovePullRequests bool
	ForkApproval           string
}

// GitHub implements API over REST. The token needs organisation
// administration (rulesets, custom properties, OIDC) and repository
// administration (security settings).
type GitHub struct {
	Client ghapi.Client
	Login  string
	Org    bool
}

var _ API = GitHub{}

// Owner implements API.
func (g GitHub) Owner() (string, bool) { return g.Login, g.Org }

func (g GitHub) owner() string { return url.PathEscape(g.Login) }

// Plan implements API: the organisation's plan name, or "user".
func (g GitHub) Plan(ctx context.Context) (string, error) {
	if !g.Org {
		return "user", nil
	}
	var o struct {
		Plan *struct {
			Name string `json:"name"`
		} `json:"plan"`
	}
	if err := g.Client.Do(ctx, http.MethodGet, "/orgs/"+g.owner(), nil, &o); err != nil {
		return "", err
	}
	if o.Plan == nil {
		return "unknown", nil // plan is visible only to organisation owners
	}
	return o.Plan.Name, nil
}

// PropertySchema implements API.
func (g GitHub) PropertySchema(ctx context.Context) ([]Property, error) {
	var out []Property
	err := g.Client.Do(ctx, http.MethodGet, "/orgs/"+g.owner()+"/properties/schema", nil, &out)
	return out, err
}

// PutPropertySchema implements API (creates or updates the listed properties).
func (g GitHub) PutPropertySchema(ctx context.Context, ps []Property) error {
	return g.Client.Do(ctx, http.MethodPatch, "/orgs/"+g.owner()+"/properties/schema", map[string]any{"properties": ps}, nil)
}

// SubClaimKeys implements API.
func (g GitHub) SubClaimKeys(ctx context.Context) ([]string, error) {
	var out struct {
		Keys []string `json:"include_claim_keys"`
	}
	err := g.Client.Do(ctx, http.MethodGet, "/orgs/"+g.owner()+"/actions/oidc/customization/sub", nil, &out)
	return out.Keys, err
}

// PutSubClaimKeys implements API.
func (g GitHub) PutSubClaimKeys(ctx context.Context, keys []string) error {
	return g.Client.Do(ctx, http.MethodPut, "/orgs/"+g.owner()+"/actions/oidc/customization/sub", map[string]any{"include_claim_keys": keys}, nil)
}

func (g GitHub) rulesets(ctx context.Context, base string) ([]Ruleset, error) {
	var list []struct {
		ID int64 `json:"id"`
	}
	if err := g.Client.Do(ctx, http.MethodGet, base+"?per_page=100", nil, &list); err != nil {
		return nil, err
	}
	var out []Ruleset
	for _, r := range list {
		var full Ruleset
		if err := g.Client.Do(ctx, http.MethodGet, fmt.Sprintf("%s/%d", base, r.ID), nil, &full); err != nil {
			return nil, err
		}
		out = append(out, full)
	}
	return out, nil
}

func (g GitHub) putRuleset(ctx context.Context, base string, r Ruleset) error {
	id := r.ID
	r.ID = 0
	if id == 0 {
		return g.Client.Do(ctx, http.MethodPost, base, r, nil)
	}
	return g.Client.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%d", base, id), r, nil)
}

// OrgRulesets implements API.
func (g GitHub) OrgRulesets(ctx context.Context) ([]Ruleset, error) {
	return g.rulesets(ctx, "/orgs/"+g.owner()+"/rulesets")
}

// PutOrgRuleset implements API.
func (g GitHub) PutOrgRuleset(ctx context.Context, r Ruleset) error {
	return g.putRuleset(ctx, "/orgs/"+g.owner()+"/rulesets", r)
}

// RepoRulesets implements API (rulesets defined on the repository itself).
func (g GitHub) RepoRulesets(ctx context.Context, repo string) ([]Ruleset, error) {
	return g.rulesets(ctx, "/repos/"+g.owner()+"/"+url.PathEscape(repo)+"/rulesets")
}

// PutRepoRuleset implements API.
func (g GitHub) PutRepoRuleset(ctx context.Context, repo string, r Ruleset) error {
	return g.putRuleset(ctx, "/repos/"+g.owner()+"/"+url.PathEscape(repo)+"/rulesets", r)
}

// Repos implements API.
func (g GitHub) Repos(ctx context.Context) ([]Repo, error) {
	kind := "users"
	if g.Org {
		kind = "orgs"
	}
	type status struct {
		Status string `json:"status"`
	}
	var out []Repo
	for page := 1; ; page++ {
		var repos []struct {
			Name     string `json:"name"`
			Private  bool   `json:"private"`
			Archived bool   `json:"archived"`
			Security *struct {
				SecretScanning *status `json:"secret_scanning"`
				PushProtection *status `json:"secret_scanning_push_protection"`
			} `json:"security_and_analysis"`
		}
		if err := g.Client.Do(ctx, http.MethodGet, fmt.Sprintf("/%s/%s/repos?per_page=100&page=%d", kind, g.owner(), page), nil, &repos); err != nil {
			return nil, err
		}
		for _, r := range repos {
			x := Repo{Name: r.Name, Private: r.Private, Archived: r.Archived, Properties: map[string]string{}}
			if r.Security != nil {
				x.SecretScanning = r.Security.SecretScanning != nil && r.Security.SecretScanning.Status == "enabled"
				x.PushProtection = r.Security.PushProtection != nil && r.Security.PushProtection.Status == "enabled"
			}
			out = append(out, x)
		}
		if len(repos) < 100 {
			break
		}
	}
	if !g.Org {
		return out, nil
	}
	byName := map[string]*Repo{}
	for i := range out {
		byName[out[i].Name] = &out[i]
	}
	for page := 1; ; page++ {
		var vals []struct {
			Name  string `json:"repository_name"`
			Props []struct {
				Name  string `json:"property_name"`
				Value any    `json:"value"`
			} `json:"properties"`
		}
		if err := g.Client.Do(ctx, http.MethodGet, fmt.Sprintf("/orgs/%s/properties/values?per_page=100&page=%d", g.owner(), page), nil, &vals); err != nil {
			return nil, err
		}
		for _, v := range vals {
			if r := byName[v.Name]; r != nil {
				for _, p := range v.Props {
					if s, ok := p.Value.(string); ok {
						r.Properties[p.Name] = s
					}
				}
			}
		}
		if len(vals) < 100 {
			break
		}
	}
	return out, nil
}

// EnableSecretScanning implements API.
func (g GitHub) EnableSecretScanning(ctx context.Context, repo string) error {
	on := map[string]string{"status": "enabled"}
	return g.Client.Do(ctx, http.MethodPatch, "/repos/"+g.owner()+"/"+url.PathEscape(repo),
		map[string]any{"security_and_analysis": map[string]any{"secret_scanning": on, "secret_scanning_push_protection": on}}, nil)
}

// Actions implements API.
func (g GitHub) Actions(ctx context.Context) (ActionsSettings, error) {
	base := "/orgs/" + g.owner() + "/actions/permissions"
	var perms struct {
		AllowedActions     string `json:"allowed_actions"`
		SHAPinningRequired bool   `json:"sha_pinning_required"`
	}
	if err := g.Client.Do(ctx, http.MethodGet, base, nil, &perms); err != nil {
		return ActionsSettings{}, err
	}
	out := ActionsSettings{AllowedActions: perms.AllowedActions, SHAPinningRequired: perms.SHAPinningRequired}
	if perms.AllowedActions == "selected" {
		var sel struct {
			GitHubOwned bool     `json:"github_owned_allowed"`
			Verified    bool     `json:"verified_allowed"`
			Patterns    []string `json:"patterns_allowed"`
		}
		if err := g.Client.Do(ctx, http.MethodGet, base+"/selected-actions", nil, &sel); err != nil {
			return out, err
		}
		out.GitHubOwnedAllowed, out.VerifiedAllowed, out.Patterns = sel.GitHubOwned, sel.Verified, sel.Patterns
	}
	var wf struct {
		Default    string `json:"default_workflow_permissions"`
		CanApprove bool   `json:"can_approve_pull_request_reviews"`
	}
	if err := g.Client.Do(ctx, http.MethodGet, base+"/workflow", nil, &wf); err != nil {
		return out, err
	}
	out.DefaultPermissions, out.CanApprovePullRequests = wf.Default, wf.CanApprove
	var fork struct {
		Policy string `json:"approval_policy"`
	}
	if err := g.Client.Do(ctx, http.MethodGet, base+"/fork-pr-contributor-approval", nil, &fork); err != nil {
		return out, err
	}
	out.ForkApproval = fork.Policy
	return out, nil
}

// PutActions implements API.
func (g GitHub) PutActions(ctx context.Context, a ActionsSettings) error {
	base := "/orgs/" + g.owner() + "/actions/permissions"
	if err := g.Client.Do(ctx, http.MethodPut, base, map[string]any{"enabled_repositories": "all", "allowed_actions": a.AllowedActions, "sha_pinning_required": a.SHAPinningRequired}, nil); err != nil {
		return err
	}
	if a.AllowedActions == "selected" {
		patterns := a.Patterns
		if patterns == nil {
			patterns = []string{}
		}
		if err := g.Client.Do(ctx, http.MethodPut, base+"/selected-actions", map[string]any{"github_owned_allowed": a.GitHubOwnedAllowed, "verified_allowed": a.VerifiedAllowed, "patterns_allowed": patterns}, nil); err != nil {
			return err
		}
	}
	if err := g.Client.Do(ctx, http.MethodPut, base+"/workflow", map[string]any{"default_workflow_permissions": a.DefaultPermissions, "can_approve_pull_request_reviews": a.CanApprovePullRequests}, nil); err != nil {
		return err
	}
	return g.Client.Do(ctx, http.MethodPut, base+"/fork-pr-contributor-approval", map[string]any{"approval_policy": a.ForkApproval}, nil)
}
