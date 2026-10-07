// Package discovery defines how Keel finds existing cloud accounts in a
// provider's organisation so operators can bring them into the Catalog (#26).
package discovery

import (
	"context"
	"strings"
)

// Account is a cloud account found in a provider organisation.
type Account struct {
	Provider   string            `json:"provider"`
	ExternalID string            `json:"external_id"`
	Name       string            `json:"name"`
	Parent     string            `json:"parent"` // org unit / department name
	Tags       map[string]string `json:"tags,omitempty"`
}

// Source lists accounts in one provider organisation.
type Source interface {
	Provider() string
	ListAccounts(ctx context.Context) ([]Account, error)
}

// Suggestion is a guessed Project/Environment from an account name.
type Suggestion struct {
	ProjectSlug string `json:"project_slug"`
	Environment string `json:"environment"`
}

var knownEnvs = map[string]bool{"dev": true, "develop": true, "test": true, "qa": true, "uat": true, "stg": true, "staging": true, "prod": true, "production": true, "sandbox": true}

// Suggest splits names like "tat-crm-prod" into project "tat-crm" and
// environment "prod". It returns nil when the last segment is not a known
// environment name.
func Suggest(name string) *Suggestion {
	n := strings.ToLower(strings.TrimSpace(name))
	i := strings.LastIndexAny(n, "-_")
	if i <= 0 || i == len(n)-1 {
		return nil
	}
	env := n[i+1:]
	if !knownEnvs[env] {
		return nil
	}
	return &Suggestion{ProjectSlug: strings.ReplaceAll(n[:i], "_", "-"), Environment: env}
}
