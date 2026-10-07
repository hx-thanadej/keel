// Package pipelineauth authenticates CI pipelines by their GitHub Actions
// OIDC token (ADR-0007): no stored secret. The token's immutable
// repository_id maps to the Service(s) in the Catalog, and the principal may
// act only on those Services.
package pipelineauth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/ciidentity"
	"github.com/hx-thanadej/keel/internal/store"
)

// Claims are the GitHub Actions token claims Keel uses.
type Claims struct {
	Subject           string `json:"sub"`
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	Ref               string `json:"ref"`
	RefProtected      string `json:"ref_protected"`
	SHA               string `json:"sha"`
	Workflow          string `json:"workflow_ref"`
	JobWorkflow       string `json:"job_workflow_ref"`
	Event             string `json:"event_name"`
	RunID             string `json:"run_id"`
	Environment       string `json:"environment"`
}

// Authenticator accepts GitHub Actions tokens and passes everything else on.
type Authenticator struct {
	Store    *store.Store
	Issuer   string // default GitHub's
	Audience string // the audience pipelines request, e.g. "keel"
	Next     auth.Authenticator

	once     sync.Once
	verifier *oidc.IDTokenVerifier
	initErr  error
}

func (a *Authenticator) issuer() string {
	if a.Issuer == "" {
		return ciidentity.GitHubIssuer
	}
	return a.Issuer
}

// Authenticate implements auth.Authenticator.
func (a *Authenticator) Authenticate(r *http.Request) (auth.Principal, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || issuerOf(strings.TrimPrefix(h, "Bearer ")) != a.issuer() {
		if a.Next == nil {
			return auth.Principal{}, auth.ErrUnauthenticated
		}
		return a.Next.Authenticate(r)
	}
	c, err := a.verify(r.Context(), strings.TrimPrefix(h, "Bearer "))
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	return a.principal(r.Context(), c)
}

func (a *Authenticator) verify(ctx context.Context, raw string) (Claims, error) {
	a.once.Do(func() {
		p, err := oidc.NewProvider(ctx, a.issuer())
		if err != nil {
			a.initErr = err
			return
		}
		a.verifier = p.Verifier(&oidc.Config{ClientID: a.Audience})
	})
	if a.initErr != nil {
		a.once = sync.Once{} // retry discovery next time
		return Claims{}, a.initErr
	}
	tok, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	err = tok.Claims(&c)
	return c, err
}

// ErrUnknownRepository: the repository is not a Service in the Catalog.
var ErrUnknownRepository = errors.New("repository is not registered as a Service")

func (a *Authenticator) principal(ctx context.Context, c Claims) (auth.Principal, error) {
	repo, err := strconv.ParseInt(c.RepositoryID, 10, 64)
	if err != nil || repo == 0 {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	rows, err := a.Store.AppPool().Query(ctx, `SELECT tenant_id::text, service_id::text FROM services_by_repository($1)`, repo)
	if err != nil {
		return auth.Principal{}, err
	}
	defer rows.Close()
	p := auth.Principal{Kind: auth.KindPipeline, Issuer: a.issuer(), Bindings: []auth.Binding{},
		Subject: "pipeline:github:" + c.Repository + "@" + c.Ref + "#" + c.RunID,
		Pipeline: &auth.Pipeline{Repository: c.Repository, RepositoryID: c.RepositoryID, Ref: c.Ref, RefProtected: c.RefProtected == "true",
			SHA: c.SHA, Workflow: c.Workflow, JobWorkflow: c.JobWorkflow, Event: c.Event, RunID: c.RunID, Environment: c.Environment}}
	for rows.Next() {
		var tenant, service string
		if err := rows.Scan(&tenant, &service); err != nil {
			return auth.Principal{}, err
		}
		if p.TenantID != "" && p.TenantID != tenant {
			return auth.Principal{}, auth.ErrUnauthenticated // one repository, one Tenant
		}
		p.TenantID = tenant
		p.ServiceIDs = append(p.ServiceIDs, service)
	}
	if err := rows.Err(); err != nil {
		return auth.Principal{}, err
	}
	if p.TenantID == "" {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	return p, nil
}

func issuerOf(raw string) string {
	iss, _ := unverifiedIssuer(raw)
	return iss
}
