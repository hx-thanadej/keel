package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/oidcauth/oidctest"
	"github.com/hx-thanadej/keel/internal/pipelineauth"
	"github.com/hx-thanadej/keel/internal/promotion"
	"github.com/hx-thanadej/keel/internal/scans"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type fakeBroker struct{}

func (fakeBroker) TempToken(context.Context) (string, string, time.Time, error) {
	return "tcr$keel", "t0k3n", time.Now().Add(time.Hour), nil
}

func TestPipelinesUploadScansAndReleasesForTheirOwnServiceOnly(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	var svc, other string
	if err := s.InTenant(t.Context(), tat, func(tx pgx.Tx) error {
		var team, project string
		if err := tx.QueryRow(t.Context(), `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tat).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(t.Context(), `INSERT INTO projects (tenant_id, team_id, slug, name, registry_namespace) VALUES ($1, $2, 'tat-crm', 'TAT CRM', 'tat-tat-crm') RETURNING id`, tat, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(t.Context(), `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository_id, repository_owner_id) VALUES ($1, $2, $3, 'crm-api', 'CRM API', 900, 42) RETURNING id`, tat, project, team).Scan(&svc); err != nil {
			return err
		}
		return tx.QueryRow(t.Context(), `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository_id, repository_owner_id) VALUES ($1, $2, $3, 'crm-web', 'CRM Web', 901, 42) RETURNING id`, tat, project, team).Scan(&other)
	}); err != nil {
		t.Fatal(err)
	}
	gh := oidctest.New(t, "keel", "")
	authn := &pipelineauth.Authenticator{Store: s, Issuer: gh.URL, Audience: "keel"}
	promo, _ := promotion.New(promotion.Service{Store: s})
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: authn, Catalog: catalog.New(s, az),
		Scans: &api.ScanDeps{Authz: az, Service: scans.Service{Store: s}}, Promotion: &api.PromotionDeps{Authz: az, Service: promo},
		Registry: &api.RegistryDeps{Authz: az, Store: s, Broker: fakeBroker{}, Domain: "acme.tencentcloudcr.com"}}))
	t.Cleanup(srv.Close)
	token := func(repoID string) string {
		return gh.Mint(t, map[string]any{"sub": "repository_owner_id:42:repository_id:" + repoID + ":environment:prod", "repository": "acme/crm-api", "repository_id": repoID,
			"ref": "refs/heads/main", "ref_protected": "true", "sha": "c0ffee", "workflow_ref": "acme/crm-api/.github/workflows/keel.yml@refs/heads/main", "event_name": "push", "run_id": "77"})
	}
	post := func(tok, path, ctype string, body []byte) (int, string) {
		req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", ctype)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	sarif := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[{"ruleId":"go.sql-injection","level":"error","message":{"text":"SQL built from input"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.go"},"region":{"startLine":12}}}]}]}]}`)

	st, body := post(token("900"), "/v1/tenants/"+tat+"/services/"+svc+"/scans?scope=full&commit=forged", "application/sarif+json", sarif)
	if st != 201 || !strings.Contains(body, `"commit_sha":"c0ffee"`) || !strings.Contains(body, `"raised":1`) {
		t.Fatalf("upload %d %s", st, body)
	}
	if st, body := post(token("900"), "/v1/tenants/"+tat+"/services/"+other+"/scans?scope=full", "application/sarif+json", sarif); st != 403 {
		t.Fatalf("other service %d %s", st, body)
	}
	if st, _ := post(token("555"), "/v1/tenants/"+tat+"/services/"+svc+"/scans?scope=full", "application/sarif+json", sarif); st != 401 {
		t.Fatalf("unknown repository %d", st)
	}
	// Push credentials come from Keel, for the Project's namespace only.
	if st, body := post(token("900"), "/v1/tenants/"+tat+"/services/"+svc+"/registry-token", "application/json", nil); st != 201 || !strings.Contains(body, `"namespace":"tat-tat-crm"`) || !strings.Contains(body, `"password":"t0k3n"`) {
		t.Fatalf("registry token %d %s", st, body)
	}
	outside, _ := json.Marshal(map[string]any{"version": "0.9.0", "images": []map[string]string{{"name": "acme.tencentcloudcr.com/other-ns/crm-api", "digest": "sha256:" + strings.Repeat("d", 64)}}})
	if st, body := post(token("900"), "/v1/tenants/"+tat+"/services/"+svc+"/releases", "application/json", outside); st != 400 {
		t.Fatalf("release outside namespace %d %s", st, body)
	}
	rel, _ := json.Marshal(map[string]any{"version": "1.0.0", "images": []map[string]string{{"name": "acme.tencentcloudcr.com/tat-tat-crm/crm-api", "digest": "sha256:" + strings.Repeat("d", 64)}}})
	if st, body := post(token("900"), "/v1/tenants/"+tat+"/services/"+svc+"/releases", "application/json", rel); st != 201 || !strings.Contains(body, `"commit_sha":"c0ffee"`) || !strings.Contains(body, `"created_by":"pipeline:github:acme/crm-api@refs/heads/main#77"`) {
		t.Fatalf("release %d %s", st, body)
	}
}
