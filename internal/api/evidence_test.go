package api_test

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hx-thanadej/keel/internal/api"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/controls"
	"github.com/hx-thanadej/keel/internal/evidence"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestEvidenceExportPerFramework(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	pub, key, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		Evidence: &api.EvidenceDeps{Authz: az, Exporter: evidence.Exporter{Store: s, Controls: controls.Service{Store: s, Registry: mustControls(t)}, Key: key}}}))
	t.Cleanup(srv.Close)
	get := func(role, query string) (int, evidence.Bundle) {
		p, _ := json.Marshal(auth.Principal{Subject: "user:auditor@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: role, TenantID: tat}}})
		req, _ := http.NewRequest("GET", srv.URL+"/v1/tenants/"+tat+"/evidence?from=2026-01-01&to=2026-04-01"+query, nil)
		req.Header.Set("X-Test-Principal", string(p))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		raw, _ := io.ReadAll(res.Body)
		var b evidence.Bundle
		_ = json.Unmarshal(raw, &b)
		return res.StatusCode, b
	}
	code, b := get(auth.RoleTenantViewer, "&framework=soc2")
	if code != 200 || len(b.Manifest.Frameworks) != 1 || b.Manifest.Frameworks[0] != "SOC2" || evidence.Verify(pub, b) != nil {
		t.Fatalf("soc2: %d %+v", code, b.Manifest)
	}
	if code, b := get(auth.RoleTenantViewer, ""); code != 200 || len(b.Manifest.Frameworks) != 7 || evidence.Verify(pub, b) != nil {
		t.Fatalf("all frameworks: %d %v", code, b.Manifest.Frameworks)
	}
	if code, _ := get(auth.RoleTenantViewer, "&framework=soc3"); code != 400 {
		t.Fatalf("unknown framework: %d", code)
	}
	if code, _ := get(auth.RoleEngineer, "&framework=soc2"); code != 403 {
		t.Fatalf("engineer without evidence.export: %d", code)
	}
}
