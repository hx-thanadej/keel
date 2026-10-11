package api_test

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	get := func(role, query string) (int, []byte, string) {
		p, _ := json.Marshal(auth.Principal{Subject: "user:auditor@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: role, TenantID: tat}}})
		req, _ := http.NewRequest("GET", srv.URL+"/v1/tenants/"+tat+"/evidence?from=2026-01-01&to=2026-04-01"+query, nil)
		req.Header.Set("X-Test-Principal", string(p))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, raw, res.Header.Get("Content-Disposition")
	}
	code, raw, file := get(auth.RoleTenantViewer, "&framework=SOC2")
	if b, err := evidence.Verify(pub, raw); code != 200 || err != nil || len(b.Manifest.Frameworks) != 1 || b.Manifest.Frameworks[0] != "SOC2" {
		t.Fatalf("soc2: %d %v %+v", code, err, b.Manifest)
	}
	if want := `filename="keel-evidence-soc2-2026-01-01-2026-04-01.json"`; !strings.Contains(file, want) {
		t.Fatalf("soc2 download %q, want %s", file, want)
	}
	code, raw, file = get(auth.RoleTenantViewer, "")
	if b, err := evidence.Verify(pub, raw); code != 200 || err != nil || len(b.Manifest.Frameworks) != 7 {
		t.Fatalf("all frameworks: %d %v %v", code, err, b.Manifest.Frameworks)
	}
	if want := `filename="keel-evidence-2026-01-01-2026-04-01.json"`; !strings.Contains(file, want) {
		t.Fatalf("all-framework download %q, want %s", file, want)
	}
	if code, _, _ := get(auth.RoleTenantViewer, "&framework=soc3"); code != 400 {
		t.Fatalf("unknown framework: %d", code)
	}
	if code, _, _ := get(auth.RoleEngineer, "&framework=soc2"); code != 403 {
		t.Fatalf("engineer without evidence.export: %d", code)
	}
}
