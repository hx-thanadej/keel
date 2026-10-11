package api_test

import (
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
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func TestControlsFilterByFramework(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	tat, _ := s.CreateTenant(t.Context(), "tat", "TAT", false)
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		Controls: &api.ControlDeps{Authz: az, Service: controls.Service{Store: s, Registry: mustControls(t)}}}))
	t.Cleanup(srv.Close)
	viewer, _ := json.Marshal(auth.Principal{Subject: "user:auditor@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	get := func(query string) (int, controls.Report) {
		req, _ := http.NewRequest("GET", srv.URL+"/v1/tenants/"+tat+"/controls"+query, nil)
		req.Header.Set("X-Test-Principal", string(viewer))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		var rep controls.Report
		_ = json.Unmarshal(b, &rep)
		return res.StatusCode, rep
	}
	code, all := get("")
	if code != 200 || len(all.Frameworks) != 7 {
		t.Fatalf("all: %d %+v", code, all.Frameworks)
	}
	code, iso := get("?framework=ISO27001")
	if code != 200 || len(iso.Controls) != 93 || len(iso.Frameworks) != 1 {
		t.Fatalf("ISO27001: %d %d controls %+v", code, len(iso.Controls), iso.Frameworks)
	}
	if f := iso.Frameworks[0]; f.ID != "ISO27001" || f.Controls != 93 || f.Mapped != 22 || f.Covered+f.Gaps != 93 {
		t.Fatalf("ISO27001 coverage %+v", f)
	}
	for _, c := range iso.Controls {
		if c.Framework != "ISO27001" {
			t.Fatalf("ISO27001 filter returned %s %s", c.Framework, c.ID)
		}
	}
	if code, pdpa := get("?framework=PDPA"); code != 200 || len(pdpa.Controls) != 12 || pdpa.Frameworks[0].Mapped != 5 {
		t.Fatalf("PDPA: %d %+v", code, pdpa.Frameworks)
	}
	if code, _ := get("?framework=SOC3"); code != 400 {
		t.Fatalf("unknown framework: %d", code)
	}
}
