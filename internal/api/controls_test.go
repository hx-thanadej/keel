package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"

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
	if code, lower := get("?framework=iso27001"); code != 200 || len(lower.Controls) != 93 {
		t.Fatalf("iso27001: %d %d controls", code, len(lower.Controls))
	}
	if code, _ := get("?framework=SOC3"); code != 400 {
		t.Fatalf("unknown framework: %d", code)
	}
}

func TestControlsListOpenFindingsPerControlForTheCallersTenantOnly(t *testing.T) {
	s := storetest.New(t)
	az, _ := authz.New()
	ctx := t.Context()
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	other, _ := s.CreateTenant(ctx, "other", "Other", false)
	ids := map[string]string{}
	for tn, title := range map[string]string{tat: "CVE-2026-7 in openssl", other: "Other tenant CVE"} {
		var id string
		if err := s.InTenant(ctx, tn, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title) VALUES ($1, 'vulnerability', 'vuln:CVE-2026-7', 'high', $2) RETURNING id::text`, tn, title).Scan(&id)
		}); err != nil {
			t.Fatal(err)
		}
		ids[tn] = id
	}
	srv := httptest.NewServer(api.NewRouter(api.Info{}, api.Deps{Auth: headerAuth{}, Catalog: catalog.New(s, az),
		Controls: &api.ControlDeps{Authz: az, Service: controls.Service{Store: s, Registry: mustControls(t)}}}))
	t.Cleanup(srv.Close)
	viewer, _ := json.Marshal(auth.Principal{Subject: "user:auditor@tat.or.th", Kind: auth.KindHuman, TenantID: tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: tat}}})
	req, _ := http.NewRequest("GET", srv.URL+"/v1/tenants/"+tat+"/controls?framework=SSDF", nil)
	req.Header.Set("X-Test-Principal", string(viewer))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var body struct {
		Controls []map[string]json.RawMessage `json:"controls"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil || res.StatusCode != 200 {
		t.Fatalf("%d %v", res.StatusCode, err)
	}
	shape := map[string]string{}
	for _, c := range body.Controls {
		var id string
		_ = json.Unmarshal(c["id"], &id)
		shape[id] = string(c["open_findings"])
	}
	want := `{"count":1,"items":[{"id":"` + ids[tat] + `","title":"CVE-2026-7 in openssl","severity":"high"}]}`
	if got := shape["PW.4.4"]; got != want {
		t.Fatalf("PW.4.4 open_findings %s, want %s", got, want)
	}
	if got := shape["PO.1.1"]; got != `{"count":0,"items":[]}` {
		t.Fatalf("gap PO.1.1 open_findings %s, want an empty list", got)
	}
}
