package evidence_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/controls"
	"github.com/hx-thanadej/keel/internal/evidence"
	"github.com/hx-thanadej/keel/internal/findings"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func world(t *testing.T) (*store.Store, string, string) {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var svc string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project, env, rel string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&env); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'API') RETURNING id`, tenant, project, team).Scan(&svc); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO releases (tenant_id, service_id, version, images, created_by) VALUES ($1, $2, '1.0', '[{"name":"a","digest":"sha256:aa"}]', 'p') RETURNING id`, tenant, svc).Scan(&rel); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO release_attestations (tenant_id, release_id, image_digest, passed, checks, bundle_sha256, vsa, submitted_by) VALUES ($1, $2, 'sha256:aa', true, '[]', 'b', '{"payloadType":"x"}', 'p')`, tenant, rel); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO promotions (tenant_id, release_id, environment_id, state, requested_by, deployed_at) VALUES ($1, $2, $3, 'deployed', 'u', now())`, tenant, rel, env); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, service_id, project_id, owner_team_id) VALUES ($1, 'vulnerability', $2, 'critical', 'Log4Shell', $3, $4, $5)`,
			tenant, "vuln:CVE-2021-44228:"+svc, svc, project, team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s, tenant, svc
}

func export(t *testing.T, s *store.Store, tenant, framework string) (evidence.Bundle, ed25519.PublicKey, controls.Report) {
	t.Helper()
	ctx := context.Background()
	reg, err := controls.Load()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(nil)
	cs := controls.Service{Store: s, Registry: reg}
	from, to := time.Now().AddDate(0, 0, -30), time.Now().Add(time.Hour)
	b, err := evidence.Exporter{Store: s, Controls: cs, Key: key}.Export(ctx, tenant, framework, from, to, activity.Actor{Type: activity.ActorHuman, UID: "user:auditor"})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := cs.Report(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	// Round trip through JSON as an auditor would receive it.
	raw, _ := json.Marshal(b)
	var got evidence.Bundle
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got, pub, rep
}

func TestEveryFrameworkBundleVerifiesAndEverySectionIsTamperEvident(t *testing.T) {
	s, tenant, _ := world(t)
	for _, f := range []string{"", "iso27001", "soc2", "pdpa", "ssdf", "slsa", "cra", "owasp-cicd"} {
		b, pub, rep := export(t, s, tenant, f)
		if b.Manifest.Format != "keel-evidence@2" {
			t.Fatalf("%q: format %s", f, b.Manifest.Format)
		}
		if err := evidence.Verify(pub, b); err != nil {
			t.Fatalf("%q: clean bundle: %v", f, err)
		}
		want := len(rep.Frameworks)
		if f != "" {
			want = 1
		}
		if len(b.Manifest.Frameworks) != want {
			t.Fatalf("%q: manifest frameworks %v", f, b.Manifest.Frameworks)
		}
		for _, id := range b.Manifest.Frameworks {
			if _, ok := b.Sections["frameworks/"+id]; !ok || (f != "" && !strings.EqualFold(id, f)) {
				t.Fatalf("%q: framework sections %v", f, b.Manifest.Sections)
			}
		}
		// An auditor's tools may re-indent the JSON; the bundle still verifies.
		pretty, _ := json.MarshalIndent(b, "", "  ")
		var reformatted evidence.Bundle
		if err := json.Unmarshal(pretty, &reformatted); err != nil || evidence.Verify(pub, reformatted) != nil {
			t.Fatalf("%q: re-indented bundle does not verify", f)
		}
		for name, raw := range b.Sections {
			tampered := b
			tampered.Sections = map[string]json.RawMessage{}
			for n, r := range b.Sections {
				tampered.Sections[n] = r
			}
			tampered.Sections[name] = json.RawMessage(strings.Replace(string(raw), "}", `,"x":1}`, 1))
			if string(tampered.Sections[name]) == string(raw) {
				tampered.Sections[name] = json.RawMessage(`[{"x":1}]`)
			}
			if err := evidence.Verify(pub, tampered); err == nil {
				t.Fatalf("%q: altered section %s verified", f, name)
			}
		}
		other, _, _ := ed25519.GenerateKey(nil)
		if err := evidence.Verify(other, b); err == nil {
			t.Fatalf("%q: wrong key verified", f)
		}
	}
}

func TestISOBundleListsEveryAnnexAControlWithItsGaps(t *testing.T) {
	s, tenant, _ := world(t)
	b, _, rep := export(t, s, tenant, "iso27001")
	var sec evidence.FrameworkSection
	if err := json.Unmarshal(b.Sections["frameworks/ISO27001"], &sec); err != nil {
		t.Fatal(err)
	}
	want, _ := rep.Only("ISO27001")
	if sec.Coverage != want.Frameworks[0] || len(sec.Controls) != 93 || sec.Coverage.Controls != 93 {
		t.Fatalf("coverage %+v, %d controls; report %+v", sec.Coverage, len(sec.Controls), want.Frameworks[0])
	}
	covered, gaps, unmapped := 0, 0, 0
	for i, c := range sec.Controls {
		if c.ID != want.Controls[i].ID || c.Gap != want.Controls[i].Gap {
			t.Fatalf("control %d: %s gap=%v, report %s gap=%v", i, c.ID, c.Gap, want.Controls[i].ID, want.Controls[i].Gap)
		}
		if c.Gap {
			gaps++
			if c.GapReason == "" {
				t.Errorf("gap %s has no reason", c.ID)
			}
		} else {
			covered++
		}
		if len(c.CoveredBy) == 0 {
			unmapped++
			if !c.Gap || len(c.Evidence) != 0 {
				t.Errorf("control %s with no Policy is not a gap: %+v", c.ID, c)
			}
		}
	}
	if covered != sec.Coverage.Covered || gaps != sec.Coverage.Gaps || unmapped == 0 {
		t.Fatalf("covered %d gaps %d unmapped %d; coverage %+v", covered, gaps, unmapped, sec.Coverage)
	}
	// 8.32 change management points at the Releases in the period.
	for _, c := range sec.Controls {
		if c.ID == "8.32" && !slices.ContainsFunc(c.Evidence, func(r evidence.Ref) bool { return r.Section == "releases" && r.Items != nil && *r.Items == 1 }) {
			t.Fatalf("8.32 evidence %+v", c.Evidence)
		}
	}
	for name := range b.Sections {
		if strings.HasPrefix(name, "frameworks/") && name != "frameworks/ISO27001" {
			t.Fatalf("ISO bundle carries %s", name)
		}
	}
}

func TestExportRejectsUnknownFramework(t *testing.T) {
	s, tenant, _ := world(t)
	reg, _ := controls.Load()
	_, key, _ := ed25519.GenerateKey(nil)
	_, err := evidence.Exporter{Store: s, Controls: controls.Service{Store: s, Registry: reg}, Key: key}.Export(context.Background(), tenant, "soc3", time.Now().AddDate(0, 0, -1), time.Now(), activity.Actor{})
	if !errors.Is(err, evidence.ErrUnknownFramework) {
		t.Fatalf("soc3: %v", err)
	}
}

// testdata/keel-evidence-v1.json is a keel-evidence@1 bundle exported by the
// code before #191, signed with the key from seed 0x07 * 32.
func TestKeelEvidenceV1BundleStillVerifies(t *testing.T) {
	raw, err := os.ReadFile("testdata/keel-evidence-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var b evidence.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)
	if b.Manifest.Format != "keel-evidence@1" || evidence.Verify(pub, b) != nil {
		t.Fatalf("%s bundle does not verify: %v", b.Manifest.Format, evidence.Verify(pub, b))
	}
	b.Sections["findings"] = json.RawMessage(`{"overdue": 0}`)
	if evidence.Verify(pub, b) == nil {
		t.Fatal("altered v1 section verified")
	}
}

type kev map[string]bool

func (k kev) Exploited(context.Context) (map[string]bool, error) { return k, nil }

func TestCRAClockStartsOnceForExploitedDeployedVulnerabilities(t *testing.T) {
	s, tenant, _ := world(t)
	ctx := context.Background()
	now := storetest.Epoch.Add(9 * time.Hour)
	c := evidence.CRA{Store: s, KEV: kev{"CVE-2021-44228": true}, Now: func() time.Time { return now }}
	if n, err := c.Run(ctx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	now = now.Add(time.Hour)
	if n, _ := c.Run(ctx); n != 0 {
		t.Fatal("clock restarted")
	}
	var detail map[string]any
	var raw []byte
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT detail FROM findings WHERE kind = 'cra_report'`).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &detail)
	if detail["early_warning_by"] != "2031-01-02T09:00:00Z" || detail["final_report_by"] != "2031-01-15T09:00:00Z" {
		t.Fatalf("deadlines %v", detail)
	}
	storetest.ClockedFindings(t, s, "cra_report")
}

// The findings section counts by the writers' clock: a bundle for a period on
// that clock holds the Findings raised and resolved in it.
func TestEvidenceCountsFindingsOnTheWritersClock(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	home, _ := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	sla := findings.SLA{Store: s, Now: storetest.Clock()}
	var orphan string
	if err := s.InTenant(ctx, home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, first_seen_at) VALUES ($1, 'vulnerability', 'v', 'critical', 'CVE', $2) RETURNING id`, home, sla.Now()).Scan(&orphan)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sla.Run(ctx); err != nil { // raises the unowned Finding
		t.Fatal(err)
	}
	if err := s.InTenant(ctx, home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = 'patched' WHERE id = $1`, orphan, sla.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sla.Run(ctx); err != nil { // resolves it
		t.Fatal(err)
	}
	reg, _ := controls.Load()
	_, key, _ := ed25519.GenerateKey(nil)
	e := evidence.Exporter{Store: s, Controls: controls.Service{Store: s, Registry: reg}, Key: key, Now: sla.Now}
	b, err := e.Export(ctx, home, "", storetest.Epoch.Add(-time.Hour), sla.Now().Add(time.Hour), activity.Actor{Type: activity.ActorHuman, UID: "user:auditor"})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Raised   int `json:"raised_in_period"`
		Resolved int `json:"resolved_in_period"`
		Within   int `json:"resolved_within_sla"`
	}
	if err := json.Unmarshal(b.Sections["findings"], &got); err != nil || got.Raised != 2 || got.Resolved != 2 || got.Within != 2 {
		t.Fatalf("findings section %s %v", b.Sections["findings"], err)
	}
}
