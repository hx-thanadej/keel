package attest_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/attest"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

const builder = "https://github.com/acme/keel-workflows/.github/workflows/build.yml@refs/heads/main"

func statement(t *testing.T, digest string) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": attest.SLSAProvenance,
		"subject":   []any{map[string]any{"name": "ccr.ccs.tencentyun.com/tat/crm-api", "digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}},
		"predicate": map[string]any{"buildDefinition": map[string]any{"buildType": "https://actions.github.io/buildtypes/workflow/v1"}}})
	return b
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestSigstoreVerification(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	d := digestOf("image")
	entity, err := vs.Attest(builder, attest.GitHubIssuer, statement(t, d))
	if err != nil {
		t.Fatal(err)
	}
	v := attest.Sigstore{Trusted: vs, IdentityRegexp: "^https://github.com/acme/keel-workflows/", WithoutSCT: true}
	if _, err := (attest.Sigstore{Trusted: vs}).VerifyEntity(entity, d); err == nil || !strings.Contains(err.Error(), "certificate timestamp") {
		t.Fatalf("SCTs not required by default: %v", err)
	}
	ev, err := v.VerifyEntity(entity, d)
	if err != nil {
		t.Fatal(err)
	}
	if ev.PredicateType != attest.SLSAProvenance || ev.Certificate.SubjectAlternativeName != builder || len(ev.Subjects) != 1 {
		t.Fatalf("evidence %+v", ev)
	}
	if _, err := v.VerifyEntity(entity, digestOf("another image")); err == nil {
		t.Fatal("verified for a digest it does not name")
	}
	if _, err := (attest.Sigstore{Trusted: vs, IdentityRegexp: "^https://github.com/evil/", WithoutSCT: true}).VerifyEntity(entity, d); err == nil {
		t.Fatal("verified for another builder identity")
	}
	other, _ := ca.NewVirtualSigstore()
	if _, err := (attest.Sigstore{Trusted: other, WithoutSCT: true}).VerifyEntity(entity, d); err == nil {
		t.Fatal("verified against an untrusted root")
	}
}

func good() attest.Evidence {
	return attest.Evidence{PredicateType: attest.SLSAProvenance, Subjects: map[string]string{strings.TrimPrefix(digestOf("image"), "sha256:"): "img"},
		Certificate: certificate.Summary{SubjectAlternativeName: builder, Extensions: certificate.Extensions{
			Issuer: attest.GitHubIssuer, BuildSignerURI: builder, SourceRepositoryIdentifier: "900", SourceRepositoryRef: "refs/heads/main", BuildTrigger: "push"}}}
}

var exp = attest.Expectation{BuilderPrefix: "https://github.com/acme/keel-workflows/.github/workflows/build.yml@", RepositoryID: "900"}

func failing(cs []attest.Check) []string {
	var out []string
	for _, c := range cs {
		if !c.Pass {
			out = append(out, c.Name)
		}
	}
	return out
}

func TestReleasePolicy(t *testing.T) {
	d := digestOf("image")
	if cs := attest.Evaluate(good(), exp, d); !attest.Passed(cs) {
		t.Fatalf("good provenance failed: %v", failing(cs))
	}
	cases := map[string]func(*attest.Evidence){
		"trigger":    func(e *attest.Evidence) { e.Certificate.BuildTrigger = "pull_request_target" },
		"ref":        func(e *attest.Evidence) { e.Certificate.SourceRepositoryRef = "refs/heads/feature/x" },
		"repository": func(e *attest.Evidence) { e.Certificate.SourceRepositoryIdentifier = "901" },
		"builder": func(e *attest.Evidence) {
			e.Certificate.BuildSignerURI = "https://github.com/acme/crm-api/.github/workflows/own.yml@refs/heads/main"
		},
		"predicate": func(e *attest.Evidence) { e.PredicateType = "https://spdx.dev/Document" },
		"issuer":    func(e *attest.Evidence) { e.Certificate.Issuer = "https://accounts.google.com" },
	}
	for want, mutate := range cases {
		ev := good()
		mutate(&ev)
		if got := failing(attest.Evaluate(ev, exp, d)); len(got) != 1 || got[0] != want {
			t.Errorf("%s: failing %v", want, got)
		}
	}
	// Tags pass the default ref patterns.
	ev := good()
	ev.Certificate.SourceRepositoryRef = "refs/tags/v1.5.0"
	if !attest.Passed(attest.Evaluate(ev, exp, d)) {
		t.Fatal("tag ref rejected")
	}
	if got := failing(attest.Evaluate(good(), exp, digestOf("other"))); len(got) != 1 || got[0] != "subject" {
		t.Fatalf("subject: %v", got)
	}
}

func TestVSAIsSignedAndVerifiable(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	d := digestOf("image")
	env, err := attest.VSA(key, "https://keel.example/attestations", "release:r1", "img", d, attest.Evaluate(good(), exp, d), "abc", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := attest.VerifyVSA(pub, env)
	if err != nil {
		t.Fatal(err)
	}
	pred := stmt["predicate"].(map[string]any)
	if stmt["predicateType"] != "https://slsa.dev/verification_summary/v1" || pred["verificationResult"] != "PASSED" || pred["policy"].(map[string]any)["uri"] != attest.PolicyVersion {
		t.Fatalf("vsa %v", stmt)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := attest.VerifyVSA(other, env); err == nil {
		t.Fatal("verified with the wrong key")
	}
}

type fakeVerifier struct{ ev attest.Evidence }

func (f fakeVerifier) Verify(_ []byte, digest string) (attest.Evidence, error) {
	if _, ok := f.ev.Subjects[strings.TrimPrefix(digest, "sha256:")]; !ok {
		return attest.Evidence{}, errors.New("digest not attested")
	}
	return f.ev, nil
}

func TestSubmitRecordsChecksAndVerifiesTheRelease(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	d := digestOf("image")
	var rel string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project, svc string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository_id) VALUES ($1, $2, $3, 'crm-api', 'CRM API', 900) RETURNING id`, tenant, project, team).Scan(&svc); err != nil {
			return err
		}
		imgs, _ := json.Marshal([]map[string]string{{"name": "ccr/tat/crm-api", "digest": d}})
		return tx.QueryRow(ctx, `INSERT INTO releases (tenant_id, service_id, version, images, created_by) VALUES ($1, $2, '1.0.0', $3, 'p') RETURNING id`, tenant, svc, imgs).Scan(&rel)
	}); err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(nil)
	verified := func() bool {
		var ok bool
		if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT release_verified($1)`, rel).Scan(&ok) }); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	by := activity.Actor{Type: activity.ActorPipeline, UID: "pipeline:github:acme/crm-api@refs/heads/main#1"}
	if verified() {
		t.Fatal("verified with no attestations")
	}
	// From a pull_request_target run: recorded, failing, release not verified.
	bad := good()
	bad.Certificate.BuildTrigger = "pull_request_target"
	svc := attest.Service{Store: s, Verifier: fakeVerifier{bad}, Key: key, VerifierID: "https://keel.example/attestations", Expectation: exp}
	as, err := svc.Submit(ctx, tenant, rel, []byte(`{}`), by)
	if err != nil || len(as) != 1 || as[0].Passed || verified() {
		t.Fatalf("bad submit %+v %v", as, err)
	}
	svc.Verifier = fakeVerifier{good()}
	as, err = svc.Submit(ctx, tenant, rel, []byte(`{}`), by)
	if err != nil || !as[0].Passed || !verified() {
		t.Fatalf("good submit %+v %v", as, err)
	}
	if _, err := attest.VerifyVSA(pub, as[0].VSA); err != nil {
		t.Fatal(err)
	}
	if list, _ := svc.List(ctx, tenant, rel); len(list) != 2 || !list[0].Passed {
		t.Fatalf("list %+v", list)
	}
	svc.Verifier = fakeVerifier{attest.Evidence{Subjects: map[string]string{"00": "x"}}}
	if _, err := svc.Submit(ctx, tenant, rel, []byte(`{}`), by); !errors.Is(err, attest.ErrInvalid) {
		t.Fatalf("unrelated bundle: %v", err)
	}
}
