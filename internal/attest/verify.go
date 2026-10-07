// Package attest is Keel's release policy (#112, ADR-0010): it verifies the
// Sigstore-signed SLSA provenance CI submits for each image of a Release,
// checks who built it, from which repository, ref and trigger, and issues a
// Verification Summary Attestation (VSA) signed with Keel's key. Promotion
// requires a passing VSA for every image.
package attest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Evidence is what a verified bundle proves.
type Evidence struct {
	Certificate   certificate.Summary `json:"certificate"`
	PredicateType string              `json:"predicate_type"`
	Subjects      map[string]string   `json:"subjects"` // sha256 hex → name
}

// Verifier checks a bundle's signature, certificate chain, timestamps and
// that it attests to the given digest.
type Verifier interface {
	Verify(raw []byte, digest string) (Evidence, error)
}

// Sigstore verifies against one trusted root: Sigstore's public-good
// instance (transparency log) or GitHub's private instance (signed
// timestamps) for private repositories.
type Sigstore struct {
	Trusted root.TrustedMaterial
	// GitHubPrivate: GitHub's instance has no transparency log; it uses a
	// timestamp authority.
	GitHubPrivate bool
	// IdentityRegexp limits whose certificates count (the builder's SAN),
	// e.g. ^https://github.com/acme/keel-workflows/
	IdentityRegexp string
	// WithoutSCT skips certificate-transparency checks; only for test CAs
	// that issue none. Production instances always embed SCTs.
	WithoutSCT bool
}

// GitHubIssuer is the OIDC issuer in GitHub Actions certificates.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// Verify implements Verifier.
func (s Sigstore) Verify(raw []byte, digest string) (Evidence, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return Evidence{}, fmt.Errorf("not a Sigstore bundle: %w", err)
	}
	return s.VerifyEntity(&b, digest)
}

// VerifyEntity verifies any signed entity (a bundle, or a test entity).
func (s Sigstore) VerifyEntity(e verify.SignedEntity, digest string) (Evidence, error) {
	if s.Trusted == nil {
		return Evidence{}, errors.New("no Sigstore trusted root configured")
	}
	opts := []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	if s.GitHubPrivate {
		opts = []verify.VerifierOption{verify.WithSignedTimestamps(1)}
	}
	if !s.WithoutSCT {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	v, err := verify.NewVerifier(s.Trusted, opts...)
	if err != nil {
		return Evidence{}, err
	}
	sum, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil || len(sum) != 32 {
		return Evidence{}, fmt.Errorf("digest %q is not sha256", digest)
	}
	re := s.IdentityRegexp
	if re == "" {
		re = ".+"
	}
	id, err := verify.NewShortCertificateIdentity(GitHubIssuer, "", "", re)
	if err != nil {
		return Evidence{}, err
	}
	res, err := v.Verify(e, verify.NewPolicy(verify.WithArtifactDigest("sha256", sum), verify.WithCertificateIdentity(id)))
	if err != nil {
		return Evidence{}, fmt.Errorf("signature verification failed: %w", err)
	}
	ev := Evidence{Subjects: map[string]string{}}
	if res.Signature != nil && res.Signature.Certificate != nil {
		ev.Certificate = *res.Signature.Certificate
	}
	if res.Statement != nil {
		ev.PredicateType = res.Statement.GetPredicateType()
		for _, sub := range res.Statement.GetSubject() {
			if h := sub.GetDigest()["sha256"]; h != "" {
				ev.Subjects[h] = sub.GetName()
			}
		}
	}
	return ev, nil
}
