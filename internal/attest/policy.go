package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"
)

// Expectation is what Keel's release policy (keel-release@1) requires.
type Expectation struct {
	BuilderPrefix   string   // reusable workflow, e.g. https://github.com/acme/keel-workflows/.github/workflows/build.yml@
	RepositoryID    string   // the Service's GitHub repository id
	AllowedRefs     []string // path patterns, e.g. refs/heads/main, refs/tags/*
	AllowedTriggers []string // e.g. push, workflow_dispatch, release
}

// DefaultRefs and DefaultTriggers apply when the Expectation leaves them empty.
var (
	DefaultRefs     = []string{"refs/heads/main", "refs/tags/*"}
	DefaultTriggers = []string{"push", "workflow_dispatch", "release"}
)

// SLSAProvenance is the predicate Keel accepts.
const SLSAProvenance = "https://slsa.dev/provenance/v1"

// PolicyVersion names the release policy in VSAs and Activities.
const PolicyVersion = "keel-release@1"

// Check is one rule's outcome.
type Check struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

// Evaluate applies the release policy to verified evidence for one digest.
func Evaluate(ev Evidence, exp Expectation, digest string) []Check {
	c := ev.Certificate
	refs, triggers := exp.AllowedRefs, exp.AllowedTriggers
	if len(refs) == 0 {
		refs = DefaultRefs
	}
	if len(triggers) == 0 {
		triggers = DefaultTriggers
	}
	trigger := c.BuildTrigger
	if trigger == "" {
		trigger = c.GithubWorkflowTrigger
	}
	builder := c.BuildSignerURI
	if builder == "" {
		builder = c.SubjectAlternativeName
	}
	refOK := false
	for _, p := range refs {
		if ok, _ := path.Match(p, c.SourceRepositoryRef); ok {
			refOK = true
		}
	}
	trigOK := false
	for _, t := range triggers {
		if t == trigger {
			trigOK = true
		}
	}
	_, subject := ev.Subjects[strings.TrimPrefix(digest, "sha256:")]
	return []Check{
		{"signature", true, "Sigstore bundle verified against the trusted root"},
		{"issuer", c.Issuer == GitHubIssuer, "certificate issuer " + orUnset(c.Issuer)},
		{"builder", exp.BuilderPrefix != "" && strings.HasPrefix(builder, exp.BuilderPrefix), "built by " + orUnset(builder) + ", want " + exp.BuilderPrefix + "…"},
		{"repository", exp.RepositoryID != "" && c.SourceRepositoryIdentifier == exp.RepositoryID, "source repository id " + orUnset(c.SourceRepositoryIdentifier) + ", want " + exp.RepositoryID},
		{"ref", refOK, "built from " + orUnset(c.SourceRepositoryRef) + ", allowed " + strings.Join(refs, ", ")},
		{"trigger", trigOK, "triggered by " + orUnset(trigger) + ", allowed " + strings.Join(triggers, ", ")},
		{"predicate", ev.PredicateType == SLSAProvenance, "predicate " + orUnset(ev.PredicateType)},
		{"subject", subject, "provenance names " + digest},
	}
}

// Passed reports whether every check passed.
func Passed(cs []Check) bool {
	for _, c := range cs {
		if !c.Pass {
			return false
		}
	}
	return len(cs) > 0
}

func orUnset(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

const inTotoPayload = "application/vnd.in-toto+json"

func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// KeyID names a public key in envelopes.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "keel:" + hex.EncodeToString(sum[:8])
}

// VSA builds and signs a SLSA Verification Summary Attestation.
func VSA(key ed25519.PrivateKey, verifierID, resource, image, digest string, cs []Check, inputDigest string, at time.Time) (Envelope, error) {
	result, levels := "FAILED", []string{}
	if Passed(cs) {
		result, levels = "PASSED", []string{"SLSA_BUILD_LEVEL_3"}
	}
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": image, "digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}},
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"predicate": map[string]any{
			"verifier":           map[string]any{"id": verifierID},
			"timeVerified":       at.UTC().Format(time.RFC3339),
			"resourceUri":        resource,
			"policy":             map[string]any{"uri": PolicyVersion},
			"inputAttestations":  []any{map[string]any{"uri": "sigstore-bundle", "digest": map[string]string{"sha256": inputDigest}}},
			"verificationResult": result,
			"verifiedLevels":     levels,
		},
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(key, pae(inTotoPayload, payload))
	return Envelope{PayloadType: inTotoPayload, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{KeyID: KeyID(key.Public().(ed25519.PublicKey)), Sig: base64.StdEncoding.EncodeToString(sig)}}}, nil
}

// VerifyVSA checks an envelope's signature (for consumers and tests).
func VerifyVSA(pub ed25519.PublicKey, e Envelope) (map[string]any, error) {
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, err
	}
	for _, s := range e.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err == nil && ed25519.Verify(pub, pae(e.PayloadType, payload), sig) {
			var out map[string]any
			return out, json.Unmarshal(payload, &out)
		}
	}
	return nil, fmt.Errorf("no valid signature")
}
