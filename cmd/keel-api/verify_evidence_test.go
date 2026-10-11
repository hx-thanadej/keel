package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/evidence"
)

// v2Bundle signs a minimal keel-evidence@2 bundle the way Export lays it
// out, its section in canonical (sorted-key) form.
func v2Bundle(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(nil)
	section := `{"controls":[{"gap":true,"id":"A.5.1"}],"coverage":{},"services":1}`
	sum := sha256.Sum256([]byte(section))
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	manifest, _ := json.Marshal(evidence.Manifest{Format: evidence.Format, Tenant: "t1", From: at.AddDate(0, -1, 0), To: at, GeneratedAt: at,
		Controls: "keel-controls@2", Frameworks: []string{"ISO27001"}, Sections: map[string]string{"frameworks/ISO27001": hex.EncodeToString(sum[:])}})
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest))
	return []byte(`{"manifest":` + string(manifest) + `,"sections":{"frameworks/ISO27001":` + section + `},"key_id":"k","signature":"` + sig + `"}`), pub
}

func runVerifyEvidence(t *testing.T, bundle []byte, pub ed25519.PublicKey) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	return verifyEvidence([]string{path, base64.StdEncoding.EncodeToString(pub)})
}

func TestVerifyEvidenceRejectsAmbiguousJSON(t *testing.T) {
	v1, err := os.ReadFile("../../internal/evidence/testdata/keel-evidence-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	v1Pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)
	v2, v2Pub := v2Bundle(t)
	for _, c := range []struct {
		name   string
		bundle []byte
		pub    ed25519.PublicKey
	}{{"keel-evidence@1", v1, v1Pub}, {"keel-evidence@2", v2, v2Pub}} {
		if err := runVerifyEvidence(t, c.bundle, c.pub); err != nil {
			t.Fatalf("genuine %s: %v", c.name, err)
		}
		forgeries := map[string]string{
			"duplicate manifest tenant": strings.Replace(string(c.bundle), `"manifest":{`, `"manifest":{"tenant":"forged-tenant",`, 1),
			"unknown manifest field":    strings.Replace(string(c.bundle), `"manifest":{`, `"manifest":{"approved_by":"ciso",`, 1),
		}
		if c.name == "keel-evidence@2" {
			forgeries["duplicate top-level section key"] = strings.Replace(string(c.bundle), `"frameworks/ISO27001":{`, `"frameworks/ISO27001":{"services":999,`, 1)
			forgeries["duplicate nested section key"] = strings.Replace(string(c.bundle), `"gap":true`, `"gap":false,"gap":true`, 1)
		}
		for name, forged := range forgeries {
			if forged == string(c.bundle) {
				t.Fatalf("%s %s: forgery not applied", c.name, name)
			}
			if err := runVerifyEvidence(t, []byte(forged), c.pub); err == nil {
				t.Errorf("%s with %s verified", c.name, name)
			}
		}
	}
}
