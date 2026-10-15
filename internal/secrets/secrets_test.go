package secrets_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/hx-thanadej/keel/internal/secrets"
)

func newKey(t *testing.T) string {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k)
}

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := secrets.FromEnv(env(map[string]string{"KEEL_SECRETS_KEY": newKey(t)}))
	if err != nil || s == nil {
		t.Fatalf("FromEnv: %v %v", s, err)
	}
	aad := []byte("tenant-1|conn-1|secret_key")
	blob, err := s.Seal([]byte("very-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("very-secret")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	again, _ := s.Seal([]byte("very-secret"), aad)
	if bytes.Equal(blob, again) {
		t.Fatal("two seals of one value are equal: the nonce is not random")
	}
	got, err := s.Open(blob, aad)
	if err != nil || string(got) != "very-secret" {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestOpenRefusesWrongKeyAndSwappedAAD(t *testing.T) {
	a, _ := secrets.FromEnv(env(map[string]string{"KEEL_SECRETS_KEY": newKey(t)}))
	b, _ := secrets.FromEnv(env(map[string]string{"KEEL_SECRETS_KEY": newKey(t)}))
	blob, _ := a.Seal([]byte("v"), []byte("tenant-1|conn-1|secret_key"))
	if _, err := b.Open(blob, []byte("tenant-1|conn-1|secret_key")); !errors.Is(err, secrets.ErrUnknownKey) {
		t.Fatalf("wrong key: %v, want ErrUnknownKey", err)
	}
	for _, aad := range []string{"tenant-2|conn-1|secret_key", "tenant-1|conn-2|secret_key", "tenant-1|conn-1|secret_id"} {
		if _, err := a.Open(blob, []byte(aad)); !errors.Is(err, secrets.ErrCorrupt) {
			t.Fatalf("aad %q: %v, want ErrCorrupt", aad, err)
		}
	}
	tampered := bytes.Clone(blob)
	tampered[len(tampered)-1] ^= 1
	if _, err := a.Open(tampered, []byte("tenant-1|conn-1|secret_key")); !errors.Is(err, secrets.ErrCorrupt) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestRotationOpensWithPreviousAndSealsWithCurrent(t *testing.T) {
	oldKey, newK := newKey(t), newKey(t)
	old, _ := secrets.FromEnv(env(map[string]string{"KEEL_SECRETS_KEY": oldKey}))
	blob, _ := old.Seal([]byte("v"), []byte("x"))
	rotated, err := secrets.FromEnv(env(map[string]string{"KEEL_SECRETS_KEY": newK, "KEEL_SECRETS_KEY_PREVIOUS": oldKey}))
	if err != nil {
		t.Fatal(err)
	}
	if !rotated.Stale(blob) {
		t.Fatal("a value sealed with the previous key is not stale")
	}
	if got, err := rotated.Open(blob, []byte("x")); err != nil || string(got) != "v" {
		t.Fatalf("open with previous key: %q %v", got, err)
	}
	resealed, _ := rotated.Seal([]byte("v"), []byte("x"))
	if rotated.Stale(resealed) {
		t.Fatal("a fresh seal is stale")
	}
	current, _ := secrets.FromEnv(env(map[string]string{"KEEL_SECRETS_KEY": newK}))
	if _, err := current.Open(resealed, []byte("x")); err != nil {
		t.Fatalf("resealed value does not open with the new key alone: %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	if s, err := secrets.FromEnv(env(nil)); s != nil || err != nil {
		t.Fatalf("unset: %v %v, want nil, nil", s, err)
	}
	for name, vars := range map[string]map[string]string{
		"not base64":         {"KEEL_SECRETS_KEY": "%%%"},
		"16 bytes":           {"KEEL_SECRETS_KEY": base64.StdEncoding.EncodeToString(make([]byte, 16))},
		"previous only":      {"KEEL_SECRETS_KEY_PREVIOUS": newKey(t)},
		"previous malformed": {"KEEL_SECRETS_KEY": newKey(t), "KEEL_SECRETS_KEY_PREVIOUS": "short"},
	} {
		if _, err := secrets.FromEnv(env(vars)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
