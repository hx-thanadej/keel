// Package secrets seals values Keel must store and later use, such as a
// cloud connection's key (ADR-0022), with AES-256-GCM under a key held
// outside the database (KEEL_SECRETS_KEY).
//
// A sealed value is version (1 byte) | key id (8) | nonce (12) | ciphertext
// and tag. The key id names the key that sealed it, so a rotated deployment
// can open values under the previous key and reseal them under the current.
// The additional data binds a value to where it is stored: a value moved to
// another row, Tenant or column does not open.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const version = 1

var (
	// ErrUnknownKey means the value was sealed with a key Keel is not
	// configured with.
	ErrUnknownKey = errors.New("secrets: sealed with a key that is neither KEEL_SECRETS_KEY nor KEEL_SECRETS_KEY_PREVIOUS")
	// ErrCorrupt means the value, or the context it is bound to, changed.
	ErrCorrupt = errors.New("secrets: sealed value does not open: altered, or bound to another record")
)

type key struct {
	id   [8]byte
	aead cipher.AEAD
}

func parseKey(name, b64 string) (key, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return key{}, fmt.Errorf("%s must be 32 bytes, base64-encoded", name)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return key{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return key{}, err
	}
	sum := sha256.Sum256(append([]byte("keel-secrets-key-id\x00"), raw...))
	var k key
	copy(k.id[:], sum[:8])
	k.aead = aead
	return k, nil
}

// Sealer seals with the current key and opens with the current or previous
// key.
type Sealer struct {
	current  key
	previous *key
}

// FromEnv reads KEEL_SECRETS_KEY and, during a rotation,
// KEEL_SECRETS_KEY_PREVIOUS. It returns nil, nil when no key is set.
func FromEnv(getenv func(string) string) (*Sealer, error) {
	cur, prev := getenv("KEEL_SECRETS_KEY"), getenv("KEEL_SECRETS_KEY_PREVIOUS")
	if cur == "" {
		if prev != "" {
			return nil, errors.New("KEEL_SECRETS_KEY_PREVIOUS is set without KEEL_SECRETS_KEY")
		}
		return nil, nil
	}
	c, err := parseKey("KEEL_SECRETS_KEY", cur)
	if err != nil {
		return nil, err
	}
	s := &Sealer{current: c}
	if prev != "" {
		p, err := parseKey("KEEL_SECRETS_KEY_PREVIOUS", prev)
		if err != nil {
			return nil, err
		}
		s.previous = &p
	}
	return s, nil
}

// Seal encrypts plain, bound to aad, under the current key.
func (s *Sealer) Seal(plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.current.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{version}, s.current.id[:]...)
	out = append(out, nonce...)
	return s.current.aead.Seal(out, nonce, plain, aad), nil
}

// Open decrypts a value sealed by Seal with the same aad.
func (s *Sealer) Open(sealed, aad []byte) ([]byte, error) {
	k, err := s.keyFor(sealed)
	if err != nil {
		return nil, err
	}
	n := k.aead.NonceSize()
	body := sealed[9:]
	if len(body) < n+k.aead.Overhead() {
		return nil, ErrCorrupt
	}
	plain, err := k.aead.Open(nil, body[:n], body[n:], aad)
	if err != nil {
		return nil, ErrCorrupt
	}
	return plain, nil
}

// Stale reports whether sealed was sealed with a key other than the current
// one, so it should be resealed.
func (s *Sealer) Stale(sealed []byte) bool {
	return len(sealed) < 9 || [8]byte(sealed[1:9]) != s.current.id
}

func (s *Sealer) keyFor(sealed []byte) (key, error) {
	if len(sealed) < 9 || sealed[0] != version {
		return key{}, ErrCorrupt
	}
	id := [8]byte(sealed[1:9])
	switch {
	case id == s.current.id:
		return s.current, nil
	case s.previous != nil && id == s.previous.id:
		return *s.previous, nil
	}
	return key{}, ErrUnknownKey
}
