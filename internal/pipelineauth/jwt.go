package pipelineauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// unverifiedIssuer reads iss to decide whether this authenticator handles the
// token; the signature is verified afterwards against the issuer's keys.
func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", err
	}
	return c.Iss, nil
}
