package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Static authenticates every request as one fixed Principal. Local
// development only: cmd/keel-api refuses to use it unless KEEL_ENV=dev.
type Static struct{ P Principal }

// Authenticate implements Authenticator.
func (s Static) Authenticate(*http.Request) (Principal, error) { return s.P, nil }

// ParseStatic builds a Static authenticator from a JSON Principal.
func ParseStatic(raw string) (Static, error) {
	var p Principal
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return Static{}, fmt.Errorf("parse dev principal: %w", err)
	}
	if p.Subject == "" || p.TenantID == "" {
		return Static{}, fmt.Errorf("dev principal needs subject and tenant_id")
	}
	return Static{P: p}, nil
}
