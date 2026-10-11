package scans

import (
	"maps"
	"slices"
	"testing"

	"github.com/hx-thanadej/keel/internal/findings"
)

func TestEveryScanKindIsARegisteredFindingKind(t *testing.T) {
	for _, k := range append(slices.Collect(maps.Values(toolKinds)), Kind("any", "CVE-2026-1"), Kind("unknown-tool", "rule")) {
		if !findings.KnownKind(k) {
			t.Errorf("scans raise Finding kind %q that findings.Kinds does not list", k)
		}
	}
}
