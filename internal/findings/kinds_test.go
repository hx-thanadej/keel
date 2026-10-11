package findings_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/findings"
)

// insertKind matches a literal kind in an INSERT INTO findings statement,
// where the tenant is $1 and the kind follows it.
var insertKind = regexp.MustCompile(`(?s)INSERT INTO findings \(tenant_id, kind,[^)]*\)\s*(?:VALUES \(|SELECT )\$1, '([a-z_]+)'`)

func sources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		out[path] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEveryKindRaisedInSQLIsRegistered(t *testing.T) {
	seen := 0
	for path, src := range sources(t) {
		for _, m := range insertKind.FindAllStringSubmatch(src, -1) {
			seen++
			if !findings.KnownKind(m[1]) {
				t.Errorf("%s raises Finding kind %q that findings.Kinds does not list", path, m[1])
			}
		}
	}
	if seen < 15 {
		t.Fatalf("matched only %d literal kinds; the pattern no longer finds the INSERTs", seen)
	}
}

func TestEveryRegisteredKindIsRaisedSomewhere(t *testing.T) {
	var all strings.Builder
	for path, src := range sources(t) {
		if !strings.HasSuffix(path, "kinds.go") {
			all.WriteString(src)
		}
	}
	for _, k := range findings.Kinds {
		if !strings.Contains(all.String(), `'`+k+`'`) && !strings.Contains(all.String(), `"`+k+`"`) {
			t.Errorf("findings.Kinds lists %q but no source raises it", k)
		}
	}
}
