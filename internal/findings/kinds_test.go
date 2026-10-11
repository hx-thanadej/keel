package findings_test

import (
	"go/ast"
	"go/parser"
	"go/token"
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

// Go code raises a kind through its findings.Kind value; SQL names it
// literally.
func TestEveryRegisteredKindIsRaisedSomewhere(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "kinds.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ident := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		if v, ok := n.(*ast.ValueSpec); ok && len(v.Values) == 1 {
			if call, ok := v.Values[0].(*ast.CallExpr); ok && len(call.Args) == 1 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					ident[strings.Trim(lit.Value, `"`)] = v.Names[0].Name
				}
			}
		}
		return true
	})
	var all strings.Builder
	for path, src := range sources(t) {
		if !strings.HasSuffix(path, "kinds.go") {
			all.WriteString(src)
		}
	}
	for _, k := range findings.Kinds {
		name, ok := ident[k.String()]
		if !ok {
			t.Fatalf("kinds.go declares no variable for %q", k)
		}
		inGo := regexp.MustCompile(`\bfindings\.` + name + `\b`).MatchString(all.String())
		if !inGo && !strings.Contains(all.String(), `'`+k.String()+`'`) {
			t.Errorf("findings.Kinds lists %q but no source raises it", k)
		}
	}
}
